# Testing & QA Instructions — @QA

> **Scope**: `sql/`, `tap/`, `isolation/`, `expected/`, `ci/scripts/`,
> `bench_tde.sh`

---

## Mandatory Validation Gates

ALL gates must pass before any change is considered complete:

```bash
# Gate 1: Full regression (110 tests: 70 baseline + 20 v1.5 + 38 v1.6 + 2 skip-guarded, vault provider)
make ci-regress

# Gate 1b: Wallet provider regression (110 tests, kms_provider=local)
make ci-wallet

# Gate 2: Page checksum compatibility
make ci-checksums

# Gate 3: TAP tests (Perl, with mock Vault)
make ci-tap

# Gate 4: Isolation tests (concurrency / MVCC)
make ci-isolation

# Gate 5: Vault integration (Compose-based)
make ci-vault

# Gate 6: Zero compiler warnings
make PG_CONFIG=$(which pg_config) 2>&1 | grep -c "warning:" | grep "^0$"

# Gate 7: Full local pipeline (all of the above + bench)
make ci-all
```

---

## Test Suite Map

`sql/regression_test.sql` contains **70 tests** (52 v1.4 baseline + 18 v1.7
TAM/TOAST additions in tests 53–70).  The v1.5 and v1.6 supplement files each
carry their own internal numbering.  All three files together make up the
**110-test** suite run by `make ci-regress` / `make ci-wallet`.

| Test # | Category | What It Validates | File |
|--------|----------|-------------------|------|
| 1–11 | Crypto primitives | GCM encrypt/decrypt, IV uniqueness, tamper detection, rotation | `regression_test.sql` |
| 12 | TAM INSERT+SELECT | Basic round-trip on `encrypted_heap` table | `regression_test.sql` |
| 13 | On-disk absence | Raw file scan confirms no plaintext on disk | `regression_test.sql` |
| 14 | TAM UPDATE | ctid preservation, tuple refetch, HOT chains | `regression_test.sql` |
| 15 | DELETE | Row removal without crash | `regression_test.sql` |
| 16 | All-NULL row | `user_len == 0` edge case (no Assert crash) | `regression_test.sql` |
| 17 | Index scan | `index_fetch_tuple` + `rd_tableam` impersonation | `regression_test.sql` |
| 18 | COPY/bulk | `multi_insert` path via `COPY FROM` | `regression_test.sql` |
| 19 | Multi-column | int, text, bool, numeric, timestamptz types | `regression_test.sql` |
| 20 | Key rotation | DEK-A rows rejected after rotating to DEK-B | `regression_test.sql` |
| 21 | ANALYZE | Statistics computed on decrypted data | `regression_test.sql` |
| 22 | SELECT FOR UPDATE | `tuple_lock` path | `regression_test.sql` |
| 23 | BitmapHeapScan | `scan_bitmap_next_tuple` via forced bitmap scan | `regression_test.sql` |
| 24 | TABLESAMPLE | `scan_sample_next_tuple` via SYSTEM(100) | `regression_test.sql` |
| 25–43 | UPSERT, MERGE, TRUNCATE, REINDEX, ALTER, JOINs, CTEs, HW accel, Vault, logical decoding | v1.1–v1.3 coverage | `regression_test.sql` |
| 44 | `health_check()` 7-col v1.5+ schema | Realigned to (`version`, `enabled`, `kms_provider`, `dek_available`, `aad_binding`, `wallet_open`, `checked_at`) | `regression_test.sql` |
| 45–46 | BGW token renewal, multi_insert batch | v1.3 coverage | `regression_test.sql` |
| 47 | `health_check()` state transitions | Uses `dek_available` only | `regression_test.sql` |
| 48 | Logical decoding (skipped if `wal_level != logical`) | v1.2 | `regression_test.sql` |
| 49 | Wire format v2 round-trip | v1.4 | `regression_test.sql` |
| 50 | `tde_btree` CREATE INDEX + equality | v1.4 | `regression_test.sql` |
| 51 | `health_check.kms_provider` GUC coherence | Replaces v1.4 `wrapped_dek_perms` test | `regression_test.sql` |
| 52 | `tde_btree` UNIQUE constraint | v1.4 | `regression_test.sql` |
| 53–58 | TOAST large-value round-trips (4 kB text, 8 kB jsonb, UPDATE, bulk COPY, inline/EXTERNAL storage paths) | v1.7 TAM/TOAST additions | `regression_test.sql` |
| 59 | VACUUM dead tuples | `VACUUM` + `pg_stat_force_next_flush`; dead tuple counter matches delete count | `regression_test.sql` |
| 60 | VACUUM FULL + `tde_tuple_has_external_slow` | `pg_vault_tde_relation_copy_for_cluster`; DELETE after VACUUM FULL finds TOAST chunks even if `HEAP_HASEXTERNAL` was cleared on the rewritten tuple | `regression_test.sql` |
| 61 | CLUSTER | Same `relation_copy_for_cluster` path driven by `CLUSTER ON index`; full round-trip on re-clustered relation | `regression_test.sql` |
| 62 | TOAST + index scan | Large-value column + `index_fetch_tuple`; verifies decrypt survives detoast across index lookup | `regression_test.sql` |
| 63 | TOAST + BitmapHeapScan | Large-value column + `scan_bitmap_next_tuple`; forced bitmap scan | `regression_test.sql` |
| 64 | TOAST + SELECT FOR UPDATE | Large-value column + `tuple_lock`; verifies TOAST-bearing rows handled by tuple_lock | `regression_test.sql` |
| 65 | TOAST + TABLESAMPLE | Large-value column + `scan_sample_next_tuple`; SYSTEM(100) | `regression_test.sql` |
| 66 | TOAST + ANALYZE | Large-value column + `scan_analyze_next_tuple`; verifies stats computed on decrypted text | `regression_test.sql` |
| 67 | TOAST + multi_insert | Bulk COPY with large-value column; `multi_insert` + TOAST round-trip | `regression_test.sql` |
| 68 | Multi-column TOAST | Table with two large-value columns; both columns decoded correctly after TOAST | `regression_test.sql` |
| 69 | UPDATE large↔large / large↔small | `old_has_external` branch in `tuple_update`; UPDATE large→large, large→small, small→large | `regression_test.sql` |
| 70 | `toast_am` GUC | `pg_vault_tde_toast_am` returns correct AM OID based on `toast_encryption` GUC; TOAST table AM matches expectation | `regression_test.sql` |
| 53–72 | Per-table DEK catalog, TOAST large-value, DEK isolation, tde_btree native ops, wire format v3 AAD, online rotation BGW | v1.5 coverage | `regression_test_v15.sql` |
| 73–110 | Wallet init/unlock/lock, wallet passphrase, rotate_kek, bundle export/import, TOAST storage paths (EXTERNAL/EXTENDED), VACUUM FULL + TOAST, CLUSTER, all seven read paths with TOAST, ANALYZE, multi_insert, UPDATE old_has_external, ALTER TABLE AM switch, online rotation, CREATE TABLE AS, WITH HOLD cursor plaintext spill | v1.6 coverage | `regression_test_v16.sql` |

> **Skip semantics under `make ci-regress` (vault provider):**
> Test 48 SKIP if `wal_level != logical`; Test 61 (v15) SKIP if the `pageinspect`
> contrib extension is not available; Tests 74–80 SKIP if `kms_provider != local`;
> tests 84–85 SKIP if `pg_vault_tde.dev_mode != on`; test 103 SKIP if
> `pg_vault_tde.toast_encryption != on`.
> Net result: 110/110 PASS with the corresponding skips.
>
> **Under `make ci-wallet` (`kms_provider=local`):**
> Tests 73–79 PASS; test 80 SKIPS unless `wallet_passphrase_env` is wired
> up; tests 81–110 also PASS (the v1.6 patch resolved the change_passphrase
> SPI invalidation crash and the rotate_kek MAC mismatch).

---

## Test Writing Template

When adding a new TAM/IAM callback, follow this template:

```sql
-- Test NN: [Feature Name] ([callback_name] path)
-- Validates: [what this test proves]

-- Setup: create encrypted table
CREATE TABLE test_nn_feature (
    id serial PRIMARY KEY,
    val text
) USING encrypted_heap;

-- Insert known data
INSERT INTO test_nn_feature (val) VALUES ('known_plaintext');

-- Force specific scan path
SET enable_seqscan = off;       -- if testing index scan
SET enable_indexscan = off;     -- if testing bitmap scan
-- etc.

-- Verify round-trip
SELECT val FROM test_nn_feature WHERE id = 1;
-- Expected: 'known_plaintext'

-- Cleanup
DROP TABLE test_nn_feature;
```

For key rotation tests, use SEPARATE tables per DEK generation:

```sql
-- Create and populate with DEK-A
CREATE TABLE test_dek_a (...) USING encrypted_heap;
INSERT INTO test_dek_a ...;

-- Rotate
SELECT pg_vault_tde_rotate_key();
SELECT pg_vault_tde_set_test_dek();

-- Create new table with DEK-B
CREATE TABLE test_dek_b (...) USING encrypted_heap;
INSERT INTO test_dek_b ...;

-- DEK-B table should work
SELECT * FROM test_dek_b;  -- OK

-- DEK-A table should fail (GCM auth error)
SELECT * FROM test_dek_a;  -- ERROR: GCM authentication failed
```

---

## Anti-Patterns (DO NOT)

1. **DO NOT** mix rows encrypted with different DEKs in the same table for
   sequential scan tests — the scan hits wrong-DEK rows first and raises
   GCM errors before reaching target rows.

2. **DO NOT** assume `slot->tts_tid` is valid after
   `ExecFetchSlotHeapTuple(slot, false, ...)` — use
   `bslot->base.tuple->t_self` while buffer pin is held.

3. **DO NOT** test `pg_vault_tde_decode_slot` on already-decoded slots
   without the double-decode guard.

4. **DO NOT** use `VACUUM FULL` in rotation tests — it rewrites tuples,
   which re-encrypts them with the current DEK, masking the rotation test.

5. **DO NOT** rely on specific tuple ordering in sequential scans — heap
   page allocation and HOT chains affect order.

---

## TAP Test Conventions

```perl
# tap/NN_feature.t
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More tests => N;

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_vault_tde'");
$node->start;

$node->safe_psql('postgres', "CREATE EXTENSION pg_vault_tde;");
$node->safe_psql('postgres', "SELECT pg_vault_tde_set_test_dek();");

# ... test logic ...

$node->stop;
```

---

## Isolation Test Conventions

Isolation specs live in `isolation/` and use the PostgreSQL isolation tester:

```
# isolation/feature_name.spec
setup {
    CREATE EXTENSION IF NOT EXISTS pg_vault_tde;
    SELECT pg_vault_tde_set_test_dek();
}

teardown {
    DROP TABLE IF EXISTS test_table;
}

session s1
step s1_begin   { BEGIN; }
step s1_insert  { INSERT INTO ...; }
step s1_commit  { COMMIT; }

session s2
step s2_read    { SELECT * FROM ...; }

permutation s1_begin s1_insert s2_read s1_commit
```

---

## Benchmark Script (`bench_tde.sh`)

Arguments: `bash bench_tde.sh <row_count>`

Workloads compared: INSERT, SELECT, UPDATE, index scan, TABLESAMPLE.
Both `plain_heap` and `encrypted_heap` are tested. Use
`pg_vault_tde.enabled = off` to isolate TAM overhead from crypto cost.

---

## Test × Callback Coverage Matrix

This matrix maps EVERY TAM/IAM callback to its covering test(s).
A callback with no test is a **gap** that MUST be filled before release.

| Callback | Test(s) | Gap? |
|----------|---------|------|
| `tuple_insert` | 12 | No |
| `tuple_update` | 14, 69 | No |
| `tuple_delete` | 15, 60 | No |
| `multi_insert` | 18, 67 | No |
| `scan_getnextslot` | 12, 14, 16, 19 | No |
| `index_fetch_tuple` | 17, 62 | No |
| `scan_bitmap_next_tuple` | 23, 63 | No |
| `scan_analyze_next_tuple` | 21, 66 | No |
| `scan_sample_next_tuple` | 24, 65 | No |
| `tuple_fetch_row_version` | 14, 64 | No |
| `tuple_lock` | 22, 64 | No |
| `relation_copy_for_cluster` | 60, 61 | No |
| `tde_tuple_has_external_slow` (DELETE after VACUUM FULL) | 60 | No |
| `ambuild` (IAM) | 17 | No |
| `aminsert` (IAM) | 17 | No |

## Expected Output File Conventions

Every regression test MUST have a corresponding expected output file:

```
sql/regression_test.sql  →  expected/pg_vault_tde_init.out
```

When adding new tests (current numbering in `regression_test.sql` goes up to 70):
1. Run the test manually: `psql -f sql/regression_test.sql > expected/pg_vault_tde_init.out 2>&1`
2. Review the output for correctness
3. Commit the `.out` file alongside the `.sql` file
4. NEVER hand-edit `.out` files — always regenerate
5. v1.6 tests (73–110) live in `sql/regression_test_v16.sql`; v1.5 tests (53–72)
   live in `sql/regression_test_v15.sql`. The baseline file `sql/regression_test.sql`
   now contains tests 1–70: the original 52 v1.4 tests plus tests 53–70 added as
   v1.7 TAM/TOAST coverage.
