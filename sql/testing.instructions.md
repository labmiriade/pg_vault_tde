# Testing & QA Instructions — @QA

> **Scope**: `sql/`, `tap/`, `isolation/`, `expected/`, `ci/scripts/`,
> `bench_tde.sh`

---

## Mandatory Validation Gates

ALL gates must pass before any change is considered complete:

```bash
# Gate 1: Full regression (24 tests)
make ci-regress

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

## Test Suite Map (24 Regression Tests)

| Test # | Category | What It Validates |
|--------|----------|-------------------|
| 1–11 | Crypto primitives | GCM encrypt/decrypt, IV uniqueness, tamper detection, rotation |
| 12 | TAM INSERT+SELECT | Basic round-trip on `encrypted_heap` table |
| 13 | On-disk absence | Raw file scan confirms no plaintext on disk |
| 14 | TAM UPDATE | ctid preservation, tuple refetch, HOT chains |
| 15 | DELETE | Row removal without crash |
| 16 | All-NULL row | `user_len == 0` edge case (no Assert crash) |
| 17 | Index scan | `index_fetch_tuple` + `rd_tableam` impersonation |
| 18 | COPY/bulk | `multi_insert` path via `COPY FROM` |
| 19 | Multi-column | int, text, bool, numeric, timestamptz types |
| 20 | Key rotation | DEK-A rows rejected after rotating to DEK-B |
| 21 | ANALYZE | Statistics computed on decrypted data |
| 22 | SELECT FOR UPDATE | `tuple_lock` path |
| 23 | BitmapHeapScan | `scan_bitmap_next_tuple` via forced bitmap scan |
| 24 | TABLESAMPLE | `scan_sample_next_tuple` via SYSTEM(100) |

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
| `tuple_update` | 14 | No |
| `tuple_delete` | 15 | No |
| `multi_insert` | 18 | No |
| `scan_getnextslot` | 12, 14, 16, 19 | No |
| `index_fetch_tuple` | 17 | No |
| `scan_bitmap_next_tuple` | 23 | No |
| `scan_analyze_next_tuple` | 21 | No |
| `scan_sample_next_tuple` | 24 | No |
| `tuple_fetch_row_version` | (implicit via 14) | Borderline |
| `tuple_lock` | 22 | No |
| `ambuild` (IAM) | 17 | No |
| `aminsert` (IAM) | 17 | No |

## Expected Output File Conventions

Every regression test MUST have a corresponding expected output file:

```
sql/regression_test.sql  →  expected/pg_vault_tde_init.out
```

When adding Tests 23-24:
1. Run the test manually: `psql -f sql/regression_test.sql > expected/pg_vault_tde_init.out 2>&1`
2. Review the output for correctness
3. Commit the `.out` file alongside the `.sql` file
4. NEVER hand-edit `.out` files — always regenerate
