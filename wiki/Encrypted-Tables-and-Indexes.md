# Encrypted Tables and Indexes

pg_vault_tde adds two access methods: `encrypted_heap` for tables and
`tde_btree` for indexes. This page covers what they do, how to use them, and
exactly what is (and isn't) covered by each.

## `encrypted_heap` — Table Access Method

```sql
CREATE TABLE secrets (id serial, token text) USING encrypted_heap;
```

Every column value in the table is encrypted with AES-256-GCM before it
reaches disk, and decrypted transparently when read back — no application
changes required. The row header (`xmin`, `xmax`, `ctid`, infomask bits)
stays plaintext, because PostgreSQL's MVCC machinery needs to read it
without going through the encryption layer.

### Converting an Existing Table

```sql
ALTER TABLE mytable SET ACCESS METHOD encrypted_heap;   -- plain heap → encrypted
ALTER TABLE mytable SET ACCESS METHOD heap;              -- encrypted → plain heap (decrypts)
```

> **Do not toggle `pg_vault_tde.enabled` instead of doing this properly.**
> Rows are written using the wire format active at the time of the write:
> encrypted when `enabled = on`, verbatim heap tuple when `off`. Flipping
> the GUC and restarting does **not** retroactively convert existing rows —
> reads use whichever format is currently active, so any `encrypted_heap`
> table containing rows written under the other setting will have those
> rows **misread as silent data corruption, not an error**. Only ever change
> `enabled` on a database where every `encrypted_heap` table is empty or has
> been fully rewritten under the target setting first (e.g. via
> `CREATE TABLE ... AS SELECT`).

### TOAST (Large Column Values)

Controlled by `pg_vault_tde.toast_encryption` (default `on`): TOAST chunks
for large column values are encrypted per-chunk with the parent table's DEK,
using the same `encrypted_heap` machinery. Set it to `off` only if you
specifically need plaintext TOAST storage for performance reasons and have
already accepted the confidentiality trade-off for large values.

## `tde_btree` — Index Access Method

```sql
CREATE INDEX ON secrets USING tde_btree (id);
```

| Property | Value |
|---|---|
| Algorithm | AES-256-SIV (deterministic, misuse-resistant authenticated encryption) |
| Equality | Preserved — the same plaintext always produces the same ciphertext under the same DEK, so `=` lookups work |
| Ordering | **Not preserved** — range predicates (`>`, `<`, `BETWEEN`) return empty results |
| Use case | Equality predicates only: `=`, `IN`, `ON CONFLICT` |
| Column types | Both varlena (`text`, `bytea`, `numeric`) and fixed-size (`int4`, `int8`, `uuid`, `date`, `timestamptz`) — all encrypted since v1.7 |

### Operator Classes

`CREATE EXTENSION pg_vault_tde` registers encrypted-key operator classes as
the **default** opclass for their type, so a plain `USING tde_btree (col)`
already picks the encrypted variant — you do not need to name the opclass
explicitly:

```sql
CREATE TABLE employees (
    id       int4,
    username text,
    salary   numeric
) USING encrypted_heap;

CREATE INDEX ON employees USING tde_btree (id);         -- tde_int4_enc_ops (default)
CREATE INDEX ON employees USING tde_btree (username);   -- tde_text_ops (default)

SELECT salary FROM employees WHERE id = 1;              -- uses the index
SELECT * FROM employees WHERE id > 1;                   -- seq scan — index returns empty by design
```

Legacy non-encrypted opclasses (`tde_int4_ops`, etc.) still exist for
backward compatibility but are **not** the default — prefer the `enc_ops`
classes so index keys stay encrypted.

### Index-Only Scans Are Not Supported (By Design)

An index-only scan would return column values straight from the index page
without visiting the heap — but `tde_btree` stores AES-SIV **ciphertext** as
the index key, so that would leak raw ciphertext to the client with no
decryption step. PostgreSQL's planner is prevented from choosing this path
for `tde_btree` indexes; the heap tuple is always fetched instead.

### Parallel Index Build Is Disabled

`amcanbuildparallel = false` on `tde_btree`: PostgreSQL's parallel index
build workers run in separate processes not intercepted by the TAM/IAM
encryption wrappers, so a parallel worker would read raw ciphertext as if it
were plaintext. Index builds and `REINDEX` always run single-process on
`tde_btree`.

## Compatibility Matrix

| Feature | Status | Notes |
|---|---|---|
| Sequential scan | ✅ Full | |
| Index scan | ✅ Full | |
| Bitmap heap scan | ✅ Full | |
| ANALYZE | ✅ Full | Statistics computed on decrypted values |
| TABLESAMPLE | ✅ Full | |
| SELECT FOR UPDATE / SHARE | ✅ Full | |
| INSERT / COPY | ✅ Full | |
| UPDATE | ✅ Full | |
| DELETE | ✅ Full | |
| VACUUM / VACUUM FULL / CLUSTER | ✅ Full | |
| `CREATE TABLE ... AS SELECT` | ✅ Full | |
| `pg_dump` (plain) | ⚠️ Dump is plaintext | Reads via the decrypt-on-read path; use `pg_dump_tde` to keep the dump encrypted — see [Backup and Restore](Backup-and-Restore) |
| Streaming (physical) replication | ✅ Full | WAL ships encrypted bytes; standby decrypts at the TAM layer |
| Page checksums | ✅ Full | Checksums cover the encrypted bytes |
| Logical replication (non-TOAST) | ✅ Full | See [Logical Replication](Logical-Replication) |
| Logical replication (TOAST columns) | ✅ Full (opt-in) | Requires `REPLICA IDENTITY FULL` + primary key — see [Logical Replication](Logical-Replication) |
| Range scans on `tde_btree` | ⚠️ By design, empty results | Use sequential scan, or a plain (unencrypted) index if range queries are required on that column |
| HOT **updates** | ⚠️ Disabled by design | See below |
| Column-level encryption | 🔜 Planned (v1.8) | Currently all-or-nothing per table |
| GIN / Hash / GiST index encryption | 🔜 Planned (v1.8) | Only `tde_btree` exists today |

### Why HOT Updates Are Disabled

An `encrypted_heap` table never uses a HOT (Heap-Only Tuple) update, even
when only non-indexed columns change. This is intentional: it guarantees
`tde_btree` indexes never silently drift out of sync with the heap.
`heap_update` decides HOT eligibility by comparing the **encrypted bytes**
of indexed columns between the old and new tuple — and because every
encryption uses a fresh random IV, the encrypted bytes always differ, even
when the underlying plaintext hasn't changed. The practical consequence:
every `UPDATE` on an `encrypted_heap` table maintains indexes explicitly,
which is slightly more write amplification than an equivalent plain-heap
table, in exchange for indexes that can never silently go stale.

See [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
for this and the rest of the current limitation list.

## See Also
- [Getting Started](Getting-Started)
- [Backup and Restore](Backup-and-Restore)
- [Logical Replication](Logical-Replication)
- [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
