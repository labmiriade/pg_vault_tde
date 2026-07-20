# Known Limitations and Troubleshooting

## Current Limitations (v1.7)

| # | Limitation | Status |
|---|---|---|
| 1 | **Range scans on `tde_btree`** — `WHERE col > x` returns empty results (AES-SIV is not order-preserving) | By design, permanent |
| 2 | **HOT updates disabled** — every `UPDATE` on an `encrypted_heap` table maintains indexes explicitly, never using a HOT update | By design, permanent (see [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes)) |
| 3 | **Parallel index build/rebuild disabled** — `CREATE INDEX`/`REINDEX` on `tde_btree` always runs single-process | By design, permanent |
| 4 | **All-or-nothing table encryption** — every column in an `encrypted_heap` table is encrypted; no per-column opt-out | Planned: per-column `ENABLE COLUMN ENCRYPTION` DDL (v1.8) |
| 5 | **GIN / Hash / GiST index encryption** — only `tde_btree` (B-Tree) exists today | Planned (v1.8) |
| 6 | **`pg_statistic` stored in plaintext** — see [Security Considerations](Security-Considerations) | Planned mitigation (v1.8); `REVOKE` is today's workaround |
| 7 | **WAL encryption** — only tuple payload bytes are encrypted; WAL structural metadata is plaintext, and full WAL encryption would require a core hook (`XLogInsert()`) unavailable to extensions | Permanently deferred |
| 8 | **BRIN on encrypted columns** — min/max of AES-SIV ciphertext is meaningless | By design, permanent |
| 9 | **`WITH HOLD` cursor temp-file spill is unencrypted** | Permanently deferred — see below |
| 10 | **PKCS#11 provider unsupported by `pg_dump_tde`/`pg_restore_tde`** | Planned; use `pg_basebackup_tde` meanwhile |

### `WITH HOLD` Cursor Plaintext Spill — Read Before Relying on Held Cursors

When a transaction holding a `WITH HOLD` cursor commits, PostgreSQL
materializes the cursor's **entire result set** into a tuplestore so it can
still be fetched afterward. If that result set exceeds `work_mem`, the
tuplestore spills to a **plaintext** temporary file on disk. This happens
because the executor populates the tuplestore directly, bypassing the table
access method's write path entirely — there is no extension hook anywhere in
the `WITH HOLD` cursor lifecycle (parse, plan, portal start, commit-time
persist) that pg_vault_tde can intercept. (This is the same class of gap
documented for other PostgreSQL TDE implementations, including Percona's
`pg_tde`.)

The spilled file can outlive the query that created it — it persists for as
long as the held cursor stays open, and like any other PostgreSQL temp file
is not guaranteed to be cleaned up if the server crashes before the owning
session ends normally.

**Mitigation:**
- Set `work_mem` large enough that cursor result sets are expected to stay
  in memory for your workload.
- Avoid declaring `WITH HOLD` cursors over queries that touch
  `encrypted_heap` tables (directly or through a view) in
  memory-constrained environments, or wherever the result set size can't be
  bounded in advance.

## Troubleshooting

### "GCM tag mismatch" / decryption / integrity errors

This means the ciphertext, IV, or associated data did not authenticate —
pg_vault_tde raises an `ERROR` rather than ever returning a silently wrong
result. Common causes:

- **Wrong DEK/KEK** — most often, connecting to the wrong database/tenant
  configuration, or a wallet/Vault/HSM pointed at the wrong key material
  after a restore. Check `SHOW pg_vault_tde.kms_provider` and the relevant
  provider GUCs against what the data was actually encrypted with.
- **Genuine on-disk corruption** — run
  `SELECT * FROM pg_vault_tde_verify_integrity('mytable');` to scope how
  many tuples are affected, and treat it as a storage/hardware incident.
- **Cross-table/cross-database ciphertext copied by hand** (e.g. a raw
  `COPY` of on-disk bytes from another relation) — the wire format binds
  each tuple to its own `(database, relid, generation)` as authenticated
  data specifically to make this fail loudly instead of silently decrypting
  as the wrong row.

### `pg_vault_tde_wallet_init()` fails / wallet base directory error

The base directory `/var/lib/pg_vault_tde/` must exist, be owned by the OS
user running PostgreSQL, and live outside `PGDATA` before the wallet can be
created. Package installs create it automatically; source builds do not —
see [Installation](Installation) and [KMS: Local Wallet](KMS-Local-Wallet).

### A rotation or `unseal_keys()` call fails with a concurrency error

`unseal_keys()` and `rotate_online()` on the same table conflict under
PostgreSQL's normal MVCC rules (`tuple concurrently updated` or a
duplicate-key error) rather than corrupting anything. Simply re-run the
failed call once the other operation finishes — see
[Key Rotation](Key-Rotation) and [Backup and Restore](Backup-and-Restore).

### `bgw_enabled` or `max_encrypted_relations` change had no effect

Both are restart-affecting: `bgw_enabled` registers a background worker at
postmaster startup (`pg_reload_conf()` alone will not start/stop it), and
`max_encrypted_relations` sizes a shared-memory structure allocated once at
startup. Both need a full server restart, not just a config reload — see
[GUC Reference](GUC-Reference).

### Restore of a `pg_dump_tde` backup fails after moving to a new server

Restore is locked to the exact KEK that produced the backup's wrapped DEK.
If the target uses a different local wallet (or the source database — and
therefore its wallet — was dropped), restore cannot succeed without the
original KEK. See the "Current Limitations" section of
[Backup and Restore](Backup-and-Restore).

### An index still shows up in `pg_vault_tde_check_plaintext_index_keys()`

The index was built before v1.6 with a plaintext (non-`enc_ops`) operator
class on a fixed-size type. The function's output includes a ready-to-run
`REINDEX` statement using the encrypted opclass — see
[Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes).

## See Also
- [Security Considerations](Security-Considerations)
- [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes)
- [Auditing and Monitoring](Auditing-and-Monitoring)
- [GUC Reference](GUC-Reference)
