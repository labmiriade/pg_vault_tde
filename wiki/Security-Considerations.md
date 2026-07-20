# Security Considerations

## Threat Model

pg_vault_tde encrypts **data at rest**: relation files, TOAST files, backup
media, and standby base backups. It is explicitly **not** designed to
protect against every threat, and understanding the boundary matters for
compliance sign-off. It does **not** protect:

- In-memory tuple data during query execution (a process with access to a
  running backend's memory sees plaintext, same as any database).
- WAL **structural** metadata — LSNs, block numbers, and relation OIDs are
  plaintext in WAL; only tuple **payload** bytes are ciphertext.
- `pg_statistic` rows written by `ANALYZE` (see below).
- Network connections between backends and clients — use `ssl = on` in
  `pg_hba.conf` / `postgresql.conf`; TDE and TLS address different layers.

## Planner Statistics Expose Value Distribution

`ANALYZE` populates `pg_statistic` **after** decryption, through the normal
TAM read path — so `pg_statistic` is stored **as plaintext** in the system
catalog, including most-common-value lists and histogram bounds. This is a
meaningful gap for highly sensitive columns: an attacker with catalog access
can learn value distributions (e.g. common SSNs or salary bands) without
ever decrypting a row. Mitigate with:

```sql
REVOKE SELECT ON TABLE pg_statistic FROM PUBLIC;
```

Per-column statistics suppression (`ALTER TABLE ... ALTER COLUMN ... SET
STATISTICS 0`) is a further option for individual highly-sensitive columns,
at the cost of planner quality for queries against them.

## Superuser Bypass

A PostgreSQL superuser executing SQL sees **plaintext** — decryption happens
transparently at the TAM layer for any query, superuser or not. A superuser
with **OS-level file access** (not going through SQL) sees only encrypted
content. Row-level security and column-level privileges are complementary
controls for *SQL-level* access, not a replacement for TDE — and TDE does
not replace them either: pg_vault_tde protects the storage layer, not
in-database authorization.

## Key Material Lifecycle

| Event | What Happens |
|---|---|
| Backend start | A local DEK copy is cached in the backend's `TopMemoryContext` |
| Query end | The DEK remains cached in `TopMemoryContext` — it is **not** wiped per-query (this is what keeps repeated queries fast) |
| `pg_vault_tde_rotate_online()` | The per-relation shared-memory DEK is cleansed and the generation counter incremented |
| Backend exit | An exit hook cleanses the backend's local DEK copy |
| OS/process crash | Shared memory is lost; DEKs are re-derived from the KMS provider on the next server start — no manual recovery step needed as long as the KMS/wallet/HSM itself is intact |

## Hardening Checklist

- **Never put secrets in `postgresql.conf`.** Vault tokens, AppRole
  credentials, and wallet passphrases should be supplied via environment
  variables, a `0400`-permission file, or a command
  (`wallet_passphrase_command`) — never as an inline GUC value. The
  extension already hides these GUCs from `pg_settings`, but keep them out
  of configuration-management history and `postgresql.conf` backups too.
- **Keep the wallet base directory outside `PGDATA`.**
  `/var/lib/pg_vault_tde/` must not live inside the data directory — a plain
  `pg_basebackup`/filesystem snapshot of `PGDATA` would then carry the KEK
  material alongside the wrapped DEKs it's supposed to protect, collapsing
  the whole key hierarchy into a single copyable artifact. Verify its
  permissions: owned by the OS user running PostgreSQL, mode `0700`.
- **`REVOKE SELECT ON pg_statistic FROM PUBLIC`** on any database with
  sensitive encrypted columns (see above).
- **Never toggle `pg_vault_tde.enabled` on a database with existing
  `encrypted_heap` data** — see the warning in
  [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes). This is a
  data-corruption risk, not just a security one.
- **Treat the wallet file (`local` provider) as a first-class secret**, with
  its own backup and access-control plan independent of `PGDATA` backups —
  see [KMS: Local Wallet](KMS-Local-Wallet) and
  [Backup and Restore](Backup-and-Restore).
- **Enable TLS (`ssl = on`)** for client connections — TDE protects data at
  rest, not data in transit.
- **Use `dev_mode = off` in production**, always. `wallet_dev_mode_passphrase`
  is intentionally noisy (a `WARNING` on every use) specifically so a stray
  dev-mode setting is hard to miss in production logs.
- **Monitor the audit log** for `KMS_AUTH_FAILURE` and `ACCESS_DENIED`
  events — see [Auditing and Monitoring](Auditing-and-Monitoring).

## See Also
- [Auditing and Monitoring](Auditing-and-Monitoring)
- [Key Management Overview](Key-Management-Overview)
- [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
