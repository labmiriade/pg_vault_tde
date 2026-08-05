# SQL Function Reference

Every function below is registered by `CREATE EXTENSION pg_vault_tde`. The
**Privilege** column reflects the actual grants in the extension's install
script, not a general assumption — it tells you exactly which role can call
each function without being a superuser.

## Diagnostics and Health

> These are executable by **any role** by default — PostgreSQL's standard
> rule for newly created functions applies here (no `REVOKE` was applied to
> them). If your security policy requires restricting diagnostics to
> specific roles, run `REVOKE EXECUTE ... FROM PUBLIC` yourself after
> installing the extension.

| Function | Returns | Description |
|---|---|---|
| `pg_vault_tde_health_check()` | table: `version`, `enabled`, `kms_provider`, `enc_ops_available`, `checked_at` | Single-row diagnostic snapshot of the extension |
| `pg_vault_tde_verify_integrity(rel regclass)` | record: `total_tuples`, `failed_tuples` | GCM authentication-tag scan over every tuple in a table — a failed tuple means tampering or corruption, not a transient error |
| `pg_vault_tde_encrypted_size(rel regclass)` | record: `total_tuples`, `encryption_overhead_bytes` | Encryption storage overhead for a table |
| `pg_vault_tde_hw_accel_info()` | record: `openssl_version`, `configured_provider`, `provider_loaded`, `gcm_cipher`, `siv_cipher`, `aes_ni_available` | OpenSSL provider/cipher diagnostics — confirms which hardware acceleration path is active |
| `pg_vault_tde_vault_status()` | table: `configured`, `auth_method`, `reachable` | Vault/OpenBao connectivity diagnostics |
| `pg_vault_tde_refresh_token()` | boolean | Manually renew the current Vault token lease |
| `pg_vault_tde_get_rotation_status(rel regclass)` | table: `status`, `tuples_done`, `tuples_total`, `pct_complete`, `started_at`, `updated_at` | Online rotation progress for one relation |
| `pg_vault_tde_rotation_status` | view | All in-progress/completed rotations across the cluster (also directly `GRANT`ed to `pg_monitor`) |

## Table and Index Operations

| Function | Returns | Privilege | Description |
|---|---|---|---|
| `pg_vault_tde_reencrypt_table(rel regclass \| text, batch_size int DEFAULT 1000)` | void | `pg_monitor` + superuser | Batch re-encrypt every row with the current DEK; locks the table for the duration |
| `pg_vault_tde_rotate_online(rel regclass, batch_size int DEFAULT 1000)` | void | Any role* | Online DEK rotation, no exclusive lock; accepts `encrypted_heap` tables and `tde_btree` indexes (see [Key Rotation](Key-Rotation)) |
| `pg_vault_tde_check_plaintext_index_keys()` | table: `table_name`, `index_name`, `column_name`, `opclass_name`, `suggestion` | `pg_monitor` + superuser | Lists `tde_btree` indexes still using a pre-v1.6 plaintext operator class, with a ready-to-run `REINDEX` command in `suggestion` |

\* `rotate_online` has no explicit `REVOKE`, but still requires whatever
table-level privileges PostgreSQL itself demands to rewrite the target
relation.

## Local Wallet

| Function | Returns | Privilege | Description |
|---|---|---|---|
| `pg_vault_tde_wallet_init(passphrase text)` | void | `pg_monitor` + superuser | Create the local wallet and generate its KEK (first-time setup) |
| `pg_vault_tde_wallet_status()` | table: `wallet_exists`, `wallet_open`, `kek_algorithm`, `last_opened`, `file_perms` | `pg_monitor` + superuser | Wallet diagnostics |
| `pg_vault_tde_wallet_unlock(passphrase text)` | void | Superuser only | Interactive wallet unlock — no server restart needed |
| `pg_vault_tde_wallet_lock()` | void | Superuser only | Evict all DEKs from shared memory and mark the wallet closed |
| `pg_vault_tde_wallet_change_passphrase(old_passphrase text, new_passphrase text)` | void | Superuser only | Re-protect the wallet under a new passphrase; also rotates the KEK — do not call `rotate_kek()` separately afterward |
| `pg_vault_tde_migrate_vault_to_wallet(new_passphrase text)` | void | Superuser only | Online migration from the Vault provider to a local wallet; the wallet must already exist |

## PKCS#11 / HSM

| Function | Returns | Privilege | Description |
|---|---|---|---|
| `pg_vault_tde_pkcs11_keygen()` | void | Superuser only | One-time AES-256 KEK provisioning on the token; refuses to overwrite an existing key |

## Key Rotation

| Function | Returns | Privilege | Description |
|---|---|---|---|
| `pg_vault_tde_rotate_kek()` | void | Superuser only | Rotate the KEK and re-wrap all per-table DEKs; works across all three providers; no tuple data is touched |

## Backup Key Sealing

| Function | Returns | Privilege | Description |
|---|---|---|---|
| `pg_vault_tde_seal_keys(dest_path text, seal_passphrase text, label text DEFAULT 'basebackup')` | void | Superuser only | Write an HMAC-SHA256-signed bundle of every wrapped DEK to `dest_path` (mode `0600`); the KEK is never included |
| `pg_vault_tde_seal_keys_bytea(seal_passphrase text, label text DEFAULT 'basebackup')` | bytea | Superuser only | Same bundle, returned as `bytea` for a remote client to store (used internally by `pg_basebackup_tde`) |
| `pg_vault_tde_unseal_keys(src_path text, seal_passphrase text)` | void | Superuser only | Verify (HMAC) and re-import a sealed bundle; rejects a tampered file or wrong passphrase before writing anything |

## Access Methods

```sql
CREATE TABLE t (...) USING encrypted_heap;
CREATE INDEX ON t USING tde_btree (col);
```

| Access Method | Type | Purpose |
|---|---|---|
| `encrypted_heap` | TABLE | AES-256-GCM encryption of all user-data columns |
| `tde_btree` | INDEX | AES-256-SIV deterministic (equality-only) encryption of B-Tree index keys |

## See Also
- [GUC Reference](GUC-Reference)
- [Key Rotation](Key-Rotation)
- [Backup and Restore](Backup-and-Restore)
- [Auditing and Monitoring](Auditing-and-Monitoring)
