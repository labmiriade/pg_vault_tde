# GUC Reference

All parameters live in the `pg_vault_tde` namespace. Parameters marked
`suset` can be changed by a superuser at any time — at session level, or
scoped to one database with `ALTER DATABASE ... SET` / one role with `ALTER
ROLE ... SET` — and take effect for new connections with **no server
restart**. Parameters marked `postmaster` require a full server restart
(`postgresql.conf` or `ALTER SYSTEM`, then restart).

Parameters holding secrets (`vault_token`, `vault_role_id`,
`vault_secret_id`, `wallet_dev_mode_passphrase`) are hidden from
non-superusers in `pg_settings` and excluded from configuration file
samples.

## General

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `enabled` | boolean | `on` | postmaster | Master switch for AES-256-GCM encryption on `encrypted_heap` tables. Fixed at server startup — see the warning in [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes) about why this can never be safely toggled on a database with existing encrypted data. |
| `crypto_provider` | string | `''` | postmaster | OpenSSL 3.x provider name for hardware crypto offload. Empty (default) uses built-in AES-NI/ARM CE auto-dispatch; set to `qatprovider` for Intel QAT, `fips` for FIPS mode. |
| `max_encrypted_relations` | integer | `1024` | postmaster | Maximum number of independently-keyed `encrypted_heap` relations in the shared-memory DEK cache (range 64–65536). Increase if you have more than 1024 encrypted tables. |
| `dek_cache_ttl` | integer | `0` | suset | Per-backend DEK cache time-to-live in seconds (range 0–86400). `0` = no expiry. When set, each backend re-reads the DEK from shared memory after this interval, even without a rotation. |

## KMS Provider Selection

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `kms_provider` | string | `''` (**unset — must be configured**) | suset | Active KMS backend: `vault`, `local`, or `pkcs11`. The empty string is a valid, intentional value meaning "not yet configured" — **there is no built-in default provider**. Settable per-database. |

## HashiCorp Vault / OpenBao (`kms_provider = 'vault'`)

All `suset`, superuser-only in `pg_settings`, settable per-database.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `vault_url` | string | `''` | Vault/OpenBao base URL (e.g. `https://vault.example.com:8200`) |
| `vault_namespace` | string | `''` | Vault Enterprise namespace; leave empty for Community Edition |
| `vault_auth_method` | string | `token` | Authentication method: `token`, `approle`, or `kubernetes` |
| `vault_token` | string | `''` | Auth token for the `token` method — hidden from `pg_settings` |
| `vault_role_id` | string | `''` | AppRole `role_id` — hidden from `pg_settings` |
| `vault_secret_id` | string | `''` | AppRole `secret_id` — hidden from `pg_settings` |
| `vault_role_name` | string | `''` | AppRole role name; when set, the used `secret_id` is destroyed after a successful login (single-use pattern) |
| `vault_k8s_role` | string | `''` | Kubernetes auth role name |
| `vault_k8s_mount` | string | `kubernetes` | Kubernetes auth engine mount path |
| `vault_transit_mount` | string | `transit` | Transit secrets engine mount path |
| `vault_key_name` | string | `pg-tde-dek` | Transit key name used for DEK wrapping; override per-database to isolate tenant keys |
| `vault_ca_cert` | string | `''` | Path to CA bundle for Vault TLS verification |
| `vault_timeout_ms` | integer | `5000` | Vault HTTP timeout in ms, range 0–300000 (`0` = no timeout) |

## Background Worker (Vault Token Renewal)

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `bgw_enabled` | boolean | `off` | suset | Enables the background worker that periodically renews the Vault token — only useful with the `approle`/`kubernetes` auth methods. **The worker is registered once, at postmaster startup**: changing this GUC afterward (even via `pg_reload_conf()`) updates the stored value but does not start or stop the worker — a full restart is required for the change to take practical effect. |
| `token_renewal_interval` | integer | `3600` | suset | Token renewal interval in seconds, range 60–86400. Ignored if `bgw_enabled = off`. |

## Local Wallet (`kms_provider = 'local'`)

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `wallet_path` | string | `''` (resolves at runtime to `/var/lib/pg_vault_tde/<DB_OID>/wallet.p12`) | suset | Absolute path to the PKCS#12 wallet file. `SHOW` always returns the effective path, even when this is unset in `postgresql.conf`. |
| `wallet_passphrase_env` | string | `''` | suset | Name of the environment variable holding the wallet passphrase — never the passphrase value itself |
| `wallet_passphrase_file` | string | `''` | suset | Path to a file containing the passphrase; the file must be mode `0400` or `0600` |
| `wallet_passphrase_command` | string | `''` | suset | Shell command whose stdout is the passphrase (highest priority of the three ingestion methods; analogous to `ssl_passphrase_command`) |
| `wallet_auto_open` | boolean | `on` | suset | Auto-open the wallet during startup if a passphrase is available via one of the above; if `off`, opening is deferred until first access |
| `dev_mode` | boolean | `off` | suset | Enables development-only conveniences. **Never set `on` in production.** |
| `wallet_dev_mode_passphrase` | string | `''` | suset | Inline plaintext passphrase, used only when `dev_mode = on`; emits a `WARNING` on every use — hidden from `pg_settings` |

Passphrase source priority when more than one is configured:
`wallet_passphrase_command` > `wallet_passphrase_file` > `wallet_passphrase_env`.

## PKCS#11 / HSM (`kms_provider = 'pkcs11'`)

All `suset`, superuser-only in `pg_settings`, settable per-database.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `pkcs11_library` | string | `''` | Absolute path to the vendor's PKCS#11 module (`.so`), e.g. `/usr/lib/softhsm/libsofthsm2.so` |
| `pkcs11_token_label` | string | `''` | Token label for slot discovery; preferred over `pkcs11_slot_id` |
| `pkcs11_slot_id` | integer | `-1` | Explicit slot ID, used only when `pkcs11_token_label` is empty (`-1` = unset); range -1–`INT_MAX` |
| `pkcs11_pin_env` | string | `PG_TDE_PKCS11_PIN` | Name of the environment variable holding the token user PIN — never the PIN itself |
| `pkcs11_key_label` | string | `pg_vault_tde_kek` | `CKA_LABEL` of the AES-256 KEK object on the token |

## TOAST and Logical Replication

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `toast_encryption` | boolean | `on` | suset | Encrypts TOAST chunks for `encrypted_heap` tables using the parent relation's DEK. Set `off` only for debugging or migration — see [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes). |
| `toast_custom_rmgr` | boolean | `off` | postmaster | Enables the custom WAL resource manager that lets encrypted TOAST chunks be published over logical replication. Requires `pg_vault_tde` in `shared_preload_libraries` (already true) and a full restart — see [Logical Replication](Logical-Replication). |

## See Also
- [Key Management Overview](Key-Management-Overview)
- [SQL Function Reference](SQL-Function-Reference)
- [Security Considerations](Security-Considerations)
