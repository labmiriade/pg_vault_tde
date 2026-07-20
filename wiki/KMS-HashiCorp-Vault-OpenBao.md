# KMS: HashiCorp Vault / OpenBao

Selected with `pg_vault_tde.kms_provider = 'vault'` (there is no default
provider — see [Key Management Overview](Key-Management-Overview)). The KEK
is held and used entirely inside Vault's/OpenBao's **Transit secrets
engine** — pg_vault_tde only ever sees wrapped DEKs; the raw KEK material
never leaves Vault.

## When to Use It

Centralized key management across multiple PostgreSQL clusters, existing
Vault/OpenBao infrastructure, environments where key custody and audit trail
need to live in a dedicated secrets-management system rather than on the
database host.

## Vault-Side Setup

Enable the Transit engine and create a policy that only allows wrap/unwrap
(encrypt/decrypt) operations — pg_vault_tde never needs to read the key
material itself:

```hcl
path "transit/decrypt/pg-tde-dek" {
  capabilities = ["update"]
}
path "transit/encrypt/pg-tde-dek" {
  capabilities = ["update"]
}
```

## PostgreSQL-Side Configuration

```ini
pg_vault_tde.kms_provider        = 'vault'
pg_vault_tde.vault_url            = 'https://vault.example.com:8200'
pg_vault_tde.vault_namespace      = ''          # leave empty for Vault Community Edition
pg_vault_tde.vault_token          = 'hvs.TOKEN' # or use AppRole / Kubernetes auth, below
pg_vault_tde.vault_transit_mount  = 'transit'
pg_vault_tde.vault_key_name       = 'pg-tde-dek'
pg_vault_tde.vault_ca_cert        = '/etc/ssl/vault/ca.pem'
pg_vault_tde.vault_timeout_ms     = 5000
pg_vault_tde.enabled              = on
```

All of these are `suset` — changeable per-database with `ALTER DATABASE ...
SET`, with no restart required (`enabled` is the one exception — see the
warning in [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes) and
[GUC Reference](GUC-Reference)).

`vault_token`, `vault_secret_id`, and the wallet passphrase GUCs are hidden
from `pg_settings` (only visible to a superuser) so they don't leak through
`SHOW ALL` or monitoring queries that read the catalog.

## Authentication Methods

Set `vault_auth_method` to select how PostgreSQL authenticates to Vault:

| Method | Relevant GUCs |
|---|---|
| `token` (default) | `vault_token` |
| `approle` | `vault_role_id`, `vault_secret_id`, `vault_role_name` (enables automatic secret_id rotation after login) |
| `kubernetes` | `vault_k8s_role`, `vault_k8s_mount` |

## Background Token Renewal

A background worker can renew the active Vault token lease automatically:

```ini
pg_vault_tde.bgw_enabled             = on
pg_vault_tde.token_renewal_interval  = 3600   # seconds, 60–86400
```

`bgw_enabled` requires a **cluster restart** to take effect — the worker is
registered via `RegisterBackgroundWorker()` at postmaster startup, so
`pg_reload_conf()` alone does not start or stop it. You can also renew a
token manually:

```sql
SELECT pg_vault_tde_refresh_token();
```

## Checking Vault Connectivity

```sql
SELECT * FROM pg_vault_tde_vault_status();   -- (configured, auth_method, reachable)
SELECT * FROM pg_vault_tde_health_check();
```

## Rotation

- **DEK rotation** (per table) and **KEK rotation** (`pg_vault_tde_rotate_kek()`,
  which asks Vault Transit to rewrap every stored DEK under a new Transit key
  version) both work with this provider — see [Key Rotation](Key-Rotation).
- Vault's own Transit key versioning means old key versions remain available
  for rewrap, so KEK rotation does not require re-encrypting any table data.

## Migrating to the Local Wallet

If you need to move a database off Vault (e.g. decommissioning a Vault
cluster, or moving a tenant to a fully offline deployment):

```sql
SELECT pg_vault_tde_migrate_vault_to_wallet('a-new-wallet-passphrase');
```

This is an online migration — see [KMS: Local Wallet](KMS-Local-Wallet) for
wallet setup details first.

## See Also
- [Key Management Overview](Key-Management-Overview)
- [Key Rotation](Key-Rotation)
- [GUC Reference](GUC-Reference)
