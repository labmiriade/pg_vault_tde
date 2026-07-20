# Key Management Overview

pg_vault_tde separates two concerns: the **DEK** (Data Encryption Key — one
per table, encrypts the actual rows) and the **KEK** (Key Encryption Key —
protects the DEKs at rest). The DEK is never stored unencrypted on disk; only
the *wrapped* (KEK-encrypted) DEK is stored, in the `pg_vault_tde_catalog`
table. Where the KEK itself lives is what a **KMS provider** decides.

## The Three KMS Providers

| Provider | `kms_provider` value | KEK lives in | Network dependency | Best for |
|---|---|---|---|---|
| [HashiCorp Vault / OpenBao](KMS-HashiCorp-Vault-OpenBao) | `vault` | Vault/OpenBao Transit engine | Yes — HTTP(S) to Vault | Centralized key management, existing Vault/OpenBao infrastructure, multi-server clusters |
| [Local Wallet](KMS-Local-Wallet) | `local` | Encrypted PKCS#12 file on local disk | No | Standalone servers, air-gapped/offline environments, development |
| [PKCS#11 / HSM](KMS-PKCS11-HSM) | `pkcs11` | Hardware security module (Thales, Utimaco, YubiHSM, AWS CloudHSM, SoftHSM2 for testing) | Depends on HSM (local device or network HSM) | Regulatory/compliance requirements for hardware key custody |

**There is no default provider** — `kms_provider` defaults to an empty
string, which the extension treats as "not yet configured." Set it
explicitly before creating any encrypted table:

```ini
pg_vault_tde.kms_provider = 'vault'
# pg_vault_tde.kms_provider = 'local'
# pg_vault_tde.kms_provider = 'pkcs11'
```

`kmip` (KMIP 1.2) is reserved for a future release (v1.8) and is not
implemented yet.

## Key Hierarchy

```
KMS provider (Vault Transit / local wallet / HSM)
        │  owns/holds the KEK
        │
        ▼  wrap / unwrap (AES-256-WRAP or provider-native)
pg_vault_tde_catalog (on-disk table)
        │  one row per relation: wrapped_dek, kms_provider, generation, timestamps
        │
        ▼  unwrap on cache miss
Shared-memory DEK cache (TdeRelDekMap)
        │  one entry per relation; single LWLock; per-relation generation counter
        │
        ▼
AES-256-GCM tuple encryption / AES-256-SIV index-key encryption
```

- The **DEK** is generated automatically the first time a table is created
  `USING encrypted_heap` — there is no manual DEK provisioning step.
- The **KEK** is provisioned once per provider (Vault Transit key, wallet
  passphrase + generated key, or HSM keygen) and afterward is normally never
  handled directly by an operator.
- An attacker who obtains a filesystem or `pg_basebackup` copy of the data
  directory only ever sees **wrapped** DEKs — the KEK itself never travels
  with the data (see [Backup and Restore](Backup-and-Restore)).

## Per-Database KMS Configuration

All KMS-related GUC parameters (`kms_provider`, `vault_*`, `wallet_*`,
`pkcs11_*`) have context `suset`: a superuser can set them per-database with
`ALTER DATABASE ... SET`, and the change takes effect for new connections
**without a server restart**. This is the primary mechanism for multi-tenant
key isolation on a shared cluster:

```sql
-- cluster-wide default (postgresql.conf / ALTER SYSTEM)
-- pg_vault_tde.kms_provider = 'vault'

-- tenant_a: dedicated Vault Transit key
ALTER DATABASE tenant_a SET pg_vault_tde.vault_key_name      = 'tde-dek-tenant-a';
ALTER DATABASE tenant_a SET pg_vault_tde.vault_transit_mount = 'transit-tenants';

-- tenant_b: fully offline, no Vault dependency at all
ALTER DATABASE tenant_b SET pg_vault_tde.kms_provider          = 'local';
ALTER DATABASE tenant_b SET pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_B';

-- verify effective configuration after reconnecting
\connect tenant_b
SHOW pg_vault_tde.kms_provider;        -- 'local'
SELECT * FROM pg_vault_tde_health_check();
```

The only parameters that are **not** database-scoped (`postmaster` context,
require a full restart) are `pg_vault_tde.enabled`, `max_encrypted_relations`,
and `crypto_provider` — these affect shared-memory sizing or the master
crypto switch and are cluster-wide by nature. See [GUC Reference](GUC-Reference)
for the context of every parameter.

## DEK Caching (Shared Memory)

Every encrypt/decrypt call looks up the relation's DEK in a shared-memory
hash table (`TdeRelDekMap`, capacity controlled by `max_encrypted_relations`,
default 1024, restart required to change). A cache hit is an O(1)
shared-lock lookup; a cache miss reads the wrapped DEK from
`pg_vault_tde_catalog` and unwraps it through the active KMS provider (one
network round-trip for Vault, one local unwrap for the wallet or HSM), then
inserts it into the cache. This is why the **first** query against a
newly-created table, or the first query after a fresh connection, pays a
small extra latency cost, and subsequent queries do not.

## Rotation

pg_vault_tde distinguishes **DEK rotation** (re-encrypts table data with a
new per-table key) from **KEK rotation** (re-wraps the existing DEKs under a
new master key, without touching a single row of table data). Both are
online operations with no exclusive table lock. See [Key Rotation](Key-Rotation)
for the full runbook, and each provider-specific page for provider-specific
rotation details (e.g. PKCS#11 KEK generations that never expire from the
token).

## See Also
- [KMS: HashiCorp Vault / OpenBao](KMS-HashiCorp-Vault-OpenBao)
- [KMS: Local Wallet](KMS-Local-Wallet)
- [KMS: PKCS#11 / HSM](KMS-PKCS11-HSM)
- [Key Rotation](Key-Rotation)
- [GUC Reference](GUC-Reference)
