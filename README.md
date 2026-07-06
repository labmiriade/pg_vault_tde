# pg_vault_tde

**Transparent Data Encryption (TDE) for PostgreSQL 17+** — plug-and-play,
zero core modifications.

pg_vault_tde encrypts every tuple with **AES-256-GCM** at the Table Access
Method layer. Data is encrypted before it reaches the storage manager and
decrypted after it leaves. Encryption keys are managed by **HashiCorp Vault** /
**OpenBao** or a **local PKCS#12 wallet** and cached in shared memory with
automatic rotation.

**Current release: v1.7** — 109 regression tests (52 v1.4 + 20 v1.5 + 37 v1.6), zero compiler warnings on PG 17 + PG 18.

### PostgreSQL Version Compatibility

| PG Major | Status | Notes |
|----------|--------|-------|
| 17 | ✅ Supported | Baseline API set |
| 18 | ✅ Supported | `scan_bitmap_next_tuple` signature change (guarded) |
| 19 | 🔜 Planned | Infrastructure ready; audit at release |

---

## Quick Start

### 1. Install

```bash
# Build and install into your PostgreSQL instance
git clone https://github.com/miriade/pg_vault_tde.git
cd pg_vault_tde

# On Debian/Ubuntu (PG 18)
apt-get install -y postgresql-server-dev-18 libssl-dev libcurl4-openssl-dev pkg-config
make && sudo make install

# On Debian/Ubuntu (PG 17)
apt-get install -y postgresql-server-dev-17 libssl-dev libcurl4-openssl-dev pkg-config
make PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config && sudo make install

# On RHEL/Rocky (PG 18)
dnf install -y postgresql18-devel openssl-devel libcurl-devel
make PG_CONFIG=/usr/pgsql-18/bin/pg_config && make install

# On RHEL/Rocky (PG 17)
dnf install -y postgresql17-devel openssl-devel libcurl-devel
make PG_CONFIG=/usr/pgsql-17/bin/pg_config && make install
```

### 2. Configure PostgreSQL

Add to `postgresql.conf`:

```
shared_preload_libraries = 'pg_vault_tde'
```

Restart PostgreSQL and create the extension in your database:

```sql
CREATE EXTENSION pg_vault_tde;
```

### 3. Configure Key Access


#### a) HashiCorp Vault / OpenBao (default)

Set GUC parameters in `postgresql.conf` (or `ALTER SYSTEM`) to point at your Vault / OpenBao instance:

```ini
pg_vault_tde.vault_url            = 'https://vault.example.com:8200'
pg_vault_tde.vault_namespace      = ''          # leave empty for community edition
pg_vault_tde.vault_token          = 'hvs.TOKEN' # or use AppRole (1.1)
pg_vault_tde.vault_transit_mount  = 'transit'
pg_vault_tde.vault_key_name       = 'pg-tde-dek'
pg_vault_tde.vault_ca_cert        = '/etc/ssl/vault/ca.pem'
pg_vault_tde.vault_timeout_ms     = 5000
pg_vault_tde.enabled              = on          # PGC_POSTMASTER: requires a full restart to change
```

> **⚠️ Warning — do not toggle `pg_vault_tde.enabled` on a live database.**
> Rows are written using the wire format active at the time of the write
> (encrypted v4 trailer when `on`, verbatim heap tuple when `off`). Changing
> the setting and restarting does **not** retroactively convert existing
> rows: reads use whatever format is currently active for the *entire*
> table, so any `encrypted_heap` table containing rows written under the
> other setting will have those old rows misread (silent data corruption,
> not an error). Only toggle this setting on databases where `encrypted_heap`
> tables are empty or have been fully migrated (e.g. rewritten via
> `CREATE TABLE ... AS SELECT` under the target setting) beforehand.

#### b) Local Wallet (keypass locale, v1.6+)

To use a local PKCS#12 wallet (no external KMS, suitable for offline/air-gapped/standalone):

1. Set the following in `postgresql.conf`:

```ini
pg_vault_tde.kms_provider          = 'local'
# wallet_path defaults to $PGDATA/base/<DB_OID>/pg_vault_tde/wallet.p12 — omit unless overriding:
# pg_vault_tde.wallet_path         = '/custom/path/to/wallet.p12'
pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_PASSPHRASE'   # env var name only
pg_vault_tde.wallet_auto_open      = on
pg_vault_tde.enabled               = on
```

2. Set the passphrase in the environment before starting PostgreSQL:

```bash
export TDE_WALLET_PASSPHRASE='my-strong-wallet-passphrase'
```

3. Initialize the wallet (first time only, as superuser):

```sql
-- In psql: \set reads the shell variable without exposing the value in
-- pg_stat_activity or server logs (note: backslash-set is a psql meta-command)
\set PASSPHRASE `echo $TDE_WALLET_PASSPHRASE`
SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
```

4. Check wallet status:

```sql
SELECT * FROM pg_vault_tde_wallet_status();
```

5. Unlock/lock wallet interactively (no restart needed):

```sql
SELECT pg_vault_tde_wallet_unlock('my-strong-wallet-passphrase');
SELECT pg_vault_tde_wallet_lock();
```

> **Tip:** You can also use `wallet_passphrase_file` or `wallet_passphrase_command` instead of an environment variable. See the [GUC Parameters](#guc-parameters) section for details.

### 4. Create an Encrypted Table

```sql
CREATE TABLE users (
    id     bigserial PRIMARY KEY,
    email  text,
    ssn    text,
    dob    date
) USING encrypted_heap;

INSERT INTO users (email, ssn, dob)
VALUES ('alice@example.com', '123-45-6789', '1990-01-15');

-- Data is transparently decrypted on read
SELECT email, ssn FROM users WHERE id = 1;
```

---

## What Gets Encrypted

| Layer | Encrypted? | Notes |
|---|---|---|
| Tuple user data | ✅ **Yes** — AES-256-GCM | All column values in `encrypted_heap` tables |
| HeapTupleHeader | ✗ No | xmin, xmax, ctid, infomask — required for MVCC |
| Index keys (B-Tree) | ⚠️ Optional — `tde_btree` | AES-256-SIV — equality only; all types encrypted (v1.7); index-only scans not supported |
| Index keys (GIN, Hash) | 🔜 v1.8 | GIN for jsonb/arrays; Hash for equality hashing |
| Index keys (GiST equality) | 🔜 v1.8 | Equality-only GiST (`inet_ops`); range/geometric GiST permanently deferred |
| TOAST values | ✅ **Yes** | Heap-level round-trips functional; per-chunk storage encryption |
| Column-level granularity | 🔜 v1.8 | Per-column `ENABLE COLUMN ENCRYPTION` DDL |
| WAL / redo log | ✅ **Yes** | Data encrypted before `heap_insert()` |
| pg_statistic | 🔜 v1.8 | Statistics stored plaintext; MCVs/histograms expose value distribution |

> **Column-level**: Only tables created with `USING encrypted_heap` are
> encrypted. Regular `heap` tables are unaffected.

---

## Architecture

```
SQL Layer
   │
   ▼
Table Access Method (TAM) — encrypted_heap            src/tam/
   │  ┌─ tuple_insert ──► tde_encrypt_heap_tuple ──► heap_insert
   │  ├─ tuple_update ──► tde_encrypt_heap_tuple ──► heap_update
   │  ├─ multi_insert ──► tde_encrypt × N ──────► heap_insert × N
   │  ├─ scan_getnextslot     ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ index_fetch_tuple    ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ scan_bitmap_next_tuple ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ scan_analyze_next_tuple ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ scan_sample_next_tuple  ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ tuple_fetch_row_version ──► heapam ──► decode_slot ──► tde_decrypt
   │  └─ tuple_lock             ──► heapam ──► decode_slot ──► tde_decrypt
   │
   ▼
Index Access Method (IAM) — tde_btree                  src/iam/
   │  AES-256-SIV (OpenSSL 3.x EVP_CIPHER_fetch) — deterministic equality
   │  64-byte double-key via PBKDF2-SHA256 from DEK
   │
   ▼
Crypto Layer — AES-256-GCM (OpenSSL 3.x EVP)           src/crypto/
   │  [IV(12) | CIPHERTEXT | GCM-TAG(16) | VER(1) | GEN(8)] per tuple
   │  Per-backend EVP_CIPHER_CTX cached & keyed by (relid, generation):
   │  AES key schedule reused across tuples, only the IV rearmed per call
   │  IV batch generation: 256 IVs per pg_strong_random() call
   │
   ▼
KMS Layer — per-relation DEK cache                     src/kms/
   │  ┌─ TdeRelDekMap (shmem HTAB, one shared LWLock, per-relation generation)
   │  └─ pg_vault_tde_catalog (on-disk wrapped DEKs, one row per relation)
   │
   ▼
HashiCorp Vault / OpenBao (GUC-configurable endpoint)
```

### Wire Format (on disk, per tuple)

**v4 format** (default for `encrypted_heap` tables):

```
┌─────────────────────────────────┬───────────────────────────────────────────────────────┐
│  HeapTupleHeader (t_hoff bytes) │   IV(12) │ Ciphertext │ GCM-Tag(16) | VER(1) │ GEN(8) | 
│  PLAINTEXT — MVCC fields        │                                                       │
└─────────────────────────────────┴───────────────────────────────────────────────────────┘
                                   ←───────────── TDE_V4_OVERHEAD = 37 bytes ─────────────→
```

v4 overhead: **37 bytes per tuple** (12-byte IV + 16-byte GCM authentication tag +
1-byte version `0x04` + 8-byte DEK generation counter).
The IV-first layout keeps the version/generation bytes at the **end** so the blob has no
byte-stable prefix — this is what structurally disables HOT updates (see
[Limitations](#limitations-v17)).
v4 also passes `[database_oid(4) | relid(4) | generation(8)]` as AEAD Additional
Authenticated Data (AAD) — zero wire overhead; prevents cross-table ciphertext smuggling.

---

## Key Management

### KMS Provider Selection

pg_vault_tde supports multiple KMS backends via a provider abstraction layer
(introduced in v1.5). Select the provider with:

```ini
pg_vault_tde.kms_provider = 'vault'   # HashiCorp Vault / OpenBao (default)
# pg_vault_tde.kms_provider = 'local'  # Local wallet (PKCS#12, no external service) (v1.6)
# pg_vault_tde.kms_provider = 'pkcs11' # HSM via PKCS#11 (v1.7)
# pg_vault_tde.kms_provider = 'kmip'   # KMIP 1.2 (v1.8)
```

### Per-Database KMS Configuration

Because all `pg_vault_tde` GUC parameters are declared `PGC_SUSET`, a superuser
can assign **different KMS settings to individual databases** in the same cluster
without restarting PostgreSQL.  Each connection picks up the effective GUC value
for its own database, so `postgres` can use a central Vault instance while
`tenant_a` uses a dedicated transit key and `tenant_b` uses a local wallet:

```sql
-- cluster-level default (postgresql.conf / ALTER SYSTEM)
-- pg_vault_tde.kms_provider = 'vault'

-- database "tenant_a" uses a dedicated Vault transit key
ALTER DATABASE tenant_a SET pg_vault_tde.vault_key_name     = 'tde-dek-tenant-a';
ALTER DATABASE tenant_a SET pg_vault_tde.vault_transit_mount = 'transit-tenants';

-- database "tenant_b" uses a local wallet (no Vault dependency)
ALTER DATABASE tenant_b SET pg_vault_tde.kms_provider = 'local';
ALTER DATABASE tenant_b SET pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_B';

-- verify effective settings for a database
\connect tenant_b
SHOW pg_vault_tde.kms_provider;        -- 'local'
SELECT pg_vault_tde_health_check();
```

Settings applied with `ALTER DATABASE SET` take effect for **new connections**
to that database and do not require a server restart.  The cluster-level defaults
in `postgresql.conf` (or `ALTER SYSTEM`) act as the fallback for any database
that does not override a parameter.

### Local Wallet Provider (v1.6 — Offline, No External Service)

A PKCS#12-based encrypted file at
`$PGDATA/base/<DB_OID>/pg_vault_tde/wallet.p12` protects the KEK. No network dependency.
Suitable for single-server deployments, air-gapped environments, and development.

```ini
pg_vault_tde.kms_provider          = 'local'
# wallet_path defaults to $PGDATA/base/<DB_OID>/pg_vault_tde/wallet.p12 — omit unless overriding:
# pg_vault_tde.wallet_path         = '/custom/path/to/wallet.p12'
pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_PASSPHRASE'   # env var, never postgresql.conf
pg_vault_tde.wallet_auto_open      = on
```

```sql
-- First-time wallet setup (\set reads the shell var without exposing it in logs):
\set PASSPHRASE `echo $TDE_WALLET_PASSPHRASE`
SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
-- Check status (5-column SRF):
SELECT * FROM pg_vault_tde_wallet_status();
-- Interactive unlock (without PG restart):
SELECT pg_vault_tde_wallet_unlock('my_passphrase');
-- Lock wallet (evict DEKs from shmem):
SELECT pg_vault_tde_wallet_lock();
-- Rotate KEK: generates a new KEK and re-wraps all per-table DEKs (works for both providers):
SELECT pg_vault_tde_rotate_kek();
-- Export wallet backup bundle:
SELECT pg_vault_tde_wallet_export_bundle('/backup/wallet_bundle.bin', 'daily-backup');
```

### Production (HashiCorp Vault / OpenBao)

The KMS layer calls Vault's Transit secrets engine:

```hcl
# Vault policy
path "transit/decrypt/pg-tde-dek" {
  capabilities = ["update"]
}
path "transit/encrypt/pg-tde-dek" {
  capabilities = ["update"]
}
```

The Vault endpoint, namespace, token, transit mount, key name, CA certificate
and timeout are all configurable via GUC parameters registered at startup
(see [Configure Key Access](#3-configure-key-access)).

### DEK Cache (Shared Memory)

Since v1.7 the cache is a shared-memory hash table (`HTAB`) keyed by `relid`,
not a fixed array. A single `LWLock` from the `"TdeRelDekMap"` named tranche
guards the whole table (no per-entry lock).

```
TdeRelDekMap (shmem HTAB, ShmemInitHash, capacity = pg_vault_tde.max_encrypted_relations, default 1024)
 └─ TdeRelDekMap entry, keyed by relid:
     ├─ relid          : Oid  (hash key)
     ├─ dek[32]        : AES-256 key bytes (OPENSSL_cleanse'd on rotation)
     ├─ prev_dek[32]   : previous DEK (rotation window fallback)
     ├─ generation     : uint64 per-relation counter
     └─ dek_valid / prev_dek_valid : bool
```

DEK access via `pg_vault_tde_kms_get_rel_dek(relid)`:
1. **Fast path**: `hash_search(HASH_FIND)` under `LW_SHARED` — O(1) average; cache hit returns immediately.
2. **Slow path** (cache miss): catalog read (`pg_vault_tde_catalog`) -> KMS unwrap -> `hash_search(HASH_ENTER)` under `LW_EXCLUSIVE`.

### Key Rotation

**Per-table DEK rotation** (re-encrypts all tuples with a new DEK, no exclusive lock):

```sql
SELECT pg_vault_tde_rotate_online('mytable', 1000);
-- Monitor progress:
SELECT * FROM pg_vault_tde_rotation_status('mytable');
```

`rotate_online` accepts both table relations and `tde_btree` index relations:

| Target | What happens |
|--------|-------------|
| `encrypted_heap` table | Generates a new table DEK, re-encrypts every tuple in-place (`RowExclusiveLock`), then rebuilds any `tde_btree` indexes on the table so their SIV ciphertexts match the new DEK. Standard `btree` indexes on encrypted columns need no rebuild. |
| `tde_btree` index | Generates a new index DEK, then calls `reindex_index` (`AccessExclusiveLock` on the index only) to rebuild the index with keys encrypted under the new DEK. The parent table's DEK and heap data are untouched. Passing a non-`tde_btree` index raises an error before touching shmem or the catalog. |

When a table with `tde_btree` indexes is rotated, the index rebuild uses the new table DEK
implicitly because the heap rows the scan reads are re-encrypted first; the index keys
are then produced from the decrypted values and re-encrypted under the (unchanged) index DEK.
To also rotate the index DEK, call `rotate_online` on the index relation directly afterwards.

**KEK rotation** (re-wraps all per-table DEKs under a new KEK — tuple data untouched):

```sql
-- Unified function — works for both local wallet and Vault Transit providers:
SELECT pg_vault_tde_rotate_kek();
```

> **Note on `pg_vault_tde_wallet_change_passphrase(old, new)`**: this function
> automatically rotates the KEK as part of the passphrase change. A separate
> `pg_vault_tde_rotate_kek()` call is unnecessary afterwards. The rationale: if an
> attacker already holds the old passphrase, they already have the old KEK — changing
> the passphrase without rotating the KEK provides no additional protection.

---

## GUC Parameters

All parameters are in the `pg_vault_tde` namespace.

Most parameters have context `suset` (superuser-settable), meaning a superuser
can change them without restarting PostgreSQL and can scope them per-database
with `ALTER DATABASE SET`.  The only exception is `max_encrypted_relations`,
which has context `postmaster` because it controls shared memory allocation at
startup.

**Context summary:**
- `suset` — superuser can `SET` at session level or via `ALTER DATABASE SET` /
  `ALTER ROLE SET`; takes effect for new connections with no restart required.
- `postmaster` — requires a server restart; set in `postgresql.conf` or via
  `ALTER SYSTEM`.

### KMS Provider (v1.5+)

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `kms_provider` | string | `vault` | suset | Active KMS backend: `vault`, `local` (v1.6), `pkcs11` (v1.7), `kmip` (v1.8). Settable per-database via `ALTER DATABASE SET`. |
| `wallet_path` | string | `$PGDATA/base/<DB_OID>/pg_vault_tde/wallet.p12` | suset | Local wallet PKCS#12 file path (`kms_provider = 'local'`). Default computed at runtime — `SHOW` returns the effective path even when not set in `postgresql.conf`. |
| `wallet_passphrase_env` | string | `''` | suset | Env var name holding wallet passphrase — env var NAME only, never the value |
| `wallet_passphrase_file` | string | `''` | suset | File path containing wallet passphrase (trimmed; `0400` permission enforced) **(v1.6)** |
| `wallet_passphrase_command` | string | `''` | suset | Shell command to retrieve passphrase (analogous to PG's `ssl_passphrase_command`) **(v1.6)** |
| `wallet_dev_mode_passphrase` | string | `''` | suset | Convenience passphrase for dev/CI (only honoured when `dev_mode = on`) **(v1.6)** |
| `dev_mode` | boolean | `off` | suset | Enable development mode features (wallet_dev_mode_passphrase) **(v1.6)** |
| `wallet_auto_open` | boolean | `on` | suset | Auto-open wallet on startup if passphrase env var is set |
| `max_encrypted_relations` | integer | `1024` | postmaster | Maximum number of per-table DEK entries in shmem (64–65536). Requires restart — affects shared memory sizing. |
| `toast_encryption` | boolean | `on` | suset | Encrypt TOAST chunks with the parent relation's DEK (v1.5) |

### Vault / OpenBao (`kms_provider = 'vault'`)

All parameters are `suset` — settable per-database with `ALTER DATABASE SET`.

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `vault_url` | string | `''` | suset | Vault / OpenBao base URL |
| `vault_namespace` | string | `''` | suset | Vault namespace (enterprise; empty for community) |
| `vault_token` | string | `''` | suset | Auth token — hidden from `pg_settings` (superuser only) |
| `vault_role_id` | string | `''` | suset | AppRole role_id UUID |
| `vault_secret_id` | string | `''` | suset | AppRole secret_id — hidden from `pg_settings` (superuser only) |
| `vault_role_name` | string | `''` | suset | AppRole role name for secret_id rotation after login **(v1.4)** |
| `vault_k8s_role` | string | `''` | suset | Kubernetes JWT auth role name |
| `vault_transit_mount` | string | `transit` | suset | Transit secrets engine mount path |
| `vault_key_name` | string | `pg-tde-dek` | suset | Transit key name for DEK wrapping. Override per-database to isolate tenant keys. |
| `vault_ca_cert` | string | `''` | suset | Path to CA bundle for Vault TLS verification |
| `vault_timeout_ms` | integer | `5000` | suset | Vault HTTP timeout in ms (0 = no timeout) |

### Background Worker

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `bgw_enabled` | boolean | `off` | suset | Enable background worker for automatic token renewal |
| `token_renewal_interval` | integer | `3600` | suset | Token renewal interval in seconds (60–86400) |

### General

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `enabled` | boolean | `on` | suset | Master switch — set `off` to measure TAM overhead without crypto. Settable per-database. |

---

## Auditing

pg_vault_tde emits an audit record for every security-relevant KMS and DDL event.
Auditing is **always active**: the audit handler is registered unconditionally at
`_PG_init` time and there is no GUC to disable it.

Each event is written to the PostgreSQL server log at `LOG` severity via
`ereport(LOG)` with `errhidestmt` and `errhidecontext` set, so the originating
SQL statement and context stack are suppressed — only the audit fields appear.

### Log format

```
AUDIT: event=<name>, oid=<relation_oid_or_dash>, user=<role_name>, success=<t|f>, pid=<pid>
```

- `oid` — relation OID affected by the event, or `-` for cluster-level events.
- `success` — `t` on success, `f` on failure (e.g. authentication error, GCM tag mismatch).

### Logged events

The `event=` field carries the value below (note the DEK/KEK events drop the `KMS_` prefix in the log line):

| `event=` value | Trigger | PCI DSS ref |
|---|---|---|
| `AUDIT_LOG_START` | Audit subsystem initialised at server start | 10.2.1.6 |
| `AUDIT_LOG_STOP` | Audit subsystem shut down | 10.2.1.6 |
| `DEK_ACCESS` | DEK read from shared-memory cache or KMS | — |
| `DEK_CREATE` | New per-relation DEK generated | — |
| `DEK_ROTATE` | Per-relation DEK rotated (`pg_vault_tde_rotate_online`) | 10.2.1.7 |
| `DEK_DELETE` | DEK revoked / removed from catalog (`DROP TABLE`) | 10.2.1.7 |
| `KEK_ROTATE` | KEK rotated (`pg_vault_tde_rotate_kek`) | 10.2.1.7 |
| `KMS_AUTH_SUCCESS` | KMS / Vault authentication succeeded | 10.2.1.5 |
| `KMS_AUTH_FAILURE` | KMS / Vault authentication failed | 10.2.1.5 |
| `WALLET_OPEN` | Local wallet opened (`pg_vault_tde_wallet_unlock`) | — |
| `WALLET_CLOSE` | Local wallet closed (`pg_vault_tde_wallet_lock`) | — |
| `RELATION_ENCRYPT` | Relation converted to `encrypted_heap` | 10.2.1.7 |
| `RELATION_DECRYPT` | `encrypted_heap` converted back to plain heap | 10.2.1.7 |
| `ACCESS_DENIED` | Decryption failed — wrong key or missing permission | 10.2.1.4 |

`DEK_UPDATE` and `INTEGRITY_VIOLATION` are defined in the audit enum but not yet
emitted by any code path (reserved for a future release).

### Routing audit logs

Because audit records are written as PostgreSQL `LOG` messages they flow through
the standard `log_destination` / `logging_collector` pipeline.  To route them to
a dedicated file or to an external SIEM, match on the `AUDIT:` prefix:

```
# postgresql.conf — route AUDIT lines to a separate file (requires logging_collector = on)
log_destination = 'stderr'
logging_collector = on
log_filename = 'postgresql-%Y-%m-%d.log'
```

External sinks (syslog, Splunk, Datadog) can filter on `AUDIT:` from the standard
log stream without any extension-level configuration.

---

## SQL Functions

| Function | Returns | Description |
|---|---|---|
| `pg_vault_tde_health_check()` | composite | Status (5 columns: version, enabled, kms_provider, enc_ops_available, checked_at) |
| `pg_vault_tde_verify_integrity(regclass)` | void | GCM tag audit scan of all tuples |
| `pg_vault_tde_reencrypt_table(regclass, int)` | bigint | Batch re-encrypt with current DEK (locks table) |
| `pg_vault_tde_rotate_online(regclass, int)` | void | BGW-based online rotation, no exclusive lock **(v1.5)** |
| `pg_vault_tde_rotation_status(regclass)` | composite | Online rotation progress **(v1.5)** |
| `pg_vault_tde_wallet_init(text)` | void | Create local wallet and generate KEK **(v1.5)** |
| `pg_vault_tde_wallet_change_passphrase(text, text)` | void | Re-protect wallet with new passphrase and automatically rotate the KEK (`local` provider only); no separate `rotate_kek()` needed **(v1.6)** |
| `pg_vault_tde_wallet_status()` | composite | Wallet existence, open state, algorithm, last opened, file perms (5 cols) **(v1.6)** |
| `pg_vault_tde_wallet_unlock(text)` | void | Interactive wallet unlock without PG restart **(v1.6)** |
| `pg_vault_tde_wallet_lock()` | void | Evict all DEKs from shmem, mark wallet closed **(v1.6)** |
| `pg_vault_tde_rotate_kek()` | void | Rotate the KEK and re-wrap all per-table DEKs under a new key; works for both `local` and `vault` providers; no tuple data re-encrypted **(v1.7)** |
| `pg_vault_tde_wallet_export_bundle(text, text)` | void | Export HMAC-signed wallet backup bundle **(v1.6)** |
| `pg_vault_tde_wallet_import_bundle(text, text)` | void | Import and verify wallet backup bundle **(v1.6)** |
| `pg_vault_tde_migrate_vault_to_wallet(text)` | void | Online Vault→local wallet migration **(v1.6)** |
| `pg_vault_tde_kms_health_check()` | composite | Active provider connectivity and key access test **(v1.5)** |

---

## Access Methods

| Name | Type | Purpose |
|---|---|---|
| `encrypted_heap` | TABLE | Encrypts all user-data columns of every stored tuple |
| `tde_btree` | INDEX | AES-256-SIV deterministic encryption for B-Tree index keys |

```sql
-- Table with encrypted heap storage
CREATE TABLE secrets (id serial, token text) USING encrypted_heap;

-- B-Tree index with deterministic key encryption
CREATE INDEX ON secrets USING tde_btree (id);
```

---

## Compatibility

| Feature | Status | Notes |
|---|---|---|
| Sequential scan | ✅ Full | `scan_getnextslot` override |
| Index scan | ✅ Full | `index_fetch_tuple` override + `rd_tableam` impersonation |
| Bitmap heap scan | ✅ Full | `scan_bitmap_next_tuple` override |
| ANALYZE | ✅ Full | `scan_analyze_next_tuple` override |
| TABLESAMPLE | ✅ Full | `scan_sample_next_tuple` override |
| SELECT FOR UPDATE | ✅ Full | `tuple_lock` override |
| INSERT / COPY | ✅ Full | `tuple_insert` + `multi_insert` override |
| UPDATE | ✅ Full | `tuple_update` override + ctid preservation |
| DELETE | ✅ Full | No-op (heapam header-only delete, no column data touched) |
| HOT chains | ✅ Full | Header plaintext → HOT chain pointers preserved |
| VACUUM | ✅ Full | Inherited from heapam (dead-tuple header only) |
| CTAS   | ✅ Full | Per-table DEK registration before SELECT is executed |
| `pg_dump` (plain) | ⚠️ Dump is plaintext | pg_dump reads via scan_getnextslot → decrypted. Use `pg_dump_tde` to re-encrypt the output. |
| `pg_dump_tde` / `pg_restore_tde` | ✅ Full | Encrypted logical backup: dump wrapped with AES-256-GCM + DEK sealed in backup header. |
| Streaming replication | ✅ Full | WAL ships encrypted bytes; standby decrypts at TAM layer |
| Page checksums | ✅ Full | Checksums over encrypted content (complementary to GCM) |
| Logical replication (non-TOAST) | ✅ Full (v1.2) | `pg_vault_tde_pgoutput` plugin decrypts tuples before streaming |
| TOAST (large values > ≈2 kB) | ✅ Full | Heap-level round-trips functional; per-chunk storage encryption |
| Logical replication (TOAST columns) | ✅ Full (v1.7) | Custom WAL rmgr (`toast_custom_rmgr`) routes encrypted chunks past the reorder buffer; stitched in `change_cb`. UPDATE/DELETE need `REPLICA IDENTITY FULL` + PK |
| Range scans on TDE indexes | ⚠️ By design | `tde_btree`/`tde_gin`/`tde_hash` use AES-SIV — equality only; ranges return empty |
| Column-level encryption | 🔜 v1.8 | Per-column `ENABLE COLUMN ENCRYPTION` DDL |

---

## Testing

```bash
# Full local CI pipeline (build + all tests + bench):
make ci-all

# Test against a specific PG version:
PG_VERSION=17 make ci-all

# Individual test stages:
make ci-regress          # 109 SQL regression tests (vault provider) — tests 1-109 (test 110 deferred)
make ci-wallet           # 109 SQL regression tests (local wallet provider)
make ci-checksums        # 109 tests + page checksum compatibility
make ci-tap              # TAP tests with mock Vault
make ci-isolation        # Concurrency / MVCC isolation tests
make ci-vault            # Vault integration (Compose-based)
make ci-openbao          # OpenBao Raft 3-node HA integration (12 tests)
make ci-bench            # Performance benchmark (encrypted vs plain heap)
make ci-bench BENCH_ROWS=100000  # with custom row count

# Cleanup:
make ci-clean            # Remove test containers and images
```

Test coverage (109 tests = 52 v1.4 + 20 v1.5 + 37 v1.6):
- Tests 1-11: AES-256-GCM crypto primitives, DEK rotation, tamper detection
- Tests 12-14: TAM INSERT/SELECT/UPDATE end-to-end
- Test 15: DELETE
- Test 16: All-NULL rows (zero-length user data)
- Test 17: Index scan (`index_fetch_tuple` path)
- Test 18: COPY/bulk insert (`multi_insert` path)
- Test 19: Multi-column table (int, text, bool, numeric, timestamptz)
- Test 20: Key rotation isolation (DEK-A rows rejected by DEK-B)
- Test 21: ANALYZE produces correct statistics on decrypted data
- Test 22: SELECT FOR UPDATE (`tuple_lock` path)
- Test 23: BitmapHeapScan (`scan_bitmap_next_tuple` path)
- Test 24: TABLESAMPLE (`scan_sample_next_tuple` path)
- Tests 25-48: UPSERT, MERGE, TRUNCATE, REINDEX, ALTER, JOINs, CTEs, HW accel, Vault, logical decoding
- Test 49: Wire format v2 round-trip (version byte + generation counter) **(v1.4)**
- Test 50: tde_btree CREATE INDEX + equality index scan **(v1.4)**
- Test 51: health_check() `kms_provider` column coherence with GUC **(v1.6 realignment)**
- Test 52: tde_btree UNIQUE constraint **(v1.4)**
- Tests 53-56: Per-table DEK catalog, wallet SQL stubs, rotation progress schema **(v1.5)**
- Tests 57-61: TOAST large-value round-trips (4 kB text, 8 kB jsonb, UPDATE, bulk COPY, raw-page check) **(v1.5)**
- Tests 62-64: Per-table DEK isolation (two tables; DEK-A cannot decrypt table-B), DROP TABLE catalog cleanup **(v1.5)**
- Tests 65-67: tde_btree native type operator classes (text, int4, uuid) **(v1.5)**
- Tests 68-69: Wire format v3 AEAD AAD — cross-table paste attack rejected **(v1.5)**
- Tests 70-72: Online key rotation BGW — concurrent SELECTs, progress tracking, BGW completion **(v1.5)**
- Tests 73-77: Wallet provider — init/unlock/lock, `wallet_status()` 5-col schema (`wallet_exists`, `wallet_open`, `kek_algorithm`, `last_opened`, `file_perms`), DEK round-trip with wallet KEK **(v1.6)**
- Tests 78-79: Wallet `change_passphrase` re-wraps under new KEK; `rotate_kek` re-wraps all per-table DEKs (catalog ciphertext changes; both tables remain readable) **(v1.6 patch)**
- Test 80: Wallet `export_bundle`/`import_bundle` round-trip — SKIPS gracefully if `pg_vault_tde.wallet_passphrase_env` source is not configured (export needs the passphrase string to derive the bundle HMAC key) **(v1.6)**
- Test 81: DDL hook registers BOTH parent and `reltoastrelid` in `pg_vault_tde_catalog`; DROP deregisters both **(v1.6)**
- Test 82: 64 KB compressible payload (pglz keeps it inline) — heap-level pre-TOAST + encrypt round-trip **(v1.6)**
- Test 83: Transactional rollback after pre-TOAST + encrypt keeps the table consistent and restores `reltoastrelid` **(v1.6)**
- Test 84: `pg_vault_tde_verify_plaintext_on_disk()` on STORAGE EXTERNAL payload — forensic helper confirms ciphertext on disk **(v1.6)**
- Test 85: STORAGE EXTERNAL round-trip — incompressible 80 KB payload produces real TOAST chunks (~41 in pg_toast_NNN); validates the TAM `RELKIND_TOASTVALUE` read-path bypass that allows plaintext chunks to round-trip through the encrypted parent table **(v1.6 patch)**
- Test 86: `pg_vault_tde_verify_plaintext_on_disk()` on STORAGE EXTERNAL incompressible payload (real TOAST chunk path; test-only helper, requires `pg_vault_tde.dev_mode=on`) **(v1.6 patch)**
- Test 87: `pg_vault_tde_verify_toast_by_comparison()` byte-for-byte TOAST forensic helper on STORAGE EXTERNAL incompressible payload (test-only helper, requires `pg_vault_tde.dev_mode=on`) **(v1.6 patch)**
- Test 88: STORAGE EXTERNAL — no compression, real TOAST chunks, plaintext visible via SELECT but absent on disk **(v1.6)**
- Test 89: STORAGE EXTENDED — compression + TOAST chunks + transparent DML **(v1.6)**
- Test 90: Storage metadata sanity — `attstorage` flags and TOAST presence **(v1.6)**
- Test 91: STORAGE EXTERNAL DELETE removes visible TOAST entries **(v1.6)**
- Test 92: VACUUM FULL on plain `encrypted_heap` table **(v1.6)**
- Test 93: VACUUM FULL on `encrypted_heap` table with TOAST data **(v1.6)**
- Test 94: CLUSTER on `encrypted_heap` with TOAST data **(v1.6)**
- Test 95: TOAST data readable via index scan (`index_fetch_tuple`) **(v1.6)**
- Test 96: TOAST data readable via BitmapHeapScan **(v1.6)**
- Test 97: TOAST data readable via SELECT FOR UPDATE (`tuple_lock`) **(v1.6)**
- Test 98: TOAST data readable via TABLESAMPLE (`scan_sample_next_tuple`) **(v1.6)**
- Test 99: TOAST data — ANALYZE computes statistics correctly **(v1.6)**
- Test 100: `multi_insert` (COPY path) with TOAST-triggering values **(v1.6)**
- Test 101: Multi-column TOAST — two large varlena attributes **(v1.6)**
- Test 102: UPDATE large→large exercises `old_has_external` branch in `tuple_update` **(v1.6)**
- Test 103: `pg_vault_tde.toast_encryption=on` — TOAST table uses `encrypted_heap` AM (`pg_vault_tde_toast_am` callback) **(v1.6)**
- Test 104: TOAST header overflow edge case **(v1.6)**
- Test 105: `ALTER TABLE x SET ACCESS METHOD heap` — convert encrypted to plain heap **(v1.6)**
- Test 106: `ALTER TABLE x SET ACCESS METHOD encrypted_heap` — convert plain heap to encrypted **(v1.6)**
- Test 107: Tuple readable after `pg_vault_tde_rotation_online()` completes **(v1.6)**
- Test 108: `CREATE TABLE AS` with `encrypted_heap` **(v1.6)**
- Test 109: VACUUM FULL on table with STORAGE EXTERNAL columns **(v1.6)**

> Test runner notes:
> - `make ci-regress` (vault provider): 109/109 PASS, with conditional skips for `wal_level` (test 48), `pageinspect` (test 61) and wallet-only assertions (tests 74–80 when `kms_provider=local` is required).
> - `make ci-wallet` (local provider): tests 73–79 PASS; test 80 SKIPS unless `wallet_passphrase_env` is wired up; tests 81–109 also PASS in wallet mode.
> - Test 110 (WITH HOLD cursor plaintext spill) is permanently deferred — the executor's tuplestore layer bypasses the TAM write path, so pg_vault_tde cannot intercept it without core modifications. The test is commented out in `regression_test_v16.sql`.

---

## Building

### Generic (portable)

```bash
make && sudo make install
```

### Hardware-Accelerated Variants

```bash
# Intel / AMD AES-NI (SSE4.2)
make TDE_TARGET_ARCH=x86_64-aesni

# AMD VAES + AVX2 (Zen 4+, Intel IceLake+)
make TDE_TARGET_ARCH=x86_64-vaes TDE_OPTIMIZE=max

# ARM Crypto Extensions (ARMv8-A, Graviton, Apple M-series)
make TDE_TARGET_ARCH=aarch64-ce

# ARM SVE2 (ARMv9-A, Neoverse V2)
make TDE_TARGET_ARCH=aarch64-sve2 TDE_OPTIMIZE=max

# Detect CPU capabilities
make check-cpu

# OpenSSL AES throughput benchmark
make bench-cpu
```

All variants are ABI-compatible — the `.so` name is always `pg_vault_tde.so`.
Hardware dispatch is via OpenSSL 3.x provider; the `TDE_TARGET_ARCH` flag
enables the matching compiler intrinsics to ensure the provider is available.

### Packages

The easiest way — no local build toolchain required (only `podman` or `docker`):

```bash
# Build all four generic packages (deb+rpm × pg17+pg18) into ./dist/
bash packaging/build_in_container.sh --all

# Single package (defaults: DEB, PG18, Ubuntu 22.04, generic/portable)
bash packaging/build_in_container.sh
bash packaging/build_in_container.sh --format rpm             # RPM PG18
bash packaging/build_in_container.sh --pg-version 17          # DEB PG17
bash packaging/build_in_container.sh --format rpm --pg-version 17  # RPM PG17
```

#### OS version selection

Choose the base OS image for the build container:

```bash
# DEB — Ubuntu or Debian
bash packaging/build_in_container.sh --os-version ubuntu:22.04   # default (Jammy LTS)
bash packaging/build_in_container.sh --os-version ubuntu:24.04   # Noble LTS
bash packaging/build_in_container.sh --os-version debian:12      # Bookworm
bash packaging/build_in_container.sh --os-version debian:11      # Bullseye

# RPM — Rocky Linux or AlmaLinux (EL-compatible)
bash packaging/build_in_container.sh --format rpm --os-version rockylinux:9   # default (EL9)
bash packaging/build_in_container.sh --format rpm --os-version rockylinux:8   # EL8
bash packaging/build_in_container.sh --format rpm --os-version almalinux:9    # EL9 (AlmaLinux)
bash packaging/build_in_container.sh --format rpm --os-version almalinux:8    # EL8 (AlmaLinux)
```

#### Hardware acceleration variants

pg_vault_tde ships a **generic** package (works everywhere) and optional
**hardware-accelerated** packages for platforms that support AES CPU extensions.
OpenSSL 3.x dispatches to the matching provider automatically at runtime when the
compiler intrinsics have been enabled.

| Variant | Target CPUs | Flag |
|---------|-------------|------|
| `generic` | All x86-64 / AArch64 (default) | *(none)* |
| `aesni`   | Intel Westmere/Core 2010+ · AMD Bulldozer+ | `-maes -mpclmul -msse4.2 -O3` |
| `vaes`    | AMD Zen 4+ · Intel Ice Lake+ (VAES + AVX2) | `-mvaes -mavx2 -maes -O3` |
| `armce`   | ARMv8-A: AWS Graviton 2/3, Ampere Altra, Apple M-series | `-march=armv8-a+crypto+crc -O3` |
| `sve2`    | ARMv9-A: NVIDIA Grace, Neoverse V2 | `-march=armv9-a+crypto+sve2 -O3` |

```bash
# AES-NI — Intel/AMD desktop & server (most common)
bash packaging/build_in_container.sh --arch-variant aesni

# VAES — AMD Zen 4+ / Intel Ice Lake+ (wider vectorised AES)
bash packaging/build_in_container.sh --arch-variant vaes

# ARM Crypto Extensions
bash packaging/build_in_container.sh --arch-variant armce

# ARM SVE2 (next-gen ARM servers)
bash packaging/build_in_container.sh --arch-variant sve2
```

Options compose freely:

```bash
# AES-NI RPM for PG17 on Rocky Linux 8
bash packaging/build_in_container.sh \
    --format rpm --pg-version 17 --os-version rockylinux:8 --arch-variant aesni

# ARM CE DEB for PG18 on Debian 12
bash packaging/build_in_container.sh --os-version debian:12 --arch-variant armce
```

If you have a local build environment, invoke the underlying scripts directly:

```bash
# Debian / Ubuntu
bash packaging/build_deb.sh --no-sign                   # generic
bash packaging/build_deb.sh --arch-variant aesni        # AES-NI optimised
bash packaging/build_deb.sh --arch-variant armce        # ARM CE optimised

# RHEL / Rocky / Fedora
bash packaging/build_rpm.sh                             # generic
rpmbuild -ba packaging/rpm/pg_vault_tde-aesni.spec      # AES-NI optimised
rpmbuild -ba packaging/rpm/pg_vault_tde-arm.spec        # ARM CE optimised
```

---

## Encrypted Backups

### `pg_dump_tde` / `pg_restore_tde`
Plain `pg_dump` decrypts rows at read time (via the TAM), so the dump file is
**plaintext**.  `pg_dump_tde` closes this gap by piping the dump through
AES-256-GCM before touching disk:

```bash
# Encrypted dump
pg_dump_tde -h localhost -U postgres -d mydb -o /backup/mydb.tde

# Restore encrypted dump
pg_restore_tde -h localhost -U postgres -d mydb -i /backup/mydb.tde
```

>All other `pg_dump` options are fed directly to it.

### `pg_basebackup`
It's possible to use `pg_basebackup` to create a base backup of the cluster and use it for a standby creation.

#### Primary configuration

Configure like it's not encrypted 

#### Standby configuration
Need the same `wallet.p12` of the primary if the KMS provider used is `local` and the same configuration (basebackup does it already) if the `Vault` is used as KMS provider.

>Current limitation: DEK or KEK rotation make primary and standby disalign on keys


### How it works

1. `pg_dump_tde` forks `pg_dump -Fc` with stdout redirected to a pipe.
2. It connects to PostgreSQL to read `pg_vault_tde.kms_provider` from GUCs.
3. Generates a fresh DEK, wraps it via the active KMS provider, writes a
   `tde_backup_header` (magic + format_version + wrapped_dek) to the output file.
4. Reads the `pg_dump` stream in 64 KB blocks; encrypts each block as:

   `[ Block length (4) | 0x02 (1) | IV (12) | Ciphertext | GCM-TAG (16) ]`

   Block sequence number is bound as GCM AAD — reordering blocks is detectable.
   
   (Reading from a stream with `fread` not guarantee that the block is 64 KB every time,
   that's why the block length is stored)
5. If `pg_dump` fails mid-stream the partial output file is deleted automatically.

### Block wire format

```
[ tde_backup_header ]
[ Block 0: Block length (4) | 0x02 | IV(12) | CT(64 KB) | TAG(16) ]
[ Block 1: Block length (4) | 0x02 | IV(12) | CT(64 KB) | TAG(16) ]
...
```

Each block is independently authenticated — corruption is detected at the block
level, not only at EOF.

### Current limitations

1. Only `-Fc` format is supported.

2. `-j` option is **NOT** supported. Parallel jobs are only supported by `pg_dump`
if the directory format (`-Fd`) is set.

3. Fixed block size: 64 KB.

4. Restore is locked to the original KEK used for DEK wrapping. This means that if we need to restore a dump into a new database that is using a different wallet (KMS local speaking) from the original, we can't. The old wallet or a new wallet containing the old KEK is needed.

   Currently (v1.7) deleting a database (`DROP DATABASE`) deletes his .p12 wallet file. Dump files previous created from this database becomes undecryptable (if wallet file is lost).

5. File-only output and input. The option `--output` or `-o` (for `pg_dump_tde`) and `--input`
or `-i` (for `pg_restore_tde`) are mandatory. Neither piping nor reading from `stdin` are supported.

6. Executing `pg_dump` still produces a plain-text backup
---

## Performance

### Overhead vs Plain Heap

pg_vault_tde adds AES-256-GCM encryption/decryption and IV generation on every
tuple read and write.  The expected overhead depends on workload and row size:

| Workload | Typical Overhead | Notes |
|----------|-----------------|-------|
| OLTP (mixed R/W, 100–500 B rows) | **< 15%** | Target budget per copilot-instructions |
| Bulk INSERT (1M rows) | **25–40%** | AES-GCM + `pg_strong_random` per tuple |
| Sequential scan (1M rows, read-only) | **20–35%** | Decrypt + palloc copy per tuple |
| Index scan (point lookups) | **< 5%** | Single tuple decrypt per fetch |

### Buffer Pin Behaviour

`decode_slot` copies the encrypted tuple from the shared buffer page and decrypts
it into a palloc'd plaintext tuple.  The shared buffer pin is held until
`ExecForceStoreHeapTuple()` releases it internally — this preserves the
page-at-a-time access pattern of heapam's sequential scan.  Buffer hit counts
for encrypted tables should be comparable to plain heap (proportional to the
number of **pages**, not rows).

---

## Limitations (v1.7)

See [doc/ROADMAP.md](doc/ROADMAP.md) for the full gap-closure roadmap.

1. **tde_btree fixed-size type index key encryption** — ✅ **Resolved in v1.7**: `int4`,
   `int8`, `uuid`, `date`, `timestamptz` columns now have their btree index keys encrypted
   with AES-256-SIV, identical to varlena types. **Index-only scans are not supported**
   (by design, for security — see `doc/pg_vault_tde.md` § Index-Only Scans).

2. **Range scans on TDE indexes** (by design — permanent): The `tde_btree` AM uses
   AES-256-SIV (equality-preserving, NOT order-preserving). `WHERE col > 'x'` on a
   `tde_btree` index returns empty results. Use sequential scans for range predicates.

3. **Logical replication of TOAST columns** (✅ resolved in v1.7): Enable
   `pg_vault_tde.toast_custom_rmgr` (PGC_POSTMASTER, default off) to publish
   externally-TOASTed columns to subscribers. UPDATE/DELETE require
   `REPLICA IDENTITY FULL` **and** a primary key; `REPLICA IDENTITY DEFAULT` and
   PK-less tables remain unsupported (the replica identity would be read from
   ciphertext). See doc/pg_vault_tde.md → "Logical Decoding and Replication".

4. **All-or-nothing table encryption** (→ v1.8): All columns in an `encrypted_heap`
   table are encrypted. Per-column `ENABLE COLUMN ENCRYPTION` DDL is planned for v1.8.

5. **WAL unencrypted** (permanently deferred): Full WAL encryption requires a hook in
   `XLogInsert()` / `XLogWrite()` — not achievable as a PostgreSQL extension.

6. **`WITH HOLD` cursor temporary file is unencrypted** (permanently deferred): When a `CURSOR WITH HOLD`
   spills its result set to a temporary file on disk (e.g. when `work_mem` is exhausted),
   the file is written in **plaintext**. PostgreSQL writes the materialized tuples directly
   through the executor's tuplestore layer, bypassing the TAM write path, so
   `pg_vault_tde` has no opportunity to encrypt the data before it reaches disk.

   **Mitigation:** set `work_mem` large enough to keep cursor data in memory,
   or avoid `WITH HOLD` cursors on encrypted tables in memory-constrained environments.

6. **HOT updates are disabled by design** (so that updating an indexed column always
   maintains the index): On an `encrypted_heap` table `heap_update` never chooses a HOT
   (heap-only) update — every UPDATE writes new index entries, keeping `tde_btree` indexes
   coherent without a `REINDEX`.
   **How:** `heap_update` decides whether an update is HOT by comparing the indexed columns
   byte-for-byte between the old and new tuple. Both tuples are encrypted, and the v4 wire
   format is **IV-first**: it begins with the random GCM IV, which changes on every
   encryption. The encrypted image therefore always differs, so `heap_update` sees the
   indexed column as modified and skips the HOT path. The constant `[VERSION | GENERATION]`
   bytes were moved to the **end** of the blob precisely so they fall outside the comparison
   window. See [doc/pg_vault_tde.md](doc/pg_vault_tde.md) § Known Limitations for the full
   analysis (including the v3 bug this resolved).

---

## License


BSD License (PostgreSQL License) — see [LICENSE](LICENSE).

Compatible with MIT, BSD, ISC, and Apache 2.0.
Not derived from any GPL- or AGPL-licensed code.

---

## Copyright

Copyright © 2026 Miriade S.r.l.
