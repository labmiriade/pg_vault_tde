# pg_vault_tde

**Transparent Data Encryption (TDE) for PostgreSQL 17+** — plug-and-play,
zero core modifications.

pg_vault_tde encrypts every tuple with **AES-256-GCM** at the Table Access
Method layer. Data is encrypted before it reaches the storage manager and
decrypted after it leaves. Encryption keys live in **HashiCorp Vault** /
**OpenBao** and are cached in shared memory with automatic rotation.

**Current release: v1.4** — 52 regression tests, zero compiler warnings on PG 17 + PG 18.

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

Set GUC parameters in `postgresql.conf` (or `ALTER SYSTEM`) to point at your
Vault / OpenBao instance:

```ini
pg_vault_tde.vault_url            = 'https://vault.example.com:8200'
pg_vault_tde.vault_namespace      = ''          # leave empty for community edition
pg_vault_tde.vault_token          = 'hvs.TOKEN' # or use AppRole (1.1)
pg_vault_tde.vault_transit_mount  = 'transit'
pg_vault_tde.vault_key_name       = 'pg-tde-dek'
pg_vault_tde.vault_ca_cert        = '/etc/ssl/vault/ca.pem'
pg_vault_tde.vault_timeout_ms     = 5000
pg_vault_tde.enabled              = on          # set off to benchmark overhead
```

For development and testing (no Vault required):

```sql
-- Inject a random ephemeral DEK (test/dev only — lost on restart)
SELECT pg_vault_tde_set_test_dek();
```

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
| Index keys (B-Tree) | ⚠️ Optional — `tde_btree` | AES-256-SIV — equality only; `bytea` only in v1.4; native types in v1.5 |
| Index keys (GIN, Hash) | 🔜 v1.6 | GIN for jsonb/arrays; Hash for equality hashing |
| Index keys (GiST equality) | 🔜 v1.8 | Equality-only GiST (`inet_ops`); range/geometric GiST permanently deferred |
| TOAST values | 🔜 v1.5 | Large column values (> ~2 kB) — chunk-level AES-GCM planned |
| Column-level granularity | 🔜 v1.6 | Per-column `ENABLE COLUMN ENCRYPTION` DDL |
| WAL / redo log | ✗ Permanently deferred | Requires core hook in `XLogInsert()` — not possible as extension |
| pg_statistic | 🔜 v1.6 | Statistics stored plaintext; MCVs/histograms expose value distribution |

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
   │  [IV(12) | CIPHERTEXT | GCM-TAG(16)] per tuple
   │  Per-backend EVP_CIPHER_CTX pool (reset, not reallocate)
   │  IV batch generation: 256 IVs per pg_strong_random() call
   │
   ▼
KMS Layer — shared-memory DEK cache                    src/kms/
   │  ┌─ dek_cache (shmem, LWLock-protected, generation epoch)
   │  └─ local_dek_cache (per-backend TopMemCtx, generation mismatch → reload)
   │
   ▼
HashiCorp Vault / OpenBao (GUC-configurable endpoint)
```

### Wire Format (on disk, per tuple)

**v2 format** (all new tuples as of v1.4):

```
┌─────────────────────────────────┬────────────────────────────────────────────────────────────┐
│  HeapTupleHeader (t_hoff bytes) │  VER(1) │ GEN(8) │ IV(12) │ Ciphertext │ GCM-Tag(16)      │
│  PLAINTEXT — MVCC fields        │                       ENCRYPTED USER DATA                  │
└─────────────────────────────────┴────────────────────────────────────────────────────────────┘
                                     ←────────── TDE_V2_OVERHEAD = 37 bytes ──────────►
```

v2 overhead: **37 bytes per tuple** (1-byte version `0x02` + 8-byte DEK generation
counter + 12-byte IV + 16-byte GCM authentication tag).

v1 format (written by pg_vault_tde < 1.4) is **fully backward-compatible**: the
decrypt path detects v1/v2 from the first byte and generation counter.

---

## Key Management

### KMS Provider Selection

pg_vault_tde supports multiple KMS backends via a provider abstraction layer
(introduced in v1.5). Select the provider with:

```ini
pg_vault_tde.kms_provider = 'vault'   # HashiCorp Vault / OpenBao (default)
# pg_vault_tde.kms_provider = 'local'  # Local wallet (PKCS#12, no external service)
# pg_vault_tde.kms_provider = 'pkcs11' # HSM via PKCS#11 (v1.7)
# pg_vault_tde.kms_provider = 'kmip'   # KMIP 1.2 (v1.8)
```

### Local Wallet Provider (v1.5 — Offline, No External Service)

A PKCS#12-based encrypted file at
`$PGDATA/pg_vault_tde/wallet.p12` protects the KEK. No network dependency.
Suitable for single-server deployments, air-gapped environments, and development.

```ini
pg_vault_tde.kms_provider          = 'local'
pg_vault_tde.wallet_path           = '/var/lib/postgresql/data/pg_vault_tde/wallet.p12'
pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_PASSPHRASE'   # env var, never postgresql.conf
pg_vault_tde.wallet_auto_open      = on
```

```sql
-- First-time wallet setup:
SELECT pg_vault_tde_wallet_init(current_setting('TDE_WALLET_PASSPHRASE'));
-- Check status:
SELECT * FROM pg_vault_tde_wallet_status();
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

```
pg_vault_tde_dek_cache (shmem, 1 LWLock)
 ├─ dek[32]        : AES-256 key bytes (OPENSSL_cleanse'd on rotation)
 ├─ generation     : uint64 monotonic counter
 └─ valid          : bool
```

Each backend maintains a local copy. On every encrypt/decrypt:
1. Acquire shared lock
2. Compare `local.generation == shmem.generation`
3. If mismatch: reload DEK under shared lock (bounded staleness)

### Key Rotation

```sql
-- Step 1: wipe current DEK from shared memory (all new ops block until step 2)
SELECT pg_vault_tde_rotate_key();

-- Step 2: inject new DEK from Vault (or test random key)
SELECT pg_vault_tde_set_test_dek();   -- dev only
-- Production: trigger Vault re-key and inject via pg_vault_tde_kms_set_dek()
```

> **Important**: rotation does NOT re-encrypt existing rows. Rows written
> with the old DEK will fail GCM authentication with the new DEK. Full
> table re-encryption tooling is on the roadmap (`pg_vault_tde_reencrypt`).

---

## GUC Parameters

All parameters are in the `pg_vault_tde` namespace.

### KMS Provider (v1.5+)

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `kms_provider` | string | `vault` | postmaster | Active KMS backend: `vault`, `local` (v1.5), `pkcs11` (v1.7), `kmip` (v1.8) |
| `wallet_path` | string | `$PGDATA/pg_vault_tde/wallet.p12` | postmaster | Local wallet PKCS#12 file path (`kms_provider = 'local'`) |
| `wallet_passphrase_env` | string | `''` | postmaster | Env var name holding wallet passphrase — env var NAME only, never the value |
| `wallet_auto_open` | boolean | `on` | postmaster | Auto-open wallet on startup if passphrase env var is set |
| `max_encrypted_relations` | integer | `1024` | postmaster | Maximum number of per-table DEK entries in shmem (64–65536) |
| `toast_encryption` | boolean | `on` | postmaster | Encrypt TOAST chunks with the parent relation's DEK (v1.5) |

### Vault / OpenBao (`kms_provider = 'vault'`)

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `vault_url` | string | `''` | postmaster | Vault / OpenBao base URL |
| `vault_namespace` | string | `''` | postmaster | Vault namespace (enterprise; empty for community) |
| `vault_token` | string | `''` | postmaster | Auth token — hidden from `pg_settings` (superuser only) |
| `vault_role_id` | string | `''` | postmaster | AppRole role_id UUID |
| `vault_secret_id` | string | `''` | postmaster | AppRole secret_id — hidden from `pg_settings` (superuser only) |
| `vault_role_name` | string | `''` | postmaster | AppRole role name for secret_id rotation after login **(v1.4)** |
| `vault_k8s_role` | string | `''` | postmaster | Kubernetes JWT auth role name |
| `vault_transit_mount` | string | `transit` | postmaster | Transit secrets engine mount path |
| `vault_key_name` | string | `pg-tde-dek` | postmaster | Transit key name for DEK wrapping |
| `vault_ca_cert` | string | `''` | postmaster | Path to CA bundle for Vault TLS verification |
| `vault_timeout_ms` | integer | `5000` | postmaster | Vault HTTP timeout in ms (0 = no timeout) |
| `vault_response_wrapping` | boolean | `off` | postmaster | Use Vault response-wrapping for AppRole secret_id (v1.5) |

### Background Worker

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `bgw_enabled` | boolean | `off` | postmaster | Enable background worker for automatic token renewal |
| `token_renewal_interval` | integer | `3600` | postmaster | Token renewal interval in seconds (60–86400) |

### General

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `enabled` | boolean | `on` | superuser | Master switch — set `off` to measure TAM overhead without crypto |
| `dump_plaintext_warning` | boolean | `on` | sighup | Emit WARNING when `pg_dump`/`COPY TO` reads from an encrypted table (v1.7) |
| `encrypt_statistics` | boolean | `off` | sighup | Encrypt `pg_statistic` MCVs/histograms for encrypted columns (v1.6) |
| `audit_enabled` | boolean | `on` | sighup | Enable audit event logging to `pg_vault_tde_audit_log` (v1.7) |

---

## SQL Functions

| Function | Returns | Description |
|---|---|---|
| `pg_vault_tde_set_test_dek()` | void | Inject a random ephemeral DEK (**dev/test only**) |
| `pg_vault_tde_rotate_key()` | void | Wipe DEK from shared cache, bump generation |
| `pg_vault_tde_key_generation()` | bigint | Current generation counter |
| `pg_vault_tde_backup_status()` | text | Backup encryption status string |
| `pg_vault_tde_encrypt_test(text)` | bytea | Encrypt text via GCM (**test only**) |
| `pg_vault_tde_decrypt_test(bytea)` | text | Decrypt bytea via GCM (**test only**) |
| `pg_vault_tde_health_check()` | composite | KMS, DEK, crypto, and wallet status (15 columns) |
| `pg_vault_tde_verify_integrity(regclass)` | void | GCM tag audit scan of all tuples |
| `pg_vault_tde_reencrypt_table(regclass, int)` | bigint | Batch re-encrypt with current DEK (locks table) |
| `pg_vault_tde_rotate_online(regclass, int)` | void | BGW-based online rotation, no exclusive lock **(v1.5)** |
| `pg_vault_tde_rotation_status(regclass)` | composite | Online rotation progress **(v1.5)** |
| `pg_vault_tde_wallet_init(text)` | void | Create local wallet and generate KEK **(v1.5)** |
| `pg_vault_tde_wallet_change_passphrase(text, text)` | void | Re-protect wallet with new passphrase **(v1.5)** |
| `pg_vault_tde_wallet_status()` | composite | Wallet existence, open state, algorithm **(v1.5)** |
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
| pg_dump / pg_restore | ✅ Full | pg_dump reads via scan_getnextslot → decrypted |
| Streaming replication | ✅ Full | WAL ships encrypted bytes; standby decrypts at TAM layer |
| Page checksums | ✅ Full | Checksums over encrypted content (complementary to GCM) |
| Logical replication (non-TOAST) | ✅ Full (v1.2) | `pg_vault_tde_pgoutput` plugin decrypts tuples before streaming |
| TOAST (large values) | 🔜 v1.5 | Chunk-level AES-GCM planned; unencrypted in v1.4 |
| Logical replication (TOAST columns) | 🔜 v1.5 | TOAST decryption in `change_cb` before `ReorderBufferToastReplace()` |
| Range scans on TDE indexes | ⚠️ By design | `tde_btree`/`tde_gin`/`tde_hash` use AES-SIV — equality only; ranges return empty |
| Column-level encryption | 🔜 v1.6 | Per-column `ENABLE COLUMN ENCRYPTION` DDL |

---

## Testing

```bash
# Full local CI pipeline (build + all tests + bench):
make ci-all

# Test against a specific PG version:
PG_VERSION=17 make ci-all

# Individual test stages:
make ci-regress          # 52 SQL regression tests
make ci-checksums        # 52 tests + page checksum compatibility
make ci-tap              # TAP tests with mock Vault
make ci-isolation        # Concurrency / MVCC isolation tests
make ci-vault            # Vault integration (Compose-based)
make ci-openbao          # OpenBao Raft 3-node HA integration (12 tests)
make ci-bench            # Performance benchmark (encrypted vs plain heap)
make ci-bench BENCH_ROWS=100000  # with custom row count

# Cleanup:
make ci-clean            # Remove test containers and images
```

Test coverage (52 tests):
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
- Test 51: health_check() `wrapped_dek_perms` column **(v1.4)**
- Test 52: tde_btree UNIQUE constraint **(v1.4)**

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

## Limitations (v1.4)

See [doc/ROADMAP.md](doc/ROADMAP.md) for the full gap-closure roadmap.

1. **TOAST encryption** (→ v1.5): Column values > ~2 kB are stored in a TOAST
   table that uses the standard heap AM. These values are currently unencrypted.

2. **tde_btree bytea-only** (→ v1.5): The `tde_btree` index AM supports only
   `bytea` columns in v1.4. Native operator classes for `text`, `int4`, `uuid`,
   `numeric`, `timestamptz` are planned for v1.5.

3. **Range scans on TDE indexes** (by design — permanent): The `tde_btree` AM uses
   AES-256-SIV (equality-preserving, NOT order-preserving). `WHERE col > 'x'` on a
   `tde_btree` index returns empty results. Use sequential scans for range predicates.

4. **Logical replication TOAST gap** (→ v1.5): Tables with externally-toasted columns
   are not supported for logical decoding. `ReorderBufferToastReplace()` runs before
   the output plugin.

5. **WAL unencrypted** (permanently deferred): Full WAL encryption requires a hook in
   `XLogInsert()` / `XLogWrite()` — not achievable as a PostgreSQL extension.

6. **No Local Wallet KMS provider** (→ v1.5): Currently Vault/OpenBao HTTP is the only
   supported KMS backend. A PKCS#12-based local wallet  is planned for v1.5.

7. **All-or-nothing table encryption** (→ v1.6): All columns in an `encrypted_heap`
   table are encrypted. Per-column `ENABLE COLUMN ENCRYPTION` DDL is planned for v1.6.

8. **Single global DEK** (→ v1.5): All `encrypted_heap` tables currently share one DEK
   in shmem. Per-table DEK isolation is planned for v1.5.

---

## License


BSD License (PostgreSQL License) — see [LICENSE](LICENSE).

Compatible with MIT, BSD, ISC, and Apache 2.0.
Not derived from any GPL- or AGPL-licensed code.

---

## Copyright

Copyright © 2026 Miriade S.r.l.
