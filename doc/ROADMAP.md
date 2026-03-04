# pg_vault_tde Roadmap

> Last updated: 2026-07-20 — v1.6 COMPLETED: 72 regression tests; Local Wallet KMS production-ready with SQL unlock/lock, flexible passphrase ingestion, KEK rotation, export/import ceremony, Vault→wallet migration; v1.7 DEFINED.

---

## Completed Releases (Summary)

### v1.1 — KMS / Vault + Key Rotation + TOAST + HW Accel — COMPLETED ✅

> **41 regression tests** — PG 17 + PG 18, zero compiler warnings.

Vault HTTP connector (libcurl async, Transit API), AppRole + K8s JWT auth, graceful key rotation
with `prev_dek` fallback, `pg_vault_tde_reencrypt_table()`, TOAST pre-TOAST fix, PG 17/18/19
build infrastructure, hardware acceleration (OpenSSL 3.x QAT/FIPS/default provider), `tde_btree`
IAM stubs, tests 1–43.

### v1.2 — Logical Decoding Compatibility — COMPLETED ✅

Custom output plugin `pg_vault_tde_pgoutput` — intercepts `change_cb`, decrypts `encrypted_heap`
tuples in-place. Test 48. Known limitation: externally-TOAST'd columns not supported.

### v1.3 — Vault Transit KEK + multi_insert + BGW + health_check — COMPLETED ✅

> **48 regression tests** — PG 17 + PG 18, zero compiler warnings.

Vault Transit KEK wrapping (wrapped DEK persisted to `$PGDATA`), `multi_insert` batching
(3-phase pre-TOAST+encrypt), background worker for token renewal, `pg_vault_tde_health_check()`
14-column composite. Tests 44–48.

### v1.4 — CI/CD + tde_btree + Wire Format v2 — COMPLETED ✅

> **52 regression tests** — PG 17 + PG 18, zero compiler warnings.

CI benchmark pipeline (`run-bench.sh`), OpenBao 3-node Raft integration (12 tests),
wire format v2 with generation tag, `tde_btree` full wiring (ambuild/aminsert/amrescan),
security hardening (file permissions, secret_id rotation, token TTL logging). Tests 49–52.

### v1.5 — Per-Table DEK + Online Rotation + Wire Format v3 AAD — COMPLETED ✅

> **72 regression tests** (52 v1.4 + 20 new) — PG 17 + PG 18, zero compiler warnings.

Per-table DEK catalog (`pg_vault_tde_catalog`), KMS provider abstraction layer
(`pg_vault_tde_kms_provider.h`), TOAST heap-level round-trips, `tde_btree` native type
operator classes (text/int4/uuid/numeric/date/timestamptz), wire format v3 AEAD AAD binding
(cross-table paste attack prevention), online key rotation BGW (`pg_vault_tde_rotate_online`),
AppRole response-wrapping. Wallet SQL stubs registered (not functional). Tests 53–72.

---

## v1.6 — Local Wallet KMS — Production-Ready Offline Encryption — COMPLETED ✅

> Completed: 2026-07-20 — **72 regression tests** passing — PG 17 + PG 18, zero compiler warnings.
>
> **Theme**: The Local Wallet KMS provider becomes a first-class, fully flexible offline
> encryption backend — an equal to the Vault connector.

### What Shipped

#### 1. Local Wallet KMS Provider — Full Implementation

| Feature | Status |
|---------|--------|
| `src/kms/pg_vault_tde_kms_local.c` — complete PKCS#12 / AES-256-WRAP implementation | ✅ Done |
| `kms_provider = 'local'` fully operative — routes `get_dek`/`wrap_dek`/`unwrap_dek` to local provider | ✅ Done |
| PBKDF2-SHA256 with 600,000 iterations (NIST SP 800-132) | ✅ Done |
| Wallet file permissions `0600` enforced at creation and on every open | ✅ Done |

#### 2. Flexible Passphrase Ingestion

| Feature | Status |
|---------|--------|
| GUC `wallet_passphrase_env` — environment variable name | ✅ Done |
| GUC `wallet_passphrase_file` — file path (trimmed, `0400` permission check) | ✅ Done |
| GUC `wallet_passphrase_command` — shell command (analogous to PG's `ssl_passphrase_command`) | ✅ Done |
| GUC `wallet_dev_mode_passphrase` — convenience for dev/CI (only when `dev_mode = on`) | ✅ Done |
| Source priority: command > env > file > dev_mode; conflict detection at startup | ✅ Done |
| `pg_vault_tde_wallet_unlock(passphrase)` — SQL interactive unlock without PG restart | ✅ Done |
| `pg_vault_tde_wallet_lock()` — evict all DEKs from shmem, mark wallet closed | ✅ Done |

#### 3. Wallet Status (6-Column SRF)

`pg_vault_tde_wallet_status()` returns `(wallet_exists bool, wallet_open bool, kek_algorithm text, dek_count int, last_opened timestamptz, file_perms text)`.

#### 4. KEK Rotation and Passphrase Management

| Feature | Status |
|---------|--------|
| `pg_vault_tde_wallet_change_passphrase(old, new)` — re-wraps all DEKs atomically via SPI | ✅ Done |
| `pg_vault_tde_wallet_rotate_kek()` — new random KEK, re-wrap all DEKs, atomic wallet file write | ✅ Done |

#### 5. Wallet Export/Import Ceremony

| Feature | Status |
|---------|--------|
| `pg_vault_tde_wallet_export_bundle(dest, label)` — HMAC-SHA256-signed binary bundle | ✅ Done |
| `pg_vault_tde_wallet_import_bundle(src, passphrase)` — HMAC verify, idempotent catalog UPSERT | ✅ Done |
| Bundle format: `[magic(4) | version(2) | label_len(2) | label | timestamp(8) | wallet_len(4) | wallet_bytes | catalog_entries | HMAC-SHA256(32)]` | ✅ Done |

#### 6. Vault-to-Wallet Migration

`pg_vault_tde_migrate_vault_to_wallet(passphrase)` — online zero-downtime migration: iterates
all `pg_vault_tde_catalog` rows, calls Vault unwrap then local wrap per entry, atomic switch.

#### 7. New GUCs (v1.6)

| GUC | Type | Default | Context |
|-----|------|---------|---------|
| `pg_vault_tde.wallet_passphrase_file` | string | `''` | PGC_POSTMASTER |
| `pg_vault_tde.wallet_passphrase_command` | string | `''` | PGC_POSTMASTER |
| `pg_vault_tde.wallet_dev_mode_passphrase` | string | `''` | PGC_USERSET |
| `pg_vault_tde.dev_mode` | bool | `off` | PGC_POSTMASTER |

### v1.6 Deferred Items (Moved to v1.7+)

- **TOAST chunk-level storage encryption** → v1.7
- **KEK/DEK formal wrapping hierarchy** (provider-agnostic `wrap_dek`/`unwrap_dek` API) → v1.7
- **tde_btree fixed-size type index key encryption** → v1.7
- **Logical replication TOAST gap** → v1.7
- **Column-level encryption** → v1.8
- **GIN / Hash index encryption** → v1.8
- **pg_statistic plaintext mitigation** → v1.8
- **PG19 compatibility audit** — pending PG19 release

---

## v1.7 — TOAST Chunks + KEK Hierarchy + HSM + Audit (Q4 2027)

> Status: 📋 Defined
> **Target**: ~100 regression tests — PG 17 + PG 18 + PG 19.

**Theme**: Close the TOAST data-leak gap, formalize the KEK/DEK wrap hierarchy across
all providers, add PKCS#11/HSM support, audit trail for compliance (PCI-DSS, HIPAA).

### 1. TOAST Chunk-Level Storage Encryption (Critical)

Per-chunk AES-256-GCM at `pg_toast_NNNNN` storage layer using parent relation DEK.
`pg_vault_tde_detoast_datum()` wrapper decrypts chunks before reassembly. Raw TOAST
pages no longer contain plaintext.

### 2. Proper KEK/DEK Wrapping Hierarchy (Critical)

Provider-agnostic `pg_vault_tde_kms_wrap_dek()`/`unwrap_dek()` API. Vault Transit acts
as key protector (not key store) — raw DEK never sent to Vault, only wrapped ciphertext.
`pg_vault_tde_catalog.wrapped_dek` authoritative for all providers.

### 3. tde_btree Fixed-Size Type Encryption (Medium)

Custom btree key serialisation layer for `int4`/`int8`/`uuid`/`date`/`timestamptz`.
New `tde_*_enc_ops` operator classes; deprecation path from v1.5 plaintext ops.

### 4. Logical Replication TOAST Decrypt (Medium)

Decrypt TOAST chunks in `change_cb` before `ReorderBufferToastReplace()`.
Depends on §1 (`pg_vault_tde_detoast_datum()`).

### 5. PKCS#11 / HSM Integration (Critical)

`src/kms/pg_vault_tde_kms_pkcs11.c` — via OpenSSL 3.x PKCS#11 provider.
`C_WrapKey`/`C_UnwrapKey` for DEK wrapping. CI with SoftHSM2.
GUCs: `pkcs11_library`, `pkcs11_slot_id`, `pkcs11_pin_env`.

### 6. Audit Trail / Event Log (Critical)

`src/audit/pg_vault_tde_audit.c` — 10 event types (`KEY_ROTATION`, `DEK_ACCESS`,
`INTEGRITY_VIOLATION`, `WALLET_OPEN`, etc.). `pg_vault_tde_audit_log` encrypted table.
PCI-DSS Requirement 10 / HIPAA §164.312(b).

### 7. pg_dump Plaintext Leak Protection (Medium)

`ProcessUtility_hook` intercepts `COPY TO` on encrypted tables — emits WARNING.
GUC `pg_vault_tde.dump_plaintext_warning = on`.

### 8. Physical Backup Key Sealing (Medium)

`pg_vault_tde_backup_prepare()`/`backup_restore()` — signed bundle of all `wrapped_dek`
entries. `BackupState` hook integration for automatic bundling with `pg_basebackup`.

---

## v1.8 — KMIP + Column-Level + GIN/Hash + HA + Dual-Control (Q2 2028)

> Status: 📋 Defined
> **Target**: ~130 regression tests.

**Theme**: Enterprise HA, KMIP standards compliance, column-level encryption,
regulated-industry features.

### 1. Column-Level Encryption (High)

`ALTER TABLE ... ENABLE/DISABLE COLUMN ENCRYPTION` DDL. Per-column DEK support.
`pg_vault_tde_columns` catalog. `src/tam/pg_vault_tde_column.c`.

### 2. GIN Index Encryption (Medium)

`src/iam/pg_vault_tde_gin.c` — per-entry AES-256-SIV. Equality operators only
(`@>`, `?`, `&&`). Phrase search permanently rejected by `amvalidate`.

### 3. Hash Index Encryption (Low Effort)

`src/iam/pg_vault_tde_hash.c` — same AES-256-SIV pattern as `tde_btree`.

### 4. pg_statistic Plaintext Mitigation (Low)

Post-`ANALYZE` hook: NULL out `stavalues` for encrypted columns.
GUC `pg_vault_tde.encrypt_statistics`.

### 5. KMIP 1.2 Client (Enterprise)

`src/kms/pg_vault_tde_kms_kmip.c` — KMIP 1.2 over mutual TLS. CI with PyKMIP.

### 6. GiST Equality-Only Encryption (Medium)

`src/iam/pg_vault_tde_gist.c` — equality-only operator classes. `amvalidate`
rejects range/geometric strategies.

### 7. Streaming Replication Standby DEK Distribution (Medium)

`pg_vault_tde_replica_setup()` — read-only KMS credentials for standby. HA
documentation for all KMS providers.

### 8. Dual-Control / M-of-N Key Ceremony (High)

`pg_vault_tde_key_custody_info()`. Vault Shamir + PKCS#11 PIN-split documentation.

---

## Permanent Deferrals

These gaps **cannot be closed without modifying PostgreSQL core**.

| Gap | Reason |
|-----|--------|
| **WAL / redo encryption** | Requires hook in `XLogInsert()` / `XLogWrite()` — no extension API |
| **BRIN on encrypted columns** | min/max of AES-SIV ciphertexts is meaningless |
| **General GiST** (range, geometric) | Penalty/picksplit requires ordering; AES-SIV destroys it |
| **pg_upgrade transparent migration** | `pg_upgrade` copies files without TAM; manual `reencrypt_table()` required |
| **Full-text phrase search on encrypted tsvector** | `<->` proximity requires positional ordering |

---

## Version Summary

| Version | Theme | Completed | Tests | Key Features |
|---------|-------|-----------|-------|-----------------------|
| **v1.1** | KMS/Vault + Key Rotation + HW Accel | ✅ 2026 | 41 | Vault Transit, AppRole, prev_dek fallback, OpenSSL 3.x HW dispatch |
| **v1.2** | Logical Decoding | ✅ 2026 | — | `pg_vault_tde_pgoutput` output plugin |
| **v1.3** | Vault KEK + multi_insert + BGW | ✅ 2026 | 48 | Transit KEK wrapping, batch COPY, token renewal BGW, health_check |
| **v1.4** | CI/CD + tde_btree + Wire Format v2 | ✅ 2026-07-05 | 52 | OpenBao 3-node Raft, ambuild/aminsert/amrescan, generation tag |
| **v1.5** | Per-Table DEK + Online Rotation + AAD | ✅ 2026 | 72 | Per-table catalog, native type ops, wire format v3, rotate_online BGW |
| **v1.6** | Local Wallet KMS (production-ready) | ✅ 2026-07-20 | 72 | Wallet unlock/lock, passphrase flexibility, KEK rotation, export/import, Vault→wallet migration |
| **v1.7** | TOAST Chunks + HSM + Audit | Q4 2027 | ~100 | TOAST chunk AES-GCM, PKCS#11/HSM, audit trail, KEK/DEK hierarchy |
| **v1.8** | KMIP + Column-Level + HA | Q2 2028 | ~130 | KMIP 1.2, column-level encryption, GIN/Hash AMs, streaming replication HA |
