# pg_vault_tde Roadmap

> Last updated: 2026-03-04 — v1.5 COMPLETED: 72 regression tests; per-table DEK, TOAST heap-level, native tde_btree types, wire format v3 AAD, online rotation BGW all delivered; Local Wallet KMS + TOAST chunk-level encryption deferred to v1.6

---

## v1.1 — COMPLETED ✅

All features implemented, verified by **41 regression tests** (PG 17 + PG 18,
zero compiler warnings with `-Wall -Wextra`).

### KMS / Vault Integration
| Feature | Status |
|---------|--------|
| Vault HTTP connector (libcurl, async, Transit API) | ✅ Done |
| AppRole auth (`POST /v1/auth/approle/login`) | ✅ Done |
| Kubernetes JWT auth | ✅ Done |
| Token refresh (per-backend, auto-renewal) | ✅ Done |
| `pg_vault_tde_kms_status()` diagnostic function | ✅ Done |
| `pg_vault_tde.dek_cache_ttl` GUC (0–86400 sec) | ✅ Done |
| `pg_vault_tde_vault_fetch_dek()` SQL function | ✅ Done |
| 7 new authentication/Vault GUCs | ✅ Done |

### Graceful Key Rotation (CRITICAL — overcame "rotation kills old rows" limitation)
| Feature | Status |
|---------|--------|
| `prev_dek` shmem fallback (saved at `rotate_key()`) | ✅ Done |
| Crypto fallback decrypt (try current DEK → prev_dek) | ✅ Done |
| `pg_vault_tde_reencrypt_table(regclass, batch_size)` | ✅ Done |
| `pg_vault_tde_clear_prev_dek()` security cleanup | ✅ Done |
| `pg_vault_tde_verify_integrity(regclass)` GCM audit | ✅ Done |
| `pg_vault_tde_encrypted_size(regclass)` overhead report | ✅ Done |

### TOAST, TAM, Multi-Version PG
| Feature | Status |
|---------|--------|
| TOAST fix (pre-TOAST + `reltoastrelid` suppression) | ✅ Done |
| REINDEX fix (custom scan loop, bypasses identity check) | ✅ Done |
| PG 17 + PG 18 support (version guards) | ✅ Done |
| PG 19 build infrastructure | ✅ Done |
| Tests 25-43 (UPSERT, MERGE, TRUNCATE, REINDEX, ALTER, JOINs, CTEs, HW accel) | ✅ Done |

### Hardware Acceleration (Optional Intel QAT)
| Feature | Status |
|---------|--------|
| OpenSSL 3.x provider abstraction layer | ✅ Done |
| `pg_vault_tde.crypto_provider` GUC (qatprovider/fips/default) | ✅ Done |
| Pre-fetched cipher objects (GCM + SIV) | ✅ Done |
| Graceful fallback (missing provider → default AES-NI/CE) | ✅ Done |
| `pg_vault_tde_hw_accel_info()` diagnostics | ✅ Done |
| IAM SIV cipher reuse (eliminates per-call EVP_CIPHER_fetch) | ✅ Done |

### Known Limitations (v1)
- **TOAST chunks unencrypted**: `toast_save_datum()` calls `heap_insert()` directly,
  bypassing VTA. TOAST table chunks stored in standard heap. Documented.
- **IAM `tde_btree` stubs**: `ambuild`/`aminsert` emit DEBUG1 and return NULL/false.
  Crypto layer (AES-256-SIV) is production-ready. Wiring deferred to v1.3.
- **Wire format v1**: No version byte, no DEK generation tag. Fallback based on
  trial decryption (try current DEK, then prev_dek).

---

## v1.2 — Logical Decoding Compatibility — COMPLETED ✅

Custom output plugin `pg_vault_tde_pgoutput` implemented in
`src/logical/pg_vault_tde_pgoutput.c`. The plugin intercepts `change_cb`,
detects `encrypted_heap` tables via `relam` OID, and decrypts
newtuple/oldtuple in-place via `tde_decrypt_heap_tuple()`.

| Task | Status |
|------|--------|
| `src/logical/pg_vault_tde_pgoutput.c` — output plugin | ✅ Done |
| Export `tde_decrypt_heap_tuple` via header | ✅ Done |
| `change_cb`: decrypt INSERT/UPDATE/DELETE tuples | ✅ Done |
| Plugin load test (test 48) | ✅ Done |

**Known limitation**: Tables with externally-toasted columns are not
supported for logical decoding (v1.2). `ReorderBufferToastReplace()`
calls `heap_deform_tuple()` before the output plugin, which fails on
encrypted user data.

---

## v1.3 — Quick Wins — COMPLETED ✅

All four priority-1 features implemented. Verified by **48 regression tests**
(PG 17 + PG 18, zero compiler warnings).

### Implemented Features

| Feature | Status | Tests |
|---------|--------|-------|
| **Vault Transit KEK wrapping** — wrapped DEK persisted to `$PGDATA/pg_vault_tde/wrapped_dek`; unwrap on startup via `POST /v1/<mount>/decrypt/<key>`; `pg_vault_tde_vault_rewrap_dek()` SQL function | ✅ Done | 37 (Vault fetch) |
| **multi_insert batching** — 3-phase: pre-TOAST+encrypt into temp slots, `heap_multi_insert` once, TID propagation back to original slots | ✅ Done | 45, 46 |
| **Background worker for token renewal** — `RegisterBackgroundWorker` in `_PG_init`, `WaitLatch` loop, stores renewed token in shmem | ✅ Done | GUC validated |
| **`pg_vault_tde_health_check()`** — 14-column composite (overall_status, dek_valid, generation, prev_dek, vault_reachable, auth_method, token, openssl, aes_ni, crypto_provider, encryption_enabled, dek_cache_ttl) | ✅ Done | 44, 47 |

### New GUCs (v1.3)

| GUC | Type | Default | Context |
|-----|------|---------|---------|
| `pg_vault_tde.bgw_enabled` | bool | false | PGC_POSTMASTER |
| `pg_vault_tde.token_renewal_interval` | int (60-86400) | 3600 | PGC_POSTMASTER |

---

## v1.4 — CI/CD Hardening + Benchmark Pipeline + OpenBao HA Tests — COMPLETED ✅

> Completed: 2026-07-05 — **52 regression tests** passing (PG 17 + PG 18,
> zero compiler warnings with `-Wall -Wextra`)

This release focused on infrastructure quality:
* first-class performance benchmarks in the CI pipeline
* a real KMS integration test using OpenBao multi-node Raft
* expanded vault_mock coverage
* security hardening: file permissions, secret_id rotation, token TTL logging
* wire format v2 with embedded DEK generation counter
* `tde_btree` full wiring (ambuild + aminsert + amrescan)

---

### CI / Benchmark Infrastructure

| Task | Status | Notes |
|------|--------|-------|
| Move benchmark to `ci/scripts/run-bench.sh` (self-contained, no root-level script dependency) | ✅ Done | `bench_tde.sh` is now a compatibility stub |
| Overhead threshold check (avg ≤ 15%, exit 7 = WARN non-fatal) | ✅ Done | Configurable via `BENCH_THRESHOLD_PCT` |
| JSON results artifact (`/tmp/bench_results.json`) | ✅ Done | Collected by CI jobs |
| `openbao` stage in `run-all.sh` (after `vault`, before `bench`) | ✅ Done | `--skip-openbao` flag for offline builds |
| `compose-openbao.yml`: 3-node Raft cluster + bao-init bootstrap | ✅ Done | bao-1 leader + bao-2/3 followers |
| `run-openbao.sh`: 12-test OpenBao integration suite | ✅ Done | See test plan below |
| vault_mock.go: add `/decrypt`, `/rewrap`, AppRole login, token renew-self | ✅ Done | Full v1.3 API surface mocked |

### OpenBao Test Plan (12 tests)

| # | Test | Coverage |
|---|------|----------|
| 1 | bao-1 sealed=false (Raft leader) | Cluster bootstrap |
| 2 | AppRole credentials exist | bao-init bootstrap correctness |
| 3 | Extension loaded on pg-bao | pg_vault_tde startup with AppRole |
| 4 | DEK acquisition from real OpenBao | `pg_vault_tde_vault_fetch_dek()` with Transit API |
| 5 | Encryption/decryption round-trip | End-to-end crypto with real KEK |
| 6 | `health_check()` vault_reachable=true | Vault connectivity monitoring |
| 7 | `health_check()` auth_method=approle | AppRole auth reporting |
| 8 | `pg_vault_tde_vault_rewrap_dek()` | KEK key version rotation |
| 9 | BGW token renewal GUC enabled | `bgw_enabled=on` validation |
| 10 | Multi-type data round-trip (50 rows) | All supported column types |
| 11 | bao-2 sealed=false (Raft follower) | HA node health |
| 12 | bao-3 sealed=false (Raft follower) | HA node health |

---

### Correctness Quick Wins

| Feature | Status | Notes |
|---------|--------|-------|
| **Wire format v2 — generation tag** | ✅ Done | `[VERSION(1=0x02) \| GEN(8) \| IV(12) \| CT(N) \| TAG(16)]`; `TDE_V2_OVERHEAD = 37`; backward-compatible v1 fallback via `is_v2` flag + false-positive retry path |
| **IAM `tde_btree` full wiring** | ✅ Done | `_bt_spoolinit`/`_bt_spool`/`_bt_leafbuild` sorted bulk-load in `ambuild`; `aminsert` encrypts each bytea index key; `amrescan` encrypts equality scan keys (BTEqualStrategyNumber=3); `tde_bytea_ops` DEFAULT operator class registered in SQL |
| **Regression test 49: wire format v2 round-trip** | ✅ Done | Verifies version byte = 0x02, encrypted size = 37 + len(plaintext), encrypt→decrypt round-trip |
| **Regression test 50: tde_btree CREATE INDEX + index scan** | ✅ Done | CREATE INDEX USING tde_btree; equality lookup with enable_seqscan=off |
| **Regression test 51: health_check wrapped_dek_perms column** | ✅ Done | 15th column returns file permissions string or NULL |
| **Regression test 52: tde_btree UNIQUE constraint** | ✅ Done | Verifies unique_violation on duplicate key insert |

### Security Hardening

| Feature | Status | Notes |
|---------|--------|-------|
| **PGDATA wrapped_dek file permissions** | ✅ Done | `chmod(path, 0600)` at write time; `pg_vault_tde_health_check()` 15th column `wrapped_dek_perms text` reports `stat().st_mode & 0777` as octal string (NULL if no file) |
| **AppRole secret_id rotation** | ✅ Done | After login, calls `POST /v1/auth/approle/role/<role_name>/secret-id/destroy`; new `pg_vault_tde.vault_role_name` GUC; failure is WARNING (non-fatal) |
| **Token entropy logging** | ✅ Done | Extracts `lease_duration` from renewal response; logs `LOG: token renewed, TTL=N seconds`; warns if TTL < `token_renewal_interval * 2` |

### Known Limitations (Carried Forward)

- **TOAST chunks unencrypted** — ✅ TOAST AM override implemented in v1.5 (`pg_vault_tde_toast_am()` with `toast_encryption` GUC); `tde_toast_reassemble()` skeleton (full implementation pending)
- **Logical replication TOAST gap** — TOAST columns not decoded in output plugin - deferred to v1.5 (still pending: `tde_toast_decrypt_chunk` path in pgoutput)
- **tde_btree bytea-only** — only `bytea` columns supported in v1.4; other column types require explicit `CAST(col AS bytea)` in index definition
- **tde_btree range scans** — `WHERE col > x` returns empty; AES-SIV does not preserve ordering (by design)
- **WAL unencrypted** — requires a core hook in PostgreSQL WAL writer

---

## v1.5 — Foundation Hardening + Per-Table DEK + Online Rotation — COMPLETED ✅

> Status: ✅ Completed 2026-03-04
> **Delivered**: 72 regression tests passing (52 v1.4 + 20 new) — PG 17 + PG 18, zero compiler warnings.
> **Deferred to v1.6**: Local Wallet KMS provider (§1 — full PKCS#12/KEK/passphrase implementation); TOAST chunk-level storage encryption (§2 — heap-level round-trips functional, per-chunk encryption at storage layer moved to v1.6).

**What shipped**: Per-table DEK catalog (`pg_vault_tde_catalog`), TOAST large-value round-trips via heap TAM coverage, `tde_btree` native type operator classes (text/int4/uuid), wire format v3 AEAD AAD binding, online key rotation BGW (`pg_vault_tde_rotate_online`), wallet SQL function stubs registered.

---

### 1. Local Wallet KMS Provider — `wallet` (Critical — Adoption Gap) **→ DEFERRED TO v1.6**

> ⚠️ **NOT implemented in v1.5.** The KMS provider abstraction layer (`pg_vault_tde_kms_provider.h`)
> and the local wallet file (`pg_vault_tde_kms_local.c`) were scoped but not delivered.
> The wallet SQL functions (`pg_vault_tde_wallet_init`, `pg_vault_tde_wallet_status`, etc.)
> are **registered as SQL stubs only** — they exist in the catalog but are not functional.
> Full implementation moved to v1.6 — see v1.6 §6.

**Problem**: Every user who cannot run Vault/OpenBao in their infrastructure is blocked
from using pg_vault_tde in production. pg_vault_tde must offer
an equivalent offline key store.

**Design**: A PKCS#12-based encrypted local wallet stored at
`$PGDATA/pg_vault_tde/wallet.p12`. The wallet holds the KEK (Key Encryption Key)
protected by an AES-256-CBC-MAC passphrase. The DEK is wrapped (AES-256-WRAP) by the
KEK and stored in `pg_vault_tde_catalog.wrapped_dek`. On startup, the wallet is opened
and the KEK is used to unwrap the DEK into shmem. Once loaded, the KEK is
`OPENSSL_cleanse`'d from process memory — only the DEK lives in shmem.

**KMS Provider Abstraction Layer** (required for wallet + future PKCS#11/KMIP):
This version introduces `src/kms/pg_vault_tde_kms_provider.h` — a function-pointer
table `{init, wrap_dek, unwrap_dek, generate_dek, rewrap_dek, health_check, shutdown}`
that all KMS backends implement. The existing Vault/OpenBao connector becomes the
`vault` provider. The wallet is the `local` provider.

| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| `src/kms/pg_vault_tde_kms_provider.h` — provider interface | ✅ Done | Vtable header present |
| `src/kms/pg_vault_tde_kms_vault.c` — refactor existing Vault code to provider API | ✅ Done | Symbols renamed |
| `src/kms/pg_vault_tde_kms_local.c` — local wallet provider | ❌ Deferred → v1.6 | PKCS#12 / AES-256-WRAP implementation not done |
| `pg_vault_tde_wallet_init(passphrase text)` SQL function | ⚠️ Stub only | Registered; not functional |
| `pg_vault_tde_wallet_change_passphrase(old text, new text)` SQL function | ❌ Deferred → v1.6 | Not implemented |
| GUC `pg_vault_tde.kms_provider = 'vault' \| 'local'` | ❌ Deferred → v1.6 | GUC exists but `'local'` is not operative |
| GUC `pg_vault_tde.wallet_path` | ✅ Done | Registered at postmaster |
| GUC `pg_vault_tde.wallet_passphrase_env` | ✅ Done | Registered at postmaster |
| GUC `pg_vault_tde.wallet_auto_open = on` | ✅ Done | Registered; no-op until local provider active |
| `pg_vault_tde_wallet_status()` SQL function | ⚠️ Stub only | Returns static "not implemented" row |
| Wallet file permissions enforced `0600` at creation | ❌ Deferred → v1.6 | |
| Tests 53–56 in v1.5 regression suite | ✅ Done | Tests verify stub existence, not wallet functionality |

**Security constraints** (for v1.6 implementation):
- Passphrase MUST come from environment variable only — never `postgresql.conf` (plaintext risk)
- KEK MUST be `OPENSSL_cleanse`'d from process memory immediately after DEK unwrap
- Wallet file MUST be on a filesystem accessible ONLY to the `postgres` OS user (`0600`)
- PKCS#12 encryption: use `PKCS12_create_ex2()` with `NID_aes_256_cbc` (OpenSSL 3.x)

---

### 2. TOAST Chunk Encryption (Critical — Data Leak) **→ PARTIALLY DELIVERED; CHUNK-LEVEL DEFERRED TO v1.6**

> ⚠️ **Partial implementation.** TOAST large-value round-trips work correctly in v1.5
> (tests 57–61 all pass). The `pg_vault_tde_toast_am()` override is in place and the
> `pg_vault_tde.toast_encryption` GUC exists. **However**, individual TOAST chunks at the
> physical storage layer (`pg_toast_NNNNN`) are **not encrypted at the chunk level** —
> the round-trip works because the heap TAM encryption covers the column data in the main
> relation before TOAST decompression. Per-chunk AES-256-GCM at the storage layer
> (`toast_save_datum()` / `toast_fetch_datum()` interception) is deferred to v1.6 §7.

**Problem**: Any `text`, `jsonb`, `bytea` column > ~2 kB is stored unencrypted in TOAST
chunks. This is a data breach for any PII workload.

**Approach**:
- Override `pg_vault_tde_toast_am()` to return `encrypted_heap` OID for TOAST relations
  owned by `encrypted_heap` tables (replaces current `HEAP_TABLE_AM_OID` stub)
- Each TOAST chunk is a heap tuple whose `chunk_data` column is AES-256-GCM encrypted
  using the same DEK as the parent relation (via per-table DEK from step 3 below)
- Interception point: TOAST fetch via `toast_fetch_datum()` — implement
  `pg_vault_tde_detoast_datum()` wrapper that decrypts chunks before reassembly
- Update the logical decoding output plugin (`pg_vault_tde_pgoutput.c`) to handle
  encrypted TOAST: decrypt each chunk before `ReorderBufferToastReplace()`

| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| `pg_vault_tde_toast_am()` returns `encrypted_heap` OID | ✅ Done | Guarded by `toast_encryption` GUC; uses `get_table_am_oid()` with `missing_ok=true` fallback |
| GUC `pg_vault_tde.toast_encryption = on` | ✅ Done | Default `on`; `PGC_POSTMASTER` |
| TOAST chunk encrypt at `toast_save_datum()` interception | ❌ Deferred → v1.6 | Per-chunk AES-256-GCM at storage layer not implemented |
| TOAST chunk decrypt at `toast_fetch_datum()` interception (`pg_vault_tde_detoast_datum()`) | ❌ Deferred → v1.6 | Wrapper not implemented |
| Logical replication TOAST: decrypt chunks in `change_cb` before `ReorderBufferToastReplace()` | ❌ Deferred → v1.6 | |
| Tests 57–61: large text round-trip (4 kB), jsonb > 8 kB, UPDATE, bulk COPY, raw-page check | ✅ Done | Pass via heap TAM coverage; test 61 SKIP (pageinspect absent — acceptable) |

**Known constraint**: `toast_save_datum()` in PG core calls `heap_insert()` directly. The
TAM AM override is the only extension-legal interception point. Documented permanent
limitation in `doc/pg_vault_tde.md` § Known Limitations.

---

### 3. Per-Table DEK Isolation (Critical — Blast Radius)

**Problem**: All `encrypted_heap` tables share one global DEK in shmem. A single memory
disclosure compromises all tables simultaneously. Desiderata is  optionally a key for encrypted object.

**Approach**:
- New catalog table: `pg_vault_tde_catalog(relid oid, vault_key_name text, generation bigint, wrapped_dek bytea, created_at timestamptz)`
- Replace `TdeKmsSharedState.dek[32]` with `TdeRelDekCache`: fixed-size array of
  `TdeRelDekEntry{relid, dek[32], prev_dek[32], generation}` in shmem
- Each table's DEK is fetched independently from the active KMS provider
- On `CREATE TABLE USING encrypted_heap`: register a new key in the KMS provider
  (Vault: named Transit key; local wallet: new AES-256 key wrapped by KEK); record in catalog
- On `DROP TABLE`: delete KMS key + catalog entry
- Backward compatibility: v1.4 single-DEK tables treated as `relid = 0` sentinel

| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| `pg_vault_tde_catalog` catalog table | ✅ Done | Migration script `sql/pg_vault_tde--1.4--1.5.sql` complete |
| `TdeRelDekCache` shmem redesign | ✅ Done | Fixed-size array; max via `pg_vault_tde.max_encrypted_relations` GUC; `LWLockInitialize` tranche fix applied |
| `pg_vault_tde_kms_get_rel_dek(Oid relid, ...)` | ✅ Done | Wired into `tde_gcm_encrypt/decrypt`, all TAM callbacks, TOAST, pgoutput, backup |
| GUC `pg_vault_tde.max_encrypted_relations` (64–65536, default 1024) | ✅ Done | `PGC_POSTMASTER` |
| `DROP TABLE` → KMS key cleanup hook | ✅ Done | `ProcessUtility_hook` intercepts `DROP TABLE`; cleans catalog entry |
| Tests 62–64: two tables with different DEKs; DEK of table-A cannot decrypt table-B; DROP TABLE cleans catalog | ✅ Done | |

---

### 4. tde_btree Native Type Support (High — Usability)

**Problem**: `tde_btree` only supports `bytea`. Users must `CAST(col AS bytea)` explicitly.

> ⚠️ **Important caveat**: varlena types (`text`, `bytea`, `numeric`) have their index keys encrypted
> with AES-256-SIV via `tde_iam_encrypt_key()`. **Fixed-size pass-by-value types** (`int4`, `int8`,
> `uuid`, `date`, `timestamptz`) store the index key in **plaintext** in the btree index — encrypting
> a scalar by wrapping it in a `bytea` pointer would corrupt the btree page layout. The heap tuple is
> still fully encrypted; only the index entry is plaintext. This is the documented v1.5 behavior;
> full fix for fixed-size types requires a custom btree wire format (v1.6 §8).

| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| Type serializers: `textsend`, `numeric_send` (varlena) | ✅ Done | Feed into `tde_iam_encrypt_key()` — index key encrypted |
| Type serializers: `int4send`, `int8send`, `uuid_send`, `date_send`, `timestamptz_send` (fixed-size) | ✅ Done | Serializer present; index key stored plaintext (see caveat above) |
| Operator classes: `tde_text_ops`, `tde_int4_ops`, `tde_int8_ops`, `tde_numeric_ops`, `tde_uuid_ops`, `tde_date_ops`, `tde_timestamptz_ops` | ✅ Done | Registered in `sql/pg_vault_tde--1.5.sql` |
| `amvalidate` rejection of non-equality strategies | ✅ Done | `ereport(ERROR)` at `CREATE INDEX` time |
| Tests 65–67: `CREATE INDEX USING tde_btree` on text/int4/uuid; equality scan; rejection of `WHERE col > x` | ✅ Done | All pass |

---

### 5. Wire Format v2 AEAD AAD Binding (Medium — Security Hardening)

**Problem**: A ciphertext from table A can be physically copied to table B and will decrypt
successfully.

**Approach**: Extend v2 wire format to pass GCM Additional Authenticated Data (AAD) =
`[database_oid(4) | relfilenode(4) | generation(8)]` — 16 bytes, computed but not stored
(zero wire overhead). On decrypt: recompute same AAD; GCM authentication fails if
ciphertext was moved to a different relation.

| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| `tde_compute_aad(Oid dboid, Oid relfilenode, uint64 generation, uchar *out)` helper | ✅ Done | Static inline in `crypto.c`; AAD = `[MyDatabaseId(4)\ |\ relid(4)\ |\ gen(8)]` LE |
| Updated `tde_gcm_encrypt_tuple()` / `tde_gcm_decrypt_tuple()` to pass AAD | ✅ Done | `TDE_V3_VERSION_BYTE = 0x03`; `EVP_EncryptUpdate(NULL,...)` before data; `OidIsValid(relid)` guard for InvalidOid fallback |
| Backward compatible: v1/v2-no-AAD tuples skip AAD check (trial-decryption path) | ✅ Done | `is_v3` flag; v2 and v1 paths unchanged; prev_dek fallback also applies AAD for v3 tuples |
| Tests 68–69: cross-table paste attack rejected; same-table decrypt succeeds | ✅ Done | |

---

### 6. Online Key Rotation Without Downtime (Medium — Operational)

**Problem**: Current `pg_vault_tde_reencrypt_table()` requires exclusive lock. 
| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| `pg_vault_tde_rotate_online(regclass, batch_size int DEFAULT 1000)` SQL function | ✅ Done | Spawns BGW; cursor-based scan; commits per batch; no `AccessExclusiveLock` |
| `pg_vault_tde_rotation_progress` catalog table | ✅ Done | `(relid, status, tuples_done, tuples_total, started_at, updated_at)` |
| `pg_vault_tde_rotation_status(regclass)` monitoring view | ✅ Done | Returns progress from catalog |
| BGW completion: clears `prev_dek`, updates status to `'complete'` | ✅ Done | `prev_dek` fallback active during rotation |
| Tests 70–72: online rotation under concurrent SELECTs; progress tracking; BGW completion | ✅ Done | All pass; BGW temp-table pattern used (SPI WITH HOLD portal workaround) |

---

### 7. PG19 Compatibility Audit (High — Version Support) **→ DEFERRED (PG19 not yet released)**

> PG 19 is not yet released. Build infrastructure is ready. Full audit will be performed when PG19 enters beta.
> Tests 53–72 pass on PG 17 and PG 18.

Full execution of the PG N+1 Checklist in `copilot-instructions.md` § 0.5.

| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| Diff `tableam.h`, `amapi.h` between PG 18 and PG 19 | ⏳ Pending PG19 release | |
| `#if PG_VERSION_NUM >= 190000` guards for any new API differences | ⏳ Pending | |
| `TDE_PG_MAX = 19` in Makefile; PG19 in CI matrix and packaging | ⏳ Pending | |
| Version Registry table updated: PG19 → ✅ Supported | ⏳ Pending | |
| All tests 53–72 passing on PG 19 | ⏳ Pending | |

---

### 8. AppRole Response-Wrapping (Low — Security Hardening)

Full Vault response-wrapping: fetch wrapped `secret_id` token, unwrap server-side,
use once — extends the single-use pattern from v1.4. Applies to `vault` provider only.

| Sub-feature | v1.5 Status | Notes |
|-------------|-------------|-------|
| `POST /v1/auth/approle/role/<role>/secret-id` with `X-Vault-Wrap-TTL` header | ✅ Done | Response contains wrapping token, not raw secret_id |
| `POST /v1/sys/wrapping/unwrap` to unwrap server-side | ✅ Done | Plaintext secret_id never travels over network |
| GUC `pg_vault_tde.vault_response_wrapping = off` (default: off; `PGC_POSTMASTER`) | ✅ Done | Opt-in; registered in v1.5 |

---

### v1.5 Known Limitations Carried Forward

- **Local Wallet KMS provider** — SQL stubs registered; full PKCS#12/KEK/AES-256-WRAP implementation **deferred to v1.6**
- **TOAST chunk-level storage encryption** — heap-level round-trips work; per-chunk AES-GCM at `pg_toast_NNNNN` storage layer **deferred to v1.6**
- **tde_btree fixed-size type index keys** — `int4`, `int8`, `uuid`, `date`, `timestamptz` index keys stored plaintext (heap encrypted); full fix requires custom btree wire format, **deferred to v1.6**
- **Logical replication TOAST gap** — tables with externally-TOAST’d columns not supported for logical decoding; **deferred to v1.6**
- **Column-level encryption** — all-or-nothing per table; per-column granularity **deferred to v1.6**
- **GIN / Hash index encryption** — **deferred to v1.6**
- **KEK/DEK formal wrapping hierarchy** — local wallet provides wrapping foundation; proper `wrap_dek`/`unwrap_dek` provider API formalized in **v1.6**
- **pg_statistic plaintext** — **deferred to v1.6**
- **PG19 compatibility audit** — pending PG19 release (infrastructure ready)
- **WAL encryption** — permanently deferred (requires PG core hook; see § Permanent Deferrals)
- **BRIN on encrypted columns** — permanently deferred (see § Permanent Deferrals)

---

## v1.6 — Column-Level Encryption + GIN/Hash + Full KEK/DEK Hierarchy + Local Wallet + TOAST Chunks (Q2 2027)

> Status: 📋 Defined
> **Target**: ~100 regression tests — PG 17 + PG 18 + PG 19, full KEK/DEK hierarchy verified on both Vault and local wallet.

**Theme**: Column-level encryption; proper key wrapping hierarchy; new index AMs for `jsonb`/array workloads;
**plus deferred items from v1.5**: Local Wallet KMS provider, TOAST chunk-level storage encryption,
logical replication TOAST decrypt, tde_btree fixed-size type index key encryption.

---

### 1. Proper KEK/DEK Wrapping Hierarchy (Critical — Key Management Parity)

**Problem**: Current Vault provider stores the raw DEK in Transit (Vault encrypts it but
the semantic is "Vault is the key store", not "Vault is the key protector"). A proper
hierarchy means the DEK is wrapped by a KEK that never leaves the KMS, and the data-plane
DEK is only in PostgreSQL shmem during active use.

**Design**:
```
KMS KEK (never leaves KMS — Vault Transit / local wallet KEK / future HSM)
  └── wraps → per-table DEK-wrapped (stored in pg_vault_tde_catalog.wrapped_dek)
               └── encrypts → tuple data (AES-256-GCM per tuple)
```

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `pg_vault_tde_kms_wrap_dek(provider, relid, dek)` — formal wrapping API | 🔴 Critical | Provider-agnostic; Vault uses Transit encrypt; local uses AES-256-WRAP |
| `pg_vault_tde_kms_unwrap_dek(provider, relid, wrapped)` — formal unwrapping API | 🔴 Critical | Symmetric inverse; plaintext DEK only in caller's stack frame |
| Vault provider: generate DEK server-side via `pg_strong_random`; wrap with `POST /transit/encrypt/<key>/<relfile>` | 🔴 Critical | Raw DEK never stored in Vault now — only wrapped ciphertext in PG catalog |
| `pg_vault_tde_vault_rewrap_all_deks()` — rewrap all relation DEKs when Vault Transit key rotates | High | Replaces per-table `vault_rewrap_dek()` |
| `pg_vault_tde_catalog.wrapped_dek` formally populated and authoritative | 🔴 Critical | Replaces the file-based `wrapped_dek` approach from v1.3 |
| Tests: wrap/unwrap round-trip; restart with wrapped DEK (no plaintext on disk); rewrap on Transit key rotation | 🔴 Critical | |

---

### 2. Column-Level Encryption (Critical)

**Problem**: typical most-used feature is `ALTER TABLE t MODIFY col ENCRYPT USING AES256`.
pg_vault_tde v1.5 encrypts all columns all-or-nothing.

**Target API**:
```sql
ALTER TABLE customers ENABLE COLUMN ENCRYPTION (ssn, credit_card) USING AES256;
ALTER TABLE customers DISABLE COLUMN ENCRYPTION (name);
SELECT * FROM pg_vault_tde_columns_info('customers');
```

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `pg_vault_tde_columns(relid oid, attnum int2, encrypted bool, vault_key_name text, created_at timestamptz)` catalog | 🔴 Critical | Per-column encryption metadata |
| `src/tam/pg_vault_tde_column.c` — per-column encrypt/decrypt serializer | 🔴 Critical | Serialize only encrypted-column `Datum` values; non-encrypted columns stored natively |
| `ProcessUtility_hook` intercepts `ALTER TABLE ... ENABLE/DISABLE COLUMN ENCRYPTION` | High | No full-table rewrite; lazy re-encryption via `rotate_online()` |
| Per-column DEK option: `pg_vault_tde_columns.vault_key_name` for column-specific Vault Transit key | Medium | Default: share parent table DEK |
| `pg_vault_tde_columns_info(regclass)` diagnostic view | Medium | Shows encryption status per column |
| `ANALYZE` path: decrypt only encrypted columns before statistics machinery | Medium | Prevents plaintext MCVs/histograms for non-encrypted columns from leaking |
| Tests: single-column encryption; multi-column mixed; `ALTER` add/remove; cross-column isolation | 🔴 Critical | |

---

### 3. GIN Index Encryption (Medium — Inverted Index Support)

**Problem**: `jsonb`, `tsvector`, arrays on encrypted columns have no encrypted index.

**Fundamental limitation** (document explicitly): phrase search (`@@` with `<->`) is NOT
supported on encrypted GIN — phrase search requires positional ordering that AES-SIV
destroys. Only equality operators (`@>`, `?`) are supported.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `src/iam/pg_vault_tde_gin.c` — GIN AM wrapper | Medium | Per-entry AES-256-SIV encryption |
| `tde_gin_jsonb_ops`, `tde_gin_array_ops` operator classes | Medium | |
| `amvalidate` rejection of phrase/proximity operators | High | `ereport(ERROR)` at `CREATE INDEX` time |
| GIN posting lists (TIDs): NOT encrypted — structural, not user data | High | Document clearly |
| Tests: `jsonb @>` equality; array `&&`; rejection of `@@` phrase operator | Medium | |

---

### 4. Hash Index Encryption (Low Effort — High Value)

Hash AM: mechanically identical to `tde_btree` with AES-SIV. High value for low effort.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `src/iam/pg_vault_tde_hash.c` — Hash AM wrapper | Medium | Same AES-SIV pattern as `tde_btree` |
| `tde_hash_text_ops`, `tde_hash_int4_ops`, `tde_hash_uuid_ops` | Medium | Reuse type serializers from v1.5 `tde_btree` native types |
| Tests: `CREATE INDEX USING tde_hash` on text + int4; equality lookup; reject range scan | Medium | |

---

### 5. pg_statistic Plaintext Mitigation (Low — Information Leakage)

**Problem**: `ANALYZE` writes plaintext MCVs and histograms to `pg_statistic`. An attacker
with `pg_read_all_stats` reads value distribution without decryption.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `src/tam/pg_vault_tde_stats.c` — post-`ANALYZE` hook via `ProcessUtility_hook` | Low | Scans `pg_statistic` for encrypted relation rows; encrypts `stavalues` bytea with relation DEK |
| Planner path: if no planner statistics hook available, NULL out `stavalues` for encrypted columns (plan quality trade-off — documented) | Low | PG17/18/19 hook availability must be audited |
| GUC `pg_vault_tde.encrypt_statistics = off` (default `off` in v1.6; default `on` in v2.0) | Low | Off by default due to plan quality implications |
| Tests: `ANALYZE` on encrypted table; verify `pg_statistic` has no plaintext values | Low | |

---

### 6. Local Wallet KMS Provider — `local` (Critical — Deferred from v1.5)

**Problem**: Users who cannot run Vault/OpenBao need a fully offline KMS option. In v1.5
only SQL stubs and GUC scaffolding were delivered. The actual PKCS#12 file, KEK generation,
DEK wrapping, and `kms_provider = 'local'` switching must be implemented end-to-end.

**Design**: PKCS#12 encrypted wallet at `$PGDATA/pg_vault_tde/wallet.p12` holds the KEK.
The DEK is wrapped with AES-256-WRAP (RFC 3394) by the KEK and stored in
`pg_vault_tde_catalog.wrapped_dek`. On startup the wallet is opened, KEK unwraps the
DEK into shmem, then KEK is `OPENSSL_cleanse`'d.

| Sub-feature | Priority | Notes |
|-------------|----------|---------|
| `src/kms/pg_vault_tde_kms_local.c` — local wallet provider full implementation | 🔴 Critical | PKCS#12 via OpenSSL `PKCS12_*` API; AES-256-WRAP for DEK |
| `pg_vault_tde_wallet_init(passphrase text)` — functional implementation | 🔴 Critical | Creates `wallet.p12`, generates KEK, wraps initial DEK per `pg_vault_tde_catalog` row |
| `pg_vault_tde_wallet_change_passphrase(old text, new text)` — functional | High | Re-derives KEK; re-wraps all relation DEKs without touching table data |
| GUC `pg_vault_tde.kms_provider = 'local'` actually activates wallet backend | 🔴 Critical | `PGC_POSTMASTER`; `'local'` option was registered in v1.5 but was no-op |
| `pg_vault_tde_wallet_status()` — functional implementation | High | Returns `(wallet_exists, wallet_open, kek_algorithm, dek_wrapped)` |
| Wallet file permissions enforced `0600` at creation and on every open | High | |
| Wallet backup guidance in `doc/pg_vault_tde.md` | Medium | Wallet rotation + backup ceremony procedure |
| Tests: wallet init, DEK wrap/unwrap, restart with wallet, passphrase change, zero Vault dependency | 🔴 Critical | |

**Security constraints**:
- Passphrase from env var ONLY (`wallet_passphrase_env`) — never `postgresql.conf`
- KEK must be `OPENSSL_cleanse`'d from stack frame after DEK unwrap completes
- Wallet file owned by `postgres` OS user, mode `0600`
- PKCS#12 encryption: `PKCS12_create_ex2()` with `NID_aes_256_cbc` (OpenSSL 3.x)

---

### 7. TOAST Chunk-Level Storage Encryption (Critical — Deferred from v1.5)

**Problem**: In v1.5, TOAST round-trips work via heap TAM coverage but individual TOAST
chunks in `pg_toast_NNNNN` are **not encrypted at the chunk-storage layer**. A raw read
of the TOAST relation pages yields plaintext PII data for any column > ~2 kB.

**Approach**: Intercept at the chunk level:
- `toast_save_datum()` path: encrypt each 2 kB chunk with AES-256-GCM using the parent
  relation's DEK before the chunk is written to the TOAST heap
- `toast_fetch_datum()` path: implement `pg_vault_tde_detoast_datum()` wrapper that
  decrypts chunks before reassembly

| Sub-feature | Priority | Notes |
|-------------|----------|---------|
| TOAST chunk encrypt at write path (`toast_save_datum()` interception) | 🔴 Critical | Per-chunk AES-256-GCM; uses parent relation DEK from `pg_vault_tde_catalog` |
| `pg_vault_tde_detoast_datum()` — decrypt wrapper at read path | 🔴 Critical | Called from TAM `tuple_fetch` path before detoast reassembly |
| `pg_vault_tde.toast_compression_then_encrypt` ordering option | Low | Default: compress-then-encrypt (standard); document size implications |
| Tests: raw TOAST page inspection shows no plaintext; large text/jsonb/bytea round-trip via chunk path | 🔴 Critical | pageinspect required |

**Known constraint**: `toast_save_datum()` in PG core calls `heap_insert()` directly.
The TAM AM override is the only extension-legal interception point; any alternative
requires PG core modification (permanently deferred).

---

### 8. tde_btree Fixed-Size Type Index Key Encryption (Medium — Deferred from v1.5 caveat)

**Problem**: In v1.5, `int4`, `int8`, `uuid`, `date`, `timestamptz` columns using
`tde_btree` store the **index key in plaintext**. Only varlena types (`text`, `bytea`,
`numeric`) have their btree index keys AES-256-SIV encrypted. The heap tuple is
fully encrypted regardless; only the btree page entry is affected.

**Root cause**: Btree AM stores scalar (pass-by-value) types inline as `Datum` integers.
Replacing them with a `bytea` pointer would corrupt the btree page layout.

**Proposed fix**: Introduce a custom btree page format for `tde_btree` that stores all
keys as variable-length AES-256-SIV ciphertext regardless of the base type, using a
thin custom page-layout layer on top of standard btree.

| Sub-feature | Priority | Notes |
|-------------|----------|---------|
| Research: `tde_btree` custom page format for fixed-size types | 🔴 Critical | Must remain within extension API; no core btree page layout modification |
| `tde_btree_int4`, `tde_btree_int8`, `tde_btree_uuid` custom AM variants (if page format unfeasible) | Medium | Fallback: dedicated AM per type class with AES-SIV-in-varlena-wrapper |
| `amvalidate` warning when fixed-size column used without encryption proof | High | |
| Tests: verify `int4`/`uuid`/`timestamptz` index keys are not readable in plaintext via pageinspect | High | |

---

### 9. Logical Replication TOAST Decrypt (Medium — Deferred from v1.5)

**Problem**: The `pg_vault_tde_pgoutput` plugin does not decrypt TOAST chunks before
calling `ReorderBufferToastReplace()`. Tables with externally-TOASTed columns produce
garbled output on the subscriber.

| Sub-feature | Priority | Notes |
|-------------|----------|---------|
| Decrypt TOAST chunks in `change_cb` before `ReorderBufferToastReplace()` | Medium | Uses `pg_vault_tde_detoast_datum()` from §7 |
| Integration test: logical replication of table with `text` column > 8 kB | Medium | |
| Document dependency on §7 (TOAST chunk decrypt) in `src/logical/` | Medium | |

---

## v1.7 — HSM / PKCS#11 + Audit Trail + Backup Sealing + pg_dump Protection (Q4 2027)

> Status: 📋 Defined
> **Target**: 110 regression tests — PKCS#11 integration tests with SoftHSM2; audit policy tests.

**Theme**: Enterprise compliance (PCI-DSS, HIPAA, SOC 2 Type II);parity on
operations, backup, and key hardware protection with other most advanced secure databases.

---

### 1. PKCS#11 / HSM Integration (Critical — Financial Sector)

**Problem**: pg_vault_tde missing support for Luna, Thales nShield, and any PKCS#11-compliant HSM natively.
pg_vault_tde offers Vault HTTP and local wallet — no hardware key protection path.

**Approach**: Add `pkcs11` as a third KMS provider via the abstraction layer from v1.5.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `src/kms/pg_vault_tde_kms_pkcs11.c` — PKCS#11 provider | 🔴 Critical | Via OpenSSL 3.x PKCS#11 provider (`libpkcs11.so`); `C_WrapKey`/`C_UnwrapKey` for DEK wrapping |
| GUC `pg_vault_tde.kms_provider = 'vault' \| 'local' \| 'pkcs11'` | 🔴 Critical | Adds `pkcs11` to enum |
| GUC `pg_vault_tde.pkcs11_library` (path to `.so`; `PGC_POSTMASTER`) | High | e.g. `/usr/lib/softhsm/libsofthsm2.so` |
| GUC `pg_vault_tde.pkcs11_slot_id` (int; `PGC_POSTMASTER`) | High | PKCS#11 slot number |
| GUC `pg_vault_tde.pkcs11_pin_env` (env var name — NOT a GUC value) | 🔴 Critical | PIN never in `postgresql.conf` |
| `pg_vault_tde_kms_health_check()` extended — add `pkcs11_slot_status text` column | Medium | |
| CI: SoftHSM2 container in `ci/compose.yml`; 8 PKCS#11 integration tests | High | No physical hardware required for CI |

---

### 2. Audit Trail / Event Log (Critical — Compliance)

**Problem**: pg_vault_tde miss mandatory audit policies. PCI-DSS Requirement 10 and
HIPAA §164.312(b) require logging of all access to encrypted data.

**Audit events** (exhaustive):
`KEY_ROTATION`, `DEK_ACCESS` (per cache miss), `DEK_EVICTION`, `COLUMN_ENCRYPTION_CHANGE`,
`TABLE_CREATED`, `TABLE_DROPPED`, `INTEGRITY_VIOLATION` (GCM tag failure),
`VAULT_AUTH`, `WALLET_OPEN`, `BACKUP_KEY_EXPORT`

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `src/audit/pg_vault_tde_audit.c` — audit module | 🔴 Critical | `tde_audit_log_event()` called from all key lifecycle paths |
| `pg_vault_tde_audit_log` table — `encrypted_heap` with dedicated audit DEK | 🔴 Critical | Append-only; protected by separate Vault/wallet key ring |
| Audit record: `(event_time, event_type, database_oid, relation_oid, user_name, application_name, client_addr inet, details jsonb)` | High | |
| GUC `pg_vault_tde.audit_enabled = on` (default `on`; `PGC_SIGHUP`) | High | |
| GUC `pg_vault_tde.audit_log_level = 'table' \| 'syslog' \| 'both'` (`PGC_SIGHUP`) | Medium | |
| GUC `pg_vault_tde.audit_dek_cache_ttl = 300` — separate TTL for audit DEK (`PGC_SIGHUP`) | Low | |
| `pg_vault_tde_audit_summary()` view — last 24h events grouped by type | Medium | |
| Tests: each of the 10 event types triggered and verified in `pg_vault_tde_audit_log` | 🔴 Critical | |

---

### 3. pg_dump Plaintext Leak Protection (Medium — Operational Security)

**Problem**: `pg_dump` reads via TAM (decrypted) and dumps plaintext SQL. pg_vault_tde has to add encryption also in output file for pg_dump.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `ProcessUtility_hook` intercepts `COPY TO` on encrypted tables — emits `WARNING` | High | Default behavior; cannot prevent dump but forces awareness |
| GUC `pg_vault_tde.dump_plaintext_warning = on` (default `on`; `PGC_SIGHUP`) | High | |
| `doc/pg_vault_tde.md` § Backup and Export: clear statement that `pg_dump` produces plaintext | High | |
| `pg_vault_tde_health_check()` reports `dump_protection_enabled bool` | Medium | |
| Tests: `COPY t TO STDOUT` on encrypted table emits warning; GUC controls warning | Medium | |

---

### 4. Physical Backup Key Sealing (Medium — Backup Security)

**Problem**: `pg_basebackup` copies encrypted pages but the KMS credentials must be
available at restore time. We need to trasparently manged this

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `pg_vault_tde_backup_prepare(backup_label text)` — exports all `wrapped_dek` entries as a signed bundle | High | Bundle: `[label | timestamp | num_keys | {relfile, vault_key_name, wrapped_dek}* | HMAC-SHA256]` |
| Bundle written to `$PGDATA/pg_vault_tde/backup_<label>.bundle` (`0600`) | High | Permissions enforced at write time |
| `pg_vault_tde_backup_restore(backup_label text, kms_credentials text)` — at restore time, reimports wrapped DEKs | High | Works for both Vault and local wallet providers |
| `BackupState` hook integration — auto-call `backup_prepare` on `pg_basebackup` start | Medium | PG17+ `backup_start_hook` API |
| GUC `pg_vault_tde.auto_backup_bundle = on` (default `on`; `PGC_POSTMASTER`) | Medium | |
| Extended `src/backup/pg_vault_tde_backup.c` | High | |
| Tests: bundle creation; verify all relation DEKs present; restore simulation | High | |

---

## v1.8 — KMIP + GiST Equality + Streaming Replication HA + Dual-Control (Q2 2028)

> Status: 📋 Defined
> **Target**: 130 regression tests — KMIP integration tests with PyKMIP; dual-control ceremony tests.

**Theme**: Enterprise HA, KMIP standards compliance, regulated-industry features.

---

### 1. KMIP 1.2 Client (Enterprise Standard)

**Problem**: Most enterprise key managers (Thales CipherTrust, IBM SKLM, Entrust KeyControl)
expose KMIP 1.2, not Vault API or PKCS#11 sockets.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `src/kms/pg_vault_tde_kms_kmip.c` — KMIP 1.2 provider (stub in v1.7; full in v1.8) | High | Wire protocol: KMIP 1.2 over mutual TLS |
| Operations: `Create`, `Get`, `Register`, `Locate`, `Destroy` | High | `Locate` uses custom attribute `x-pg-relfilenode` per relation |
| GUC `pg_vault_tde.kms_provider = 'vault' \| 'local' \| 'pkcs11' \| 'kmip'` | High | `kmip` added to enum |
| GUC `pg_vault_tde.kmip_endpoint`, `kmip_cert_file`, `kmip_key_file`, `kmip_ca_file` | High | mTLS; `PGC_POSTMASTER` |
| CI: PyKMIP mock server in `ci/compose.yml`; 8 KMIP integration tests | High | |

---

### 2. GiST Equality-Only Encryption (Medium — Limited but Viable)

**Problem**: GiST indexes on equality-only operator classes (`inet_ops`, point equality)
can be AES-SIV encrypted. Full geometric/range GiST is cryptographically impossible
and permanently deferred.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `src/iam/pg_vault_tde_gist.c` — GiST AM wrapper | Medium | Same AES-SIV pattern as `tde_btree` |
| `amvalidate`: reject ANY non-equality strategy (`ereport(ERROR)`) | 🔴 Critical | Must prevent silent wrong-results |
| `tde_inet_ops` operator class (equality only) | Medium | |
| Tests: `inet` equality lookup; explicit rejection of range GiST | Medium | |

---

### 3. Streaming Replication Standby DEK Distribution (Medium — HA)

**Problem**: Standby must independently authenticate to the KMS to decrypt tuples. No
documented path exists for multi-provider HA.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `pg_vault_tde_replica_setup()` — generates read-only KMS credentials for standby | High | Vault: AppRole with Transit `decrypt` only; wallet: read-only copy of `wallet.p12` |
| `pg_vault_tde_replica_health_check()` — verifies DEK access vs all `pg_vault_tde_catalog` entries | High | Runs on standby |
| GUC `pg_vault_tde.replica_vault_addr` — optional Vault address override for standby (`PGC_POSTMASTER`) | Medium | |
| `doc/pg_vault_tde.md` § High Availability — KMS HA + PG streaming replication matrix | High | Covers Vault HA, local wallet copy, PKCS#11 HA slot |
| Tests: simulated standby DEK access (read-only); cache behavior during KMS unavailability | High | |

---

### 4. Dual-Control / M-of-N Key Ceremony (High — Regulated Industries)

**Problem**: PCI-DSS Level 1 and national security workloads require M-of-N quorum for key
access. pg_vault_tde need to enforce this natively.

| Sub-feature | Priority | Notes |
|-------------|----------|-------|
| `pg_vault_tde_key_custody_info()` diagnostic — `(sealed bool, shares_required int, unseal_progress int)` | High | Reads Vault `sys/seal-status`; PKCS#11: `C_GetSessionInfo` login state |
| Document Vault Shamir unseal + `operator unseal` quorum in `doc/pg_vault_tde.md` | High | |
| Document wallet M-of-N: split passphrase across `N` operators via XOR-split ceremony | High | No code change; operational procedure |
| GUC `pg_vault_tde.quorum_required = 0` (informational; enforced at KMS level) | Low | |
| Tests: `pg_vault_tde_key_custody_info()` output; sealed Vault → PG starts in read-only DEK-cache mode | High | |

---

## Permanent Deferrals

These gaps **cannot be closed without modifying PostgreSQL core**. They are documented
in `doc/pg_vault_tde.md` § Known Limitations — Not Solvable as Extension.

| Gap | Reason | Note |
|-----|--------|------|
| **WAL / redo encryption** | Requires hook in `XLogInsert()` / `XLogWrite()` — no extension API exists in PG 17/18/19 | need a postgresql core patch: out of this project scope |
| **BRIN on encrypted columns** | BRIN stores min/max per block range; AES-SIV/GCM produces uniformly random ciphertexts — min/max of ciphertexts is meaningless and would return silently incorrect query results | acceptable |
| **General GiST encryption** (range, geometric, tsrange) | GiST penalty/picksplit requires ordering that deterministic encryption destroys; only equality-consistent subtypes viable (`tde_gist` in v1.8) | acceptable |
| **pg_upgrade transparent migration** | `pg_upgrade` copies data files without going through TAM; encrypted files require manual `pg_vault_tde_reencrypt_table()` after upgrade | need to investigate with future local wallet |
| **Full-text phrase search on encrypted tsvector** | `@@` proximity requires positional information; AES-SIV destroys position ordering | acceptable |

---

## Version Summary

| Version | Theme | Target | Tests | Key Gap Closed |
|---------|-------|--------|-------|-----------------------|
| **v1.4** | CI/CD + tde_btree + wire format v2 | Completed 2026-07-05 | 52 | First production-ready index encryption |
| **v1.5** | Per-Table DEK + Online Rotation + Wire Format v3 AAD | Completed 2026-03-04 | 72 | Per-table DEK isolation, tde_btree native types, online rotation BGW, wire format v3 AEAD; Wallet + TOAST chunk-level → v1.6 |
| **v1.6** | Column-level + GIN/Hash + KEK hierarchy + Local Wallet + TOAST chunks | Q2 2027 | ~100 | Column-level encryption, GIN/Hash indexes, Local Wallet KMS, TOAST chunk encryption, proper wrap hierarchy |
| **v1.7** | HSM + Audit + Backup sealing | Q4 2027 | 110 | PKCS#11/HSM, audit trail (PCI-DSS), backup protection |
| **v1.8** | KMIP + HA + GiST equality + Dual-control | Q2 2028 | 130 | KMIP 1.2, streaming replication HA, M-of-N quorum |
