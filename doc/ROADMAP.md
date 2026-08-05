# pg_vault_tde Roadmap

> Last updated: 2026-06-29 — **v1.7 current**. 109 regression tests (52 v1.4 + 20 v1.5 + 37 v1.6) carried forward, plus the `tap/12_logical_repl_toast.t` end-to-end logical replication test. Key v1.7 changes: all KMS GUCs promoted to PGC_SUSET (per-database KMS via `ALTER DATABASE SET`); `pg_restore_tde` decrypt-and-pipe loop completed; logical replication of `encrypted_heap` TOAST columns via a custom WAL resource manager (`pg_vault_tde.toast_custom_rmgr`); documentation updated throughout.

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

> Completed: 2026-06-03, patched 2026-05-08 — **109 regression tests** (52 v1.4 + 20 v1.5 + 37 v1.6) — PG 17 + PG 18, zero compiler warnings.

Local Wallet KMS provider (`src/kms/pg_vault_tde_kms_local.c`) — full PKCS#12 / AES-256-WRAP
implementation, PBKDF2-SHA256 (600,000 iterations, NIST SP 800-132), `0600` wallet file
permissions. Flexible passphrase ingestion via GUCs (env var, file, shell command, dev-mode
convenience; priority `command > env > file > dev_mode`) plus SQL `wallet_unlock`/`wallet_lock`
for interactive control without a restart. `pg_vault_tde_wallet_status()` 6-column SRF.
KEK rotation and passphrase change re-wrap all DEKs atomically via SPI. Zero-downtime
`pg_vault_tde_migrate_vault_to_wallet()`. TOAST chunk-level storage encryption shipped here
as the foundation for v1.7's logical-replication work. Patch fixed a write-path error-handling
gap (`PG_TRY` widened to cover the full write pipeline in all four write callbacks) and added
the `RELKIND_TOASTVALUE` read-path bypass so real TOAST chunks round-trip correctly. Tests 73–109.

> The original wallet export/import bundle functions (`pg_vault_tde_wallet_export_bundle`/
> `_import_bundle`) shipped in v1.6 were removed in v1.7, superseded by
> `pg_vault_tde_seal_keys()`/`pg_vault_tde_unseal_keys()`.

---

## v1.7 — TOAST Chunks + KEK Hierarchy + HSM + Audit

> Status: ✅ Completed
> **Target**: ~100 regression tests — PG 17 + PG 18 + PG 19.

**Theme**: Close the TOAST data-leak gap, formalize the KEK/DEK wrap hierarchy across
all providers, add PKCS#11/HSM support, audit trail for compliance (PCI-DSS, HIPAA).

### 1. TOAST Chunk-Level Storage Encryption (foundation — shipped in v1.6)

Per-chunk AES-256-GCM at the `pg_toast_NNNNN` storage layer using the parent
relation DEK (delivered in v1.6; listed here as the foundation the v1.7 logical
replication work in §4 builds on). Raw TOAST pages no longer contain plaintext.

### 2. Proper KEK/DEK Wrapping Hierarchy (Critical)

Provider-agnostic `pg_vault_tde_kms_wrap_dek()`/`unwrap_dek()` API. Vault Transit acts
as key protector (not key store) — raw DEK never sent to Vault, only wrapped ciphertext.
`pg_vault_tde_catalog.wrapped_dek` authoritative for all providers.

### 3. tde_btree Fixed-Size Type Encryption — ✅ Completed in v1.7

Custom btree key serialisation layer for `int4`/`int8`/`uuid`/`date`/`timestamptz`.
All operator classes now store encrypted index keys. Index-only scans are disabled
by design to prevent returning raw AES-256-SIV ciphertext to clients.

### 4. Logical Replication of TOAST Columns (Medium) — COMPLETED ✅

Custom WAL resource manager (`pg_vault_tde.toast_custom_rmgr`, PGC_POSTMASTER,
default off): `tde_toast_wal_insert()` logs encrypted TOAST chunks under
`TDE_RMGR_ID` so the logical decoder routes them away from the reorder buffer's
`toast_hash`; `rm_decode` captures them per transaction and `tde_toast_stitch()`
reconstructs the plaintext value into the decrypted main tuple before `pgoutput`
serializes it. UPDATE/DELETE require `REPLICA IDENTITY FULL` + a primary key
(`DEFAULT` / PK-less unsupported — the replica identity would be read from
ciphertext). Covered end-to-end by `tap/12_logical_repl_toast.t`.
See doc/pg_vault_tde.md → "Logical Decoding and Replication".

### 5. PKCS#11 / HSM Integration (Critical) — COMPLETED ✅

`src/kms/pg_vault_tde_kms_pkcs11.c` — direct Cryptoki: the vendor module is
dlopen()ed and DEKs are wrapped with `C_WrapKey`/`C_UnwrapKey`
(`CKM_AES_KEY_WRAP`, AES-256 KEK with `CKA_EXTRACTABLE=FALSE`). The
originally-planned OpenSSL 3.x pkcs11-provider route was evaluated and
discarded: symmetric key wrap with an opaque token key is not expressible
through EVP (would force an RSA KEK), and the `pkcs11-provider` package is
missing/outdated on the DEB targets. OASIS v3.2 headers vendored under
`src/include/pkcs11/`. KEK provisioning via `pg_vault_tde_pkcs11_keygen()`;
rotation via the standard `pg_vault_tde_rotate_kek()`. Every KEK generation
is an immutable token object labelled `<pkcs11_key_label>.v<N>` (N never
reused, never renamed or destroyed); "current" is simply the highest N on
the token, and every `wrapped_dek` blob is prefixed with the version tag
of the KEK that produced it, so unwrap always finds the right key
regardless of what is "current" — including across a crash mid-rotation.
GUCs: `pkcs11_library`, `pkcs11_token_label`, `pkcs11_slot_id`,
`pkcs11_pin_env`, `pkcs11_key_label`. CI with SoftHSM2
(`tap/16_pkcs11.t`, 19 assertions, `make ci-pkcs11`). Follow-up: `pg_dump_tde`/
`pg_restore_tde` FRONTEND shim (they currently error out cleanly).

**Cross-backend KEK-rotation propagation**: a shared-memory beacon
(`Pkcs11SharedState`: one `LWLock` + a `uint32 current_kek_version`,
mapped via `pg_vault_tde_kms_pkcs11_shmem_request`/`_shmem_init`, same
dynamic-tranche pattern as the Vault token cache) lets an already-connected
backend pick up a KEK rotation committed by a *different* connection
without reconnecting. The raw `CK_OBJECT_HANDLE` is never shared across
processes (PKCS#11 handles are only meaningful within the session that
resolved them) — only the version number is; each backend re-resolves its
own handle locally via `pkcs11_find_key_by_label()`. Written only from
`pkcs11_commit_kek_rotation()` and the initial keygen (never from
`prepare_kek_rotation`, to avoid leaking an armed-but-uncommitted rotation
cluster-wide); read opportunistically on every wrap/unwrap/rewrap call via
`pkcs11_refresh_kek_if_stale()`, so staleness is bounded by "this backend's
next operation", not wall-clock time.

### 6. Audit Trail / Event Log (Critical) — COMPLETED ✅

`src/audit/pg_vault_tde_audit.c` — 10 event types (`KEY_ROTATION`, `DEK_ACCESS`,
`INTEGRITY_VIOLATION`, `WALLET_OPEN`, etc.). `pg_vault_tde_audit_log` encrypted table.
PCI-DSS Requirement 10 / HIPAA §164.312(b).

### 7. pg_dump Plaintext Leak Protection (Medium) — NOT completed, moved to v1.8

Designed (see `src/backup/pg_vault_tde_backup.c` header comment, "Layer 2 — SQL-LEVEL
GUARD"): `ProcessUtility_hook` would intercept `COPY TO` on encrypted tables and emit a
WARNING, gated by GUC `pg_vault_tde.dump_plaintext_warning`. Neither the hook nor the GUC
exist in code yet — tracked as v1.8 §10 below.

### 8. Physical Backup Key Sealing / `pg_restore_tde` (Medium) — COMPLETED ✅

`pg_restore_tde` standalone binary (`src/backup/pg_restore_tde.c`): reads the
`tde_backup_header`, unwraps the DEK via the active KMS provider
(`tde_backup_header_validate()`), decrypts the AES-256-GCM block stream
(`tde_backup_decrypt_block()` with block_seq as AAD), and pipes plaintext to
`pg_restore -Fc`.

`pg_vault_tde_seal_keys()`/`pg_vault_tde_seal_keys_bytea()`/`pg_vault_tde_unseal_keys()` (`src/kms/pg_vault_tde_seal.c`) — signed bundle of all `wrapped_dek` entries (KEK excluded), for `pg_basebackup`; TAP `tap/14_seal_keys.t`.
`pg_basebackup_tde` (`src/backup/pg_basebackup_tde.c`) — pg_basebackup wrapper: seals every database's keys via `seal_keys_bytea` before the backup and writes one `pg_vault_tde_keys.<datname>.sealed` bundle per database after it succeeds; TAP `tap/15_basebackup_tde.t`.
A core-side `BackupState`/`bbsink` hook was evaluated and discarded: PostgreSQL exposes no extension hook to inject files into the `pg_basebackup` stream, and a custom `bbsink` runs in the walsender without SPI.

---

## v1.8 — KMIP + Column-Level + GIN/Hash/GiST/BRIN + HA + Dual-Control (Q2 2027)

> Status: 📋 Defined
> **Target**: ~130 regression tests.

**Theme**: Enterprise HA, KMIP standards compliance, column-level encryption,
regulated-industry features.

### 1. Column-Level Encryption (High)

`ALTER TABLE ... ENABLE/DISABLE COLUMN ENCRYPTION` DDL. Per-column DEK support.
`pg_vault_tde_columns` catalog. `src/tam/pg_vault_tde_column.c`.

**Feasibility (verified against the current TAM architecture, see
`tam.instructions.md`)**: `encrypted_heap` today encrypts the whole tuple as
one opaque AES-256-GCM blob (`tde_encrypt_heap_tuple`, wire format v4) —
there is no per-Datum boundary. Column-level encryption needs the write
path to operate around `heap_deform_tuple`/`heap_form_tuple` for specific
attributes instead of the raw tuple bytes:
- **Varlena columns** (`text`, `bytea`, `jsonb`, `numeric`, arrays):
  straightforward — store `[IV|ciphertext|GCM-tag]` as the Datum's own
  varlena payload, the same shape already used at the tuple level, just
  scoped to one attribute. No storage-layout change needed.
- **Fixed-size columns** (`int4`, `int8`, `date`, `timestamptz`, ...):
  AES-256-GCM's IV+tag overhead does not fit the type's fixed storage
  width. Either (a) reuse `tde_btree`'s AES-256-SIV scheme — deterministic,
  same output length as input, same security trade-off already accepted
  for index keys (no protection against frequency analysis) — or (b)
  widen physical storage (bigger lift: a pseudo-type or forced
  `bytea`-backed column; likely out of scope for a first cut).
- **Query pushdown**: `WHERE col = ...` on an encrypted column needs the
  same encrypt-then-compare trick `tde_btree` already implements for an
  index to be usable; without a matching index it falls back to sequential
  scan + per-Datum decrypt (same cost model as today's whole-row decrypt,
  just narrower).
- **Two distinct feature shapes to choose between**: (a) column encryption
  as an *additional* layer inside `encrypted_heap` — a specific sensitive
  column (SSN, card number) gets its own DEK/rotation/audit trail
  independent of the table DEK, for defense-in-depth or per-column access
  control; (b) column encryption on an *ordinary* `heap` table, without
  switching the whole table to `encrypted_heap` — a lighter-weight opt-in
  for one or two sensitive columns. (a) reuses most of the existing TAM
  plumbing; (b) needs a new, narrower write/read hook that does not exist
  anywhere in the codebase today.

### 2. GIN Index Encryption (Medium)

`src/iam/pg_vault_tde_gin.c` — per-entry AES-256-SIV. Equality operators only
(`@>`, `?`, `&&`). Phrase search permanently rejected by `amvalidate`.

**Feasibility**: same delegation pattern already proven by `tde_btree` (see
`iam.instructions.md` — `amgettuple`/`amendscan`/`ambulkdelete`/
`amvacuumcleanup` delegate unchanged to the real AM; only the key
boundary is intercepted). GIN's entry tree needs a *consistent* comparator
for its internal structure, not a semantically meaningful order — encrypting
each key extracted by `extractValue`/`extractQuery` with AES-256-SIV before
handing it to GIN's own entry-tree code preserves exactly that: equal
plaintexts still compare equal, and a stable (if arbitrary) ciphertext
byte-order is all GIN's internals require. Lower risk than GiST (below)
precisely because GIN, like btree, has no semantic-distance requirement.

### 3. Hash Index Encryption (Low Effort)

`src/iam/pg_vault_tde_hash.c` — same AES-256-SIV pattern as `tde_btree`;
hash index buckets only need bucket-hash + exact equality, both of which
survive deterministic encryption unchanged. Same low-risk delegation
pattern as GIN above.

### 4. pg_statistic Plaintext Mitigation (Low)

Post-`ANALYZE` hook: NULL out `stavalues` for encrypted columns.
GUC `pg_vault_tde.encrypt_statistics`.

### 5. KMIP 1.2 Client (Enterprise)

`src/kms/pg_vault_tde_kms_kmip.c` — KMIP 1.2 over mutual TLS. CI with PyKMIP.

### 6. GiST Equality-Only Encryption (Medium)

`src/iam/pg_vault_tde_gist.c` — equality-only operator classes. `amvalidate`
rejects range/geometric strategies.

**Feasibility, and why this is harder than GIN/Hash above**: unlike btree/
GIN/Hash, GiST cannot delegate its tree-shaping support functions
(`penalty`, `picksplit`, `union`, `distance`) to the real opclass on
ciphertext — those functions encode actual geometric/semantic distance in
the plaintext domain, which AES-SIV ciphertext has none of by design (that
*is* the point of encryption). A working equality-only GiST needs genuinely
custom, non-delegated support functions that make no attempt at
selectivity (e.g. constant penalty, arbitrary picksplit) and rely entirely
on `consistent` for an exact ciphertext match — functionally correct, but
with materially worse pruning than a real GiST tree, closer in practice to
a linear scan over each visited page. Worth it specifically for types that
have **no other native access method** in PostgreSQL (`point`, `circle`,
`box`, `inet` with non-equality operators unused) — for anything with a
usable `tde_btree` or the GIN path above, prefer those instead.

### 7. Streaming Replication Standby DEK Distribution (Medium)

`pg_vault_tde_replica_setup()` — read-only KMS credentials for standby. HA
documentation for all KMS providers.

### 8. Dual-Control / M-of-N Key Ceremony (High)

`pg_vault_tde_key_custody_info()`. Vault Shamir + PKCS#11 PIN-split documentation.

### 9. BRIN Bloom Equality Encryption (Medium — new candidate, needs a spike)

`src/iam/pg_vault_tde_brin.c`. The Permanent Deferrals table below correctly
rules out `minmax` BRIN opclasses (ciphertext has no meaningful min/max) —
but PostgreSQL's `bloom` BRIN opclasses (core since PG 14,
`src/backend/access/brin/brin_bloom.c`) only need a per-block-range Bloom
filter of value hashes, never an ordering. Since AES-256-SIV is
deterministic (equal plaintext → equal ciphertext, the same property
`tde_btree` already relies on), hashing the raw ciphertext bytes directly
(`hash_any()`) produces exactly the membership test a bloom filter needs —
no type-specific logic required at all, unlike `tde_btree`/GIN/GiST which
need per-type SIV encode/decode. A single generic "encrypted equality"
bloom opclass could work uniformly across every type this project already
supports, giving cheap block-range pruning for equality predicates on
large encrypted tables at a fraction of `tde_btree`'s storage cost.
Needs a short technical spike before committing engineering time: confirm
the BRIN opclass support-function contract (`opcinfo`/`add_value`/
`consistent`/`union`) can be satisfied purely on ciphertext bytes without
ever needing the plaintext inside the index AM.

### 10. pg_dump Plaintext Leak Protection (Medium — carried over from v1.7, never implemented)

`ProcessUtility_hook` intercepts `COPY TO` on encrypted tables — emits WARNING.
GUC `pg_vault_tde.dump_plaintext_warning = on`. Designed in v1.7 (see
`src/backup/pg_vault_tde_backup.c` header comment) but the hook and GUC were
never written; carried forward here as the actual target release.

---

## Permanent Deferrals

These gaps **cannot be closed without modifying PostgreSQL core**.

| Gap | Reason |
|-----|--------|
| **WAL / redo encryption** | Requires hook in `XLogInsert()` / `XLogWrite()` — no extension API |
| **BRIN minmax on encrypted columns** | min/max of AES-SIV ciphertexts is meaningless — no ordering preserved. (Bloom-based BRIN equality pruning is *not* in this category — tracked as a real candidate, see v1.8 §9.) |
| **General GiST** (range, geometric) | Penalty/picksplit requires ordering; AES-SIV destroys it. (Equality-only GiST is *not* in this category — tracked separately, see v1.8 §6.) |
| **pg_upgrade transparent migration** | `pg_upgrade` copies files without TAM; manual `reencrypt_table()` required |
| **Full-text phrase search on encrypted tsvector** | `<->` proximity requires positional ordering |
| **`WITH HOLD` cursor temp file encryption** | The held-cursor tuplestore is written by the executor's storage layer directly, bypassing the TAM — no hook exists anywhere in the `WITH HOLD` cursor lifecycle to intercept it. See README.md § Limitations item 6. |

---

## Version Summary

| Version | Theme | Completed | Tests | Key Features |
|---------|-------|-----------|-------|-----------------------|
| **v1.1** | KMS/Vault + Key Rotation + HW Accel | ✅ 2026 | 41 | Vault Transit, AppRole, prev_dek fallback, OpenSSL 3.x HW dispatch |
| **v1.2** | Logical Decoding | ✅ 2026 | — | `pg_vault_tde_pgoutput` output plugin |
| **v1.3** | Vault KEK + multi_insert + BGW | ✅ 2026 | 48 | Transit KEK wrapping, batch COPY, token renewal BGW, health_check |
| **v1.4** | CI/CD + tde_btree + Wire Format v2 | ✅ 2026-07-05 | 52 | OpenBao 3-node Raft, ambuild/aminsert/amrescan, generation tag |
| **v1.5** | Per-Table DEK + Online Rotation + AAD | ✅ 2026 | 72 | Per-table catalog, native type ops, wire format v3, rotate_online BGW |
| **v1.6** | Local Wallet KMS (production-ready) + write-path / catalog bugfix patch | ✅ 2026-07-20 (patched 2026-05-08) | 109 | Wallet unlock/lock, passphrase flexibility, KEK rotation, export/import, Vault→wallet migration; PG_TRY widening; TOAST relid auto-registration; STORAGE EXTERNAL TAM read bypass; all-read-paths TOAST coverage; forensic helpers; tests 73–109 |
| **v1.7** | Per-database KMS + pg_restore_tde + PGC_SUSET + PKCS#11 + HSM + v1.4 removal | ✅ Completed | 109 | All KMS GUCs PGC_SUSET → per-database KMS via `ALTER DATABASE SET`; `pg_restore_tde` full decrypt-and-pipe restore loop; removed v1.4 global-DEK backward compat (`TdeShmemData`, `rotate_key`, `key_generation`, `clear_prev_dek`, `encrypt_test`, `decrypt_test`); PKCS#11/HSM provider with cross-backend KEK-rotation propagation; documentation overhaul |
| **v1.8** | KMIP + Column-Level + GIN/Hash/GiST/BRIN + HA + Dual-Control | Q2 2027 | ~130 | KMIP 1.2 client, per-column encryption, GIN/Hash/GiST(equality)/BRIN(bloom) index AMs, streaming replication standby DEK distribution, M-of-N key ceremony, pg_dump/COPY TO plaintext-leak WARNING (carried over from v1.7) |
