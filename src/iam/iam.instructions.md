# IAM Module Instructions — @Architect + @SecurityKMS

> **Scope**: `src/iam/pg_vault_tde_iam.c`, `src/include/pg_vault_tde_iam.h`

---

## Module Responsibility

Provides the `tde_btree` index access method with **AES-256-SIV**
deterministic encryption for B-Tree index keys. This enables equality
lookups (`=`, `IN`, `ON CONFLICT`) on encrypted columns without exposing
plaintext key values in the index.

**Shared ownership**:
- @Architect owns: `amhandler`, callback table, AM registration
- @SecurityKMS owns: `tde_iam_encrypt_key()`, `tde_iam_decrypt_key()`, SIV context pool

---

## Algorithm: AES-256-SIV (RFC 5297)

| Property | Value |
|----------|-------|
| Algorithm | AES-256-SIV (deterministic authenticated encryption) |
| Key length | 64 bytes (double-key: two 32-byte AES keys) |
| Equality | Preserved — same plaintext → same ciphertext under same DEK |
| Ordering | **NOT preserved** — the planner never uses `tde_btree` for ranges, `ORDER BY`, `min`/`max`; a forced range is an error |

### Why AES-SIV, not AES-GCM

AES-GCM with random IVs produces different ciphertext for the same plaintext.
B-Tree comparisons would fail. AES-SIV is deterministic: equal plaintexts
produce equal ciphertexts, enabling exact-match index lookups.

### Key Derivation

The 32-byte DEK is expanded to 64 bytes for SIV's double-key requirement:
```c
PKCS5_PBKDF2_HMAC(dek, TDE_DEK_LEN,
                  (unsigned char *)"tde-siv", 7,
                  1,                    /* 1 iteration — not for stretching */
                  EVP_sha256(), 64, siv_key);
```

### OpenSSL 3.x Provider API

```c
EVP_CIPHER *siv_cipher = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
```
Do NOT use the legacy `EVP_aes_256_siv()` — it has no public C symbol in
many OpenSSL 3.x builds.

---

## EVP Context Pool (Per-Backend)

```c
static EVP_CIPHER_CTX *tde_iam_siv_enc_ctx = NULL;
static EVP_CIPHER_CTX *tde_iam_siv_dec_ctx = NULL;
```

Same pool pattern as the GCM layer:
- Create lazily on first use
- Reset with `EVP_CIPHER_CTX_reset()` between calls
- Free in `on_proc_exit(tde_iam_siv_ctx_cleanup)`

---

## Implementation Status (v1.7)

| Hook | Status | Notes |
|------|--------|-------|
| `ambuild` | ✅ Wired | Full index build with encryption; all types (varlena + fixed-size) |
| `aminsert` | ✅ Wired | Per-key encryption on INSERT; all types encrypted |
| `amgettuple` | Delegates to btree | Returns encrypted key; heap fetch required for plaintext |
| `amrescan` | ✅ Wired | Encrypts equality scan keys; a range key is an ERROR (only a forced plan delivers one) |
| `amendscan` | Delegates to btree | Standard btree behavior |
| `ambulkdelete` | Delegates to btree | Standard btree behavior |
| `amvacuumcleanup` | Delegates to btree | Standard btree behavior |
| Index-only scan | ❌ Not supported | By design: would expose raw AES-SIV ciphertext without decryption |

---

## Known Limitations

### Equality only (by design, permanent)

AES-SIV preserves equality and nothing else, so `tde_btree` answers `=`,
`IN (…)` and `= ANY (…)` and nothing more. Enforced at three points, all in
`pg_vault_tde_iam.c` under "PLANNER: EQUALITY ONLY" (PSQLE-173): a
`get_relation_info_hook` removes the index's sort order (`sortopfamily = NULL`;
**not** `reverse_sort` — `btcostestimate()` reads it unconditionally) and drops
`numeric` / nondeterministic-collation indexes from the planner's view;
`pg_vault_tde_amcostestimate()` prices non-equality paths out; `amrescan`
errors on a range key. `amsearcharray = false` lets the executor expand
`IN (…)` into scalar lookups. `amcanorder = false` on the AM is **not** an
option: `PrepareSortSupportFromIndexRel()` rejects it during the
btree-impersonated build. New indexes are checked by `tde_iam_check_new_index()`,
called from `tde_object_access_hook()` at `OAT_POST_CREATE` — the one point every
creation path reaches (`CREATE INDEX`, `EXCLUDE` in `CREATE TABLE`/`ALTER TABLE`,
the rebuild behind `ALTER COLUMN … TYPE`, `pg_restore`) — and refuse `numeric`,
nondeterministic collations and, unless `is_internal` or `allow_plaintext_index`,
the v1.5 plaintext-key classes. Not in the ProcessUtility hook: `UNIQUE` and
`EXCLUDE` enforcement reads the index directly, and the paths that bypass that
hook let duplicates in. Not in `ambuild`: `REINDEX` must keep working. REINDEX
CONCURRENTLY builds a copy that arrives as a non-internal creation, so the
ProcessUtility hook sets `tde_reindex_in_progress` and the check skips it. The
planner hook still drops unservable indexes: ones built before 1.7.2 exist.

### Index-Only Scans (not supported, by design)

PostgreSQL index-only scans return column values directly from the index without
fetching the heap tuple. Since `tde_btree` index pages store AES-256-SIV ciphertexts,
an index-only scan would return raw ciphertext to the client — bypassing the TAM
`decode_slot` decryption path entirely. The `tde_btree` handler prevents the planner
from selecting this path.

---

## Dependency Constraints

- MAY include `pg_vault_tde_crypto.h` (for constants)
- MAY include `pg_vault_tde_kms.h` (to obtain DEK)
- MUST NOT include `pg_vault_tde_tam.h`
- MUST NOT call any TAM functions

---

## PG Version Compatibility Checklist (IAM)

When adding support for PostgreSQL N+1, audit every IAM callback:

1. **Diff `amapi.h`** between PG N and PG N+1
2. Check each callback signature in the `IndexAmRoutine` struct
3. Add `#if PG_VERSION_NUM` guards where needed
4. Verify `EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL)` still works with
   the OpenSSL version shipped by PG N+1's default platform
5. Run `make ci-regress` against PG N+1 (test 17 covers index scan)

### Known Version Differences (IAM)

| Callback | PG 17 | PG 18 | Guard |
|----------|-------|-------|-------|
| *(none so far)* | — | — | — |

**Add rows** here when PG 19+ introduces IAM API changes.
