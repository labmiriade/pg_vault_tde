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
| Ordering | **NOT preserved** — range scans return empty results |

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

## Implementation Status (v1.0)

| Hook | Status | Notes |
|------|--------|-------|
| `ambuild` | ✅ Wired | Full index build with encryption |
| `aminsert` | ✅ Wired | Per-key encryption on INSERT |
| `amgettuple` | Delegates to btree | Decryption needed for query results |
| `amrescan` | Delegates to btree | Standard btree behavior |
| `amendscan` | Delegates to btree | Standard btree behavior |
| `ambulkdelete` | Delegates to btree | Standard btree behavior |
| `amvacuumcleanup` | Delegates to btree | Standard btree behavior |

---

## Known Limitation: Range Scans

`WHERE col > 'x'` on a `tde_btree`-indexed column returns empty results.
AES-SIV does not preserve ordering. This is documented in README.md and
`doc/pg_vault_tde.md`. Users must use sequential scans for range predicates.

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
5. Update the **Version-Specific API Differences** table in
   `copilot-instructions.md` § 0.5
6. Run `make ci-regress` against PG N+1 (test 17 covers index scan)

### Known Version Differences (IAM)

| Callback | PG 17 | PG 18 | Guard |
|----------|-------|-------|-------|
| *(none so far)* | — | — | — |

**Add rows** here when PG 19+ introduces IAM API changes.
