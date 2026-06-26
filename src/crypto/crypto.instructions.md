# Crypto Module Instructions — @SecurityKMS

> **Scope**: `src/crypto/pg_vault_tde_crypto.c`, `src/include/pg_vault_tde_crypto.h`

---

## Module Responsibility

Pure cryptographic transformations. This module MUST NOT perform any
PostgreSQL I/O, catalog lookups, or SPI calls. It receives plaintext bytes
and returns ciphertext bytes (or vice versa), plus authenticates via GCM tags.

---

## Algorithm Requirements

| Operation | Algorithm | OpenSSL API |
|-----------|-----------|-------------|
| Tuple encrypt | AES-256-GCM | `EVP_EncryptInit_ex2` → `EVP_EncryptUpdate` → `EVP_EncryptFinal_ex` |
| Tuple decrypt | AES-256-GCM | `EVP_DecryptInit_ex2` → `EVP_DecryptUpdate` → `EVP_DecryptFinal_ex` |
| IV generation | 12-byte random | `pg_strong_random()` — NEVER `RAND_bytes()` |

### Why NOT `RAND_bytes()`

PostgreSQL processes fork after shared-memory setup. OpenSSL's PRNG state is
not guaranteed fork-safe across all configurations. `pg_strong_random()` reads
directly from `/dev/urandom` or `getrandom(2)`, which is fork-safe.

### Hardware Acceleration

OpenSSL 3.x EVP automatically dispatches to the best available hardware
provider (AES-NI on x86_64, ARM Crypto Extensions on aarch64). Do NOT:
- Hardcode an ENGINE name
- Call `EVP_CIPHER_fetch()` with a provider name
- Use architecture-specific intrinsics directly

---

## Wire Format (IMMUTABLE)

```
[IV (12 bytes)] [CIPHERTEXT (N bytes)] [GCM-TAG (16 bytes)]
```

Constants (defined ONLY in `pg_vault_tde_crypto.h`):
- `TDE_IV_LEN = 12`
- `TDE_TAG_LEN = 16`
- `TDE_GCM_OVERHEAD = 28` (IV + TAG)

`TDE_DEK_LEN = 32` is defined in `pg_vault_tde_kms.h` — do NOT redefine here.

---

## EVP Context Pattern — keyed by (relid, generation)

The GCM contexts are NOT reset per call. Each is cached together with the
`(relid, generation)` it is keyed for, so the AES key schedule is reused across
tuples of the same relation/generation:

```c
typedef struct TdeCipherSlot {
    EVP_CIPHER_CTX *ctx;
    Oid             relid;
    uint64          generation;
} TdeCipherSlot;

static TdeCipherSlot tde_enc = { NULL, InvalidOid, 0 };
static TdeCipherSlot tde_dec = { NULL, InvalidOid, 0 };
```

- **Create** each `ctx` once via `EVP_CIPHER_CTX_new()` (first use, idempotent).
- **Re-key** with `EVP_EncryptInit_ex2(ctx, cipher, dek, NULL, NULL)` ONLY when
  the slot's cached `relid`/`generation` differs from the current op (expensive
  key schedule). The decrypt slot keys on the *stored* generation from the wire
  trailer so `prev_dek` rows during rotation get their own schedule.
- **Per tuple** rearm only the IV: `EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL)`.
- **Free** both in `on_proc_exit(tde_crypto_ctx_cleanup)`; the same function runs
  on any fatal error path, NULL-ing the contexts so the next call re-allocates.
- **Never** reset or free+reallocate per tuple — that throws away the key schedule.

---

## IV Batch Generation

```c
#define TDE_IV_BATCH_SIZE 256
static unsigned char iv_batch[TDE_IV_BATCH_SIZE * TDE_IV_LEN];
static int           iv_batch_pos = TDE_IV_BATCH_SIZE;  /* starts empty */
```

Amortizes one `pg_strong_random()` syscall across 256 tuples.
The `iv_batch` array MUST be `OPENSSL_cleanse`d in the `on_proc_exit` cleanup.

---

## GCM Authentication — MANDATORY

```c
// Decrypt path: ALWAYS check return value
int ret = EVP_DecryptFinal_ex(ctx, out + out_len, &final_len);
if (ret != 1)
    ereport(ERROR,
            (errcode(ERRCODE_DATA_CORRUPTED),
             errmsg("pg_vault_tde: GCM authentication failed — data tampered")));
```

**NEVER** return unauthenticated plaintext under any circumstances.
GCM tag verification failure MUST raise `ERROR`, not `WARNING`.

---

## Memory Security Rules

| Buffer | Cleanse Required? | When |
|--------|-------------------|------|
| DEK copy (stack/heap) | YES — `OPENSSL_cleanse(dek, TDE_DEK_LEN)` | Before `pfree` |
| Ciphertext output | YES — `OPENSSL_cleanse(enc_buf, enc_len)` | After `pfree` not needed (disk threat model) |
| IV batch | YES — `OPENSSL_cleanse(iv_batch, sizeof(iv_batch))` | In `on_proc_exit` cleanup |
| Plaintext intermediate | Optional (threat model: disk, not RAM) | — |

---

## Zero-Length Plaintext Edge Case

When `user_len == 0` (all-NULL tuple):
- `tde_gcm_encrypt()` MUST produce `[IV(12) | TAG(16)]` (28 bytes total)
- `tde_gcm_decrypt()` MUST handle 28-byte input → 0 bytes plaintext
- **NEVER `Assert(plaintext_len > 0)`** — this fires on all-NULL rows

---

## Function Ownership Documentation

Every function that returns a `palloc`'d buffer MUST document:
1. Which `MemoryContext` the allocation occurs in
2. Who is responsible for `pfree`-ing the result
3. Whether `OPENSSL_cleanse` is required before `pfree`

Example:
```c
/*
 * tde_gcm_encrypt — Encrypt plaintext with AES-256-GCM.
 *
 * Returns: palloc'd buffer [IV(12) | CT | TAG(16)] in CurrentMemoryContext.
 * Caller owns the buffer and MUST pfree() it after use.
 * OPENSSL_cleanse is NOT required for the ciphertext output (disk threat model).
 */
```

---

## Dependency Constraints

- This module calls `pg_vault_tde_kms_get_dek()` to obtain the current DEK
- This module MUST NOT call any TAM or IAM functions
- This module MUST NOT include `pg_vault_tde_tam.h` or `pg_vault_tde_iam.h`
- OpenSSL `evp.h` is the only external crypto header permitted

---

## Performance Baselines

| Operation | Input Size | Target Latency | Measurement |
|-----------|-----------|---------------|-------------|
| `tde_gcm_encrypt` | 128 B | < 2 µs | `bench_tde.sh` micro-benchmark |
| `tde_gcm_encrypt` | 1 KB | < 5 µs | `bench_tde.sh` micro-benchmark |
| `tde_gcm_encrypt` | 8 KB (max toast-inline) | < 20 µs | `bench_tde.sh` micro-benchmark |
| `tde_gcm_decrypt` | 128 B | < 2 µs | (same) |
| `tde_gcm_decrypt` | 1 KB | < 5 µs | (same) |
| IV generation | 12 B | < 0.5 µs | `pg_strong_random` single call |
| EVP IV rearm (same relid/gen) | — | < 0.1 µs | `EVP_EncryptInit_ex2(ctx,NULL,NULL,iv,NULL)` |
| EVP re-key (relid/gen change) | — | ~1 µs | `EVP_EncryptInit_ex2` with DEK |

If a change causes > 20% regression from these baselines, it requires
@Coordinator approval and documentation in `doc/pg_vault_tde.md`.

## Error Propagation Contract

Crypto functions MUST NOT call `ereport()` directly for business-logic errors.
Instead, they return error indicators and let the caller (TAM layer) decide
the appropriate error level:

| Function | Error Indicator | Caller Action |
|----------|----------------|---------------|
| `tde_gcm_encrypt` | Returns NULL | Caller does `ereport(ERROR, ...)` |
| `tde_gcm_decrypt` | Returns NULL | Caller does `ereport(ERROR, ...)` with GCM auth message |
| `tde_encrypt_heap_tuple` | Returns NULL | TAM callback does `ereport(ERROR, ...)` |
| `tde_decrypt_heap_tuple` | Returns NULL | TAM callback does `ereport(ERROR, ...)` |

Exception: `ereport(PANIC, ...)` is allowed for unrecoverable OpenSSL
initialization failures (e.g., `EVP_CIPHER_CTX_new()` returns NULL = out
of kernel memory).
