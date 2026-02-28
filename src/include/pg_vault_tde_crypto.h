/*
 * pg_vault_tde_crypto.h - AES-256-GCM encrypt/decrypt API
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */
#ifndef PG_VAULT_TDE_CRYPTO_H
#define PG_VAULT_TDE_CRYPTO_H

#include "postgres.h"

/* Wire format v1 constants for AES-256-GCM: [IV(12)|CIPHERTEXT|TAG(16)] */
#define TDE_GCM_IV_LEN   12 /* 96-bit IV, NIST recommended for GCM */
#define TDE_GCM_TAG_LEN  16 /* 128-bit authentication tag */
#define TDE_GCM_OVERHEAD (TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN)

/*
 * Wire format v2 constants (v1.4+):
 *   [VERSION(1) | GENERATION(8) | IV(12) | CIPHERTEXT | TAG(16)]
 *
 * VERSION byte = 0x02 distinguishes v2 from v1 (whose first byte is a
 * random IV octet).  If tde_gcm_decrypt sees 0x02 as the first byte it
 * uses the v2 parse path; a 1/256 false-positive on a v1 tuple causes a
 * failed GCM tag check, which then falls through to the v1 retry path.
 *
 * GENERATION (uint64 LE, 8 bytes): DEK rotation epoch counter embedded at
 * encrypt time.  Reserved for future use (smart DEK selection without
 * trial decryption).  Read but not validated during v1.4 decryption.
 */
#define TDE_V2_VERSION_BYTE  ((unsigned char) 0x02u)
#define TDE_V2_GEN_LEN       8   /* sizeof(uint64): generation counter */
#define TDE_V2_OVERHEAD      (1 + TDE_V2_GEN_LEN + TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN)

/*
 * Encrypt plaintext_len bytes. Returns palloc'd [IV|CT|TAG] buffer.
 * Caller MUST: OPENSSL_cleanse(buf, out_len); pfree(buf);
 */
char *tde_gcm_encrypt(const char *plaintext, Size plaintext_len,
                      Size *out_len);

/*
 * Decrypt a buffer produced by tde_gcm_encrypt. Verifies GCM tag.
 * Returns palloc'd plaintext. Caller MUST: OPENSSL_cleanse + pfree.
 */
char *tde_gcm_decrypt(const char *ciphertext, Size ciphertext_len,
                      Size *out_len);

/*
 * Free per-backend EVP contexts and wipe the IV batch buffer.
 * Registered via on_proc_exit() in _PG_init; also callable directly.
 */
void tde_crypto_ctx_cleanup(void);

#endif /* PG_VAULT_TDE_CRYPTO_H */
