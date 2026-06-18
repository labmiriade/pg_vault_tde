/*
 * pg_vault_tde_crypto.h - AES-256-GCM encrypt/decrypt API
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */
#ifndef PG_VAULT_TDE_CRYPTO_H
#define PG_VAULT_TDE_CRYPTO_H

#include "postgres.h"

/* AES-256-GCM wire format: [VERSION(1=0x03) | GEN(8) | IV(12) | CT | TAG(16)] */
#define TDE_GCM_IV_LEN       12  /* 96-bit IV, NIST recommended for GCM */
#define TDE_GCM_TAG_LEN      16  /* 128-bit authentication tag */
#define TDE_V3_VERSION_BYTE  ((unsigned char) 0x03u)
#define TDE_V3_AAD_LEN       16  /* 4 (dboid) + 4 (relid) + 8 (generation) */
#define TDE_V3_GEN_LEN       8   /* sizeof(uint64): generation counter */
#define TDE_V3_OVERHEAD      (1 + TDE_V3_GEN_LEN + TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN)

/* Encrypt plaintext using the DEK for relid. Returns palloc'd buffer. */
char *tde_gcm_encrypt(Oid relid, const char *plaintext, Size plaintext_len,
                      Size *out_len);

/* Decrypt a buffer produced by tde_gcm_encrypt. Verifies GCM tag. */
char *tde_gcm_decrypt(Oid relid, const char *ciphertext, Size ciphertext_len,
                      Size *out_len);

/* Free per-backend EVP contexts and wipe the IV batch buffer. */
void tde_crypto_ctx_cleanup(void);

#endif /* PG_VAULT_TDE_CRYPTO_H */
