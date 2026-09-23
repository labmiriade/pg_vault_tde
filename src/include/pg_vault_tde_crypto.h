/*
 * pg_vault_tde_crypto.h - AES-256-GCM encrypt/decrypt API
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */
#ifndef PG_VAULT_TDE_CRYPTO_H
#define PG_VAULT_TDE_CRYPTO_H

#include "postgres.h"

/*
 * AES-256-GCM AEAD blob, IV first:
 *     [ IV(12) | CT(N) | TAG(16) | VERSION(1) | GEN(8) ]
 *
 * Stored whole by index keys, TOAST chunks and backup blocks.  A v5 heap tuple
 * re-frames it — ciphertext scattered per attribute, IV in the trailer — see
 * tde_value_ranges() in pg_vault_tde_tam.c.  The fresh IV per row version is
 * what keeps HOT off and tde_btree coherent.
 */
#define TDE_GCM_IV_LEN       12  /* 96-bit IV, NIST recommended for GCM */
#define TDE_GCM_TAG_LEN      16  /* 128-bit authentication tag */
#define TDE_V4_VERSION_BYTE  ((unsigned char) 0x04u)
/*
 * Heap tuple LAYOUT version, stored in the same framing byte (outside the
 * GCM tag).  0x04 = whole user-data region is one blob; 0x05 = attributes
 * keep their on-disk layout and only the value bytes are ciphertext.  The
 * cipher, the AAD and the tag are identical either way — see
 * tde_encrypt_heap_tuple() in src/tam/pg_vault_tde_tam.c.
 */
#define TDE_TUPLE_V5_VERSION_BYTE ((unsigned char) 0x05u)
#define TDE_V4_AAD_LEN       16  /* 4 (dboid) + 4 (relid) + 8 (generation) */
#define TDE_V4_GEN_LEN       8   /* sizeof(uint64): generation counter */
#define TDE_V4_OVERHEAD      (1 + TDE_V4_GEN_LEN + TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN)


/* Encrypt plaintext using the DEK for relid. Returns palloc'd buffer. */
char *tde_gcm_encrypt(Oid relid, const char *plaintext, Size plaintext_len,
                      Size *out_len);

/* Decrypt into caller's out_plain (cap = ciphertext_len - TDE_V4_OVERHEAD). */
/* Verifies GCM tag: ERROR on tamper, false on non-v4 version byte. */
bool tde_gcm_decrypt(Oid relid, const char *ciphertext, Size ciphertext_len,
                     char *out_plain, Size *out_len);

/* Free per-backend EVP contexts and wipe the IV batch buffer. */
void tde_crypto_ctx_cleanup(void);

#endif /* PG_VAULT_TDE_CRYPTO_H */
