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
 * Wire format v3 constants (v1.5+):
 *   [VERSION(1=0x03) | GENERATION(8) | IV(12) | CIPHERTEXT | TAG(16)]
 *
 * Identical structure to v2.  The only difference is VERSION = 0x03, which
 * signals that GCM Additional Authenticated Data (AAD) was applied at
 * encrypt time.  The AAD is:
 *   [MyDatabaseId(4 LE) | relid(4 LE) | generation(8 LE)]  = 16 bytes
 *
 * The AAD is NOT stored in the wire format (zero overhead); it is
 * recomputed from the stored GENERATION and the current database/relid.
 * Cross-table ciphertext paste attacks are detected because the recomputed
 * AAD will differ, causing GCM tag authentication to fail.
 *
 * Backward compatibility:
 *   v3 tuples: apply AAD in decrypt
 *   v2 tuples: skip AAD (v1.4 legacy, AAD was not set at encrypt)
 *   v1 tuples: skip AAD and v2 header (completely legacy path)
 */
#define TDE_V3_VERSION_BYTE  ((unsigned char) 0x03u)
#define TDE_V3_AAD_LEN       16  /* 4 (dboid) + 4 (relid) + 8 (generation) */
/* TDE_V3_OVERHEAD is the same as TDE_V2_OVERHEAD; no new wire bytes */

/*
 * Encrypt plaintext_len bytes using the DEK for the given relation.
 * relid == InvalidOid selects an unscoped path (v2 compatibility mode);
 * valid relid emits v3 with AAD binding.
 * Returns palloc'd [VERSION|GEN|IV|CT|TAG] buffer.
 * Caller MUST: OPENSSL_cleanse(buf, out_len); pfree(buf);
 */
char *tde_gcm_encrypt(Oid relid, const char *plaintext, Size plaintext_len,
                      Size *out_len);

/*
 * Decrypt a buffer produced by tde_gcm_encrypt. Verifies GCM tag.
 * Supports legacy v1/v2 tuples and current v3 tuples.
 * relid == InvalidOid selects an unscoped compatibility path.
 * Returns palloc'd plaintext. Caller MUST: OPENSSL_cleanse + pfree.
 */
char *tde_gcm_decrypt(Oid relid, const char *ciphertext, Size ciphertext_len,
                      Size *out_len);

/*
 * Free per-backend EVP contexts and wipe the IV batch buffer.
 * Registered via on_proc_exit() in _PG_init; also callable directly.
 */
void tde_crypto_ctx_cleanup(void);

#endif /* PG_VAULT_TDE_CRYPTO_H */
