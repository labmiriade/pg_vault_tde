/*
 * pg_vault_tde_iam.h - Index Access Method (IAM) handler header
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_IAM_H
#define PG_VAULT_TDE_IAM_H

#include "postgres.h"
#include "access/amapi.h"

/*
 * AES-256-SIV key encryption/decryption for B-Tree index entries.
 * Callers MUST OPENSSL_cleanse + pfree the returned buffers after use.
 */
char *tde_iam_encrypt_key(const char *plaintext, Size plaintext_len,
                          Size *out_len);
char *tde_iam_decrypt_key(const char *ciphertext, Size ciphertext_len,
                          Size *out_len);

/* Exported registration function for CREATE ACCESS METHOD */
const IndexAmRoutine *pg_vault_tde_get_iam_routine(void);

/*
 * tde_iam_init — initialize tde_btree at server startup.
 *
 * Copies the btree IndexAmRoutine and overrides the four key-manipulating
 * callbacks (ambuild, aminsert, ambeginscan, amrescan) with AES-256-SIV
 * encryption wrappers.  Must be called from _PG_init() after GUC and
 * hook registration, before any index access attempt.
 */
void tde_iam_init(void);

/*
 * Free per-backend AES-SIV EVP contexts.
 * Called from tde_backend_cleanup() which is registered via on_proc_exit().
 */
void tde_iam_siv_ctx_cleanup(void);

#endif /* PG_VAULT_TDE_IAM_H */
