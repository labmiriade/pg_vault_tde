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

/*
 * tde_iam_build_in_progress — process-local flag coordinating index build.
 *
 * Set to true by pg_vault_tde_ambuild (iam.c) before calling
 * saved_btree_am->ambuild, cleared after it returns.  PostgreSQL is
 * multi-process (not multi-thread), so this backend-local variable is
 * safe for the synchronous ambuild call chain.
 *
 * pg_vault_tde_index_build_range_scan (tam.c) reads this flag to decide
 * whether to encrypt index key values before passing them to the btree
 * build callback (btbuildCallback).  This ensures consistency between
 * the bulk-built index entries and those inserted via aminsert.
 */
extern bool tde_iam_build_in_progress;

/*
 * tde_iam_encrypt_index_datum — encrypt a typed Datum using AES-256-SIV.
 *
 * Accepts the attribute type metadata (typbyval, typlen) so that
 * pass-by-value types (int4, int8, date, timestamptz, bool …) are
 * serialised directly from the Datum scalar, while varlena types
 * (text, numeric, uuid, bytea …) are detoasted first.
 *
 * Called from pg_vault_tde_index_build_range_scan when
 * tde_iam_build_in_progress is true, to encrypt index key values before
 * they reach btree's internal spool.
 *
 * Returns a new palloc'd bytea Datum.  The caller should pfree it after
 * the index tuple has been formed (i.e., after btbuildCallback returns).
 */
Datum tde_iam_encrypt_index_datum(Datum datum, bool typbyval, int16 typlen);

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
