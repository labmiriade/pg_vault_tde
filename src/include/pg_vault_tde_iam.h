/*
 * pg_vault_tde_iam.h - Index Access Method (IAM) handler header
 *
 * Copyright (c) 2026 Miriade S.r.l.  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_IAM_H
#define PG_VAULT_TDE_IAM_H

#include "postgres.h"
#include "access/amapi.h"
#include "catalog/pg_type_d.h"   /* INT4OID, INT8OID, DATEOID, TIMESTAMPTZOID, UUIDOID */
#include "utils/uuid.h"          /* DatumGetUUIDP, pg_uuid_t */

/*
 * AES-256-SIV key encryption/decryption for B-Tree index entries.
 * Callers MUST OPENSSL_cleanse + pfree the returned buffers after use.
 */
char *tde_iam_encrypt_key(Oid idx_oid, const char* dek, int dek_len,
                          const char *plaintext, Size plaintext_len, Size *out_len);
char *tde_iam_decrypt_key(Oid idx_oid, const char* dek, int dek_len,
                          const char *ciphertext, Size ciphertext_len, Size *out_len);

/*
 * tde_iam_is_tde_btree_index — is this index built/maintained by our
 * tde_btree AM (as opposed to a plain btree/other AM on the same
 * encrypted_heap table)?
 *
 * pg_vault_tde_index_build_range_scan (tam.c) calls this to decide whether
 * to encrypt index key values before passing them to the btree build
 * callback (btbuildCallback).
 *
 * Identity check on index_rel->rd_indam->ambuild rather than a process-local
 * flag: a parallel CREATE INDEX / REINDEX build runs btbuild's scan-and-sort
 * in separate worker backends (nbtsort.c's _bt_parallel_build_main), which
 * never call pg_vault_tde_ambuild — a process-local "build in progress" flag
 * set only in the leader would stay false in those workers, silently
 * skipping key encryption there while the leader's share of the scan (if
 * any) still encrypts, producing an index with mixed plaintext/ciphertext
 * keys. rd_indam is populated independently in every backend from the
 * catalog's amhandler for this index (pg_vault_tde_get_iam_routine), so the
 * check is correct in the leader and in every worker alike.
 */
extern bool tde_iam_is_tde_btree_index(Relation index_rel);

/*
 * tde_iam_encrypt_index_datum — encrypt a typed Datum using AES-256-SIV.
 *
 * Accepts the attribute type metadata (typbyval, typlen) so that
 * pass-by-value types (int4, int8, date, timestamptz, bool …) are
 * serialised directly from the Datum scalar, while varlena types
 * (text, numeric, uuid, bytea …) are detoasted first.
 *
 * Called from pg_vault_tde_index_build_range_scan when
 * tde_iam_is_tde_btree_index() is true, to encrypt index key values before
 * they reach btree's internal spool.
 *
 * Returns a new palloc'd bytea Datum.  The caller should pfree it after
 * the index tuple has been formed (i.e., after btbuildCallback returns).
 */
Datum tde_iam_encrypt_index_datum(Relation index_rel, Datum datum, bool typbyval, int16 typlen);

/* Exported registration function for CREATE ACCESS METHOD */
const IndexAmRoutine *pg_vault_tde_get_iam_routine(void);

/* B-Tree support function 1 for tde_*_enc_ops operator classes */
extern Datum tde_enc_bytea_cmp(PG_FUNCTION_ARGS);

/*
 * TDE_IS_ENC_OPS_COL(index_rel, col_zero_based)
 *
 * True when index column `col` uses a tde_*_enc_ops operator class:
 *   - the index stores bytea (opckeytype = BYTEAOID)
 *   - but the declared opclass input type is NOT bytea or text
 *     (i.e. it is a fixed-size type: int4, int8, date, timestamptz, uuid)
 *
 * Relies on:
 *   rd_att->attrs[col].atttypid  — the actual stored type in IndexTuple
 *   rd_opcintype[col]            — the declared input type of the opclass
 *
 * Both fields are populated by RelationBuildDesc for every index relation
 * and are available from PG 12+ (confirmed in utils/rel.h:208).
 */
#define TDE_IS_ENC_OPS_COL(index_rel, col) \
    (TupleDescAttr((index_rel)->rd_att, (col))->atttypid == BYTEAOID \
     && (index_rel)->rd_opcintype[(col)] != BYTEAOID               \
     && (index_rel)->rd_opcintype[(col)] != TEXTOID)

/*
 * tde_iam_encrypt_fixed_type_datum — encrypt a fixed-size Datum (int4, int8,
 * uuid, date, timestamptz) using canonical big-endian serialisation + AES-256-SIV.
 * Returns a palloc'd bytea Datum.
 */
Datum tde_iam_encrypt_fixed_type_datum(Relation index_rel, Datum datum, Oid typoid);

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
void tde_iam_ctx_cleanup(void);

#endif /* PG_VAULT_TDE_IAM_H */
