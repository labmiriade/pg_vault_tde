/*
 * pg_vault_tde_iam_ope.h - Order-Revealing Encryption (ORE) IAM header
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_IAM_OPE_H
#define PG_VAULT_TDE_IAM_OPE_H

#include "postgres.h"
#include "access/amapi.h"
#include "catalog/pg_type_d.h"   /* INT4OID, INT8OID, DATEOID, TIMESTAMPTZOID, UUIDOID */
#include "utils/uuid.h"          /* DatumGetUUIDP, pg_uuid_t */

/*
 * ORE function
 * Callers MUST OPENSSL_cleanse + pfree the returned buffers after use if applicable.
 */
char *tde_iam_ope_encrypt_key(Oid idx_oid, const char *dek, int dek_len,
                           const char *plaintext, Size plaintext_len, Size *out_len);

/*
 * tde_iam_ope_encrypt_index_datum — encrypt a typed Datum using ORE.
 */
Datum tde_iam_ope_encrypt_index_datum(Relation index_rel, Datum datum, bool typbyval, int16 typlen);

/*
 * tde_iam_ope_encrypt_fixed_type_datum — canonical big-endian serialisation + ORE.
 */
Datum tde_iam_ope_encrypt_fixed_type_datum(Relation index_rel, Datum datum, Oid typoid);

/*
 * B-Tree support function 1 (comparator) and operator functions for ORE
 */
extern Datum tde_iam_ope_bytea_cmp(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_bytea_lt(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_bytea_le(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_bytea_eq(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_bytea_ge(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_bytea_gt(PG_FUNCTION_ARGS);

/*
 * Fixed type wrappers for support function 1
 */
extern Datum tde_iam_ope_int4_cmp(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_int8_cmp(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_uuid_cmp(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_date_cmp(PG_FUNCTION_ARGS);
extern Datum tde_iam_ope_timestamptz_cmp(PG_FUNCTION_ARGS);

/*
 * tde_iam_is_ope_btree_index — is this index built/maintained by our
 * tde_ope_btree AM?
 */
extern bool tde_iam_is_ope_btree_index(Relation index_rel);

/* Exported registration function for CREATE ACCESS METHOD */
const IndexAmRoutine *pg_vault_tde_get_iam_ope_routine(void);

/*
 * TDE_ope_IS_ENC_OPS_COL(index_rel, col_zero_based)
 *
 * True when index column `col` uses an ORE enc_ops operator class:
 *   - the index stores bytea (opckeytype = BYTEAOID)
 *   - but the declared opclass input type is NOT bytea or text
 */
#define TDE_ope_IS_ENC_OPS_COL(index_rel, col) \
    (TupleDescAttr((index_rel)->rd_att, (col))->atttypid == BYTEAOID \
     && (index_rel)->rd_opcintype[(col)] != BYTEAOID               \
     && (index_rel)->rd_opcintype[(col)] != TEXTOID)

/*
 * tde_ope_iam_init — initialize tde_ope_btree at server startup.
 */
void tde_ope_iam_init(void);

/*
 * Free per-backend ORE contexts on backend exit.
 */
void tde_ope_iam_ctx_cleanup(void);

#endif /* PG_VAULT_TDE_IAM_OPE_H */
