/*
 * pg_vault_tde_iam_ope.c - Order-Preserving Encryption (OPE) IAM handler
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * Deterministic encryption (such as AES-256-SIV in tde_btree) only preserves
 * equality, precluding range scans (<, <=, >, >=).
 *
 * This module implements the tde_ope_btree access method, which wraps native
 * B-Tree using Order-Preserving Encryption (OPE). Under OPE, encrypted index
 * tokens preserve order, allowing native B-Tree to evaluate both equality and
 * range scans.
 */
#include "postgres.h"
#include "access/amapi.h"
#include "access/genam.h"
#include "access/nbtree.h"
#include "access/tableam.h"    /* table_index_build_scan, IndexBuildCallback */
#include "nodes/execnodes.h"   /* IndexInfo full struct definition */
#include "utils/fmgroids.h"     /* F_BTHANDLER */
#include "utils/memutils.h"
#include "utils/syscache.h"     /* SearchSysCache1, ReleaseSysCache, CLAOID */
#include "utils/uuid.h"         /* DatumGetUUIDP, pg_uuid_t */
#include "catalog/pg_opclass.h" /* Form_pg_opclass */
#include "catalog/pg_am_d.h"    /* BTREE_AM_OID */
#include "storage/lwlock.h"


#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_iam_ope.h"
#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_crypto_ope.h"

/*
 * Forward declaration of build function for identity checks.
 */
static IndexBuildResult *pg_vault_tde_ope_ambuild(Relation heap, Relation index,
												  IndexInfo *index_info);

/* Mutable copy of the btree AM routine, patched with our ORE overrides */
static IndexAmRoutine  tde_ope_btree_methods;

/* Original (unmodified) btree AM — saved as a STATIC copy for safe delegation */
static IndexAmRoutine  saved_btree_methods;
static bool            saved_btree_methods_valid = false;


/*
 * Check if the index relation is managed by tde_ope_btree
 */
bool tde_iam_is_ope_btree_index(Relation index_rel)
{
	return index_rel->rd_indam != NULL &&
		   index_rel->rd_indam->ambuild == pg_vault_tde_ope_ambuild;
}

/*
 * tde_iam_ope_serialize_fixed_type — serialize fixed-size types to canonical big-endian.
 */
static Size
tde_iam_ope_serialize_fixed_type(Datum datum, Oid typoid, uint8 *buf)
{
	memset(buf, 0, 16);

	switch (typoid)
	{
	case INT4OID:
	case DATEOID:
	{
		uint32 v = pg_hton32((uint32)DatumGetInt32(datum));
		memcpy(buf, &v, 4);
		return 4;
	}
	case INT8OID:
	case TIMESTAMPTZOID:
	{
		uint64 v = pg_hton64((uint64)DatumGetInt64(datum));
		memcpy(buf, &v, 8);
		return 8;
	}
	case UUIDOID:
	{
		pg_uuid_t *uid = DatumGetUUIDP(datum);
		memcpy(buf, uid->data, 16);
		return 16;
	}
	default:
		return 0;
	}
}

/*
 * tde_iam_ope_encrypt_fixed_type_datum — encrypt fixed-size Datum using ORE.
 */
Datum
tde_iam_ope_encrypt_fixed_type_datum(Relation index_rel, Datum datum, Oid typoid)
{
    uint8   plain_buf[16];
	Size volatile plain_len;
    Size    enc_len = 0;
    char   *encrypted;
    bytea  *enc_bytea = NULL;
	unsigned char dek[TDE_DEK_LEN];

	memset(plain_buf, 0, sizeof(plain_buf));

	plain_len = tde_iam_ope_serialize_fixed_type(datum, typoid, plain_buf);
	if (plain_len == 0)
	{
		ereport(WARNING,
				(errmsg("[IAM-OPE] tde_iam_ope_encrypt_fixed_type_datum: "
						"unknown typoid %u, skipping encryption",
						typoid)));
		return datum;
	}

	if (!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
	{
		ereport(ERROR,
				(errmsg("[IAM-OPE] tde_iam_ope_encrypt_fixed_type_datum: "
						"DEK unavailable for index rel: %u",
						RelationGetRelid(index_rel))));
	}

	PG_TRY();
	{
		encrypted = tde_crypto_ope_encrypt((const char *)dek, sizeof(dek),
										   (const char *)plain_buf, plain_len, &enc_len);
		OPENSSL_cleanse(plain_buf, sizeof(plain_buf));

        enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
		SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
		memcpy(VARDATA(enc_bytea), encrypted, enc_len);
		OPENSSL_cleanse(encrypted, enc_len);
		pfree(encrypted);
	}
	PG_CATCH();
	{
		OPENSSL_cleanse(plain_buf, sizeof(plain_buf));
		OPENSSL_cleanse(dek, sizeof(dek));
		PG_RE_THROW();
	}
	PG_END_TRY();

	OPENSSL_cleanse(dek, sizeof(dek));
	return PointerGetDatum(enc_bytea);
}

/*
 * tde_iam_ope_encrypt_index_datum — encrypt typed varlena Datum using ORE.
 */
Datum
tde_iam_ope_encrypt_index_datum(Relation index_rel, Datum datum, bool typbyval, int16 typlen)
{
	if (typlen != -1 && typlen != -2)
	{
		ereport(DEBUG2,
				(errmsg("[IAM-OPE] Skipping index key encryption for "
						"fixed-size column without enc_ops (typlen=%d, typbyval=%s)",
                        (int) typlen, typbyval ? "true" : "false")));
		return datum;
	}

	{
        bytea      *bval = NULL;
		const char *plain;
        Size        plen;
        Size        enc_len = 0;
        char       *encrypted;
        bytea      *enc_bytea = NULL;
		unsigned char dek[TDE_DEK_LEN];

		if (typlen == -1)
		{
            bval  = (bytea *) PG_DETOAST_DATUM_COPY(datum);
			plain = VARDATA_ANY(bval);
            plen  = VARSIZE_ANY_EXHDR(bval);
		}
		else
		{
			plain = DatumGetCString(datum);
            plen  = strlen(plain) + 1;
		}

		if (!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
		{
            ereport(ERROR,
                    (errmsg("[IAM-OPE] tde_iam_ope_encrypt_index_datum: "
                            "DEK unavailable for index relid %u", RelationGetRelid(index_rel))));
		}

		PG_TRY();
		{
			encrypted = tde_crypto_ope_encrypt((const char *)dek, sizeof(dek),
											   plain, plen, &enc_len);

			enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
			SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
			memcpy(VARDATA(enc_bytea), encrypted, enc_len);
			OPENSSL_cleanse(encrypted, enc_len);
			pfree(encrypted);
		}
		PG_CATCH();
		{
			OPENSSL_cleanse(dek, sizeof(dek));
			PG_RE_THROW();
		}
		PG_END_TRY();
		if (bval)
			pfree(bval);
		OPENSSL_cleanse(dek, sizeof(dek));
		return PointerGetDatum(enc_bytea);
	}
} 

/*
 * tde_iam_ope_bytea_cmp — B-Tree support function 1 (three-way comparator).
 * Evaluates relative order of two ORE ciphertexts.
 *
 * Comparison algorithm:
 *
 *   For each block position i:
 *     1. Check whether prf_tag_a[i] == prf_tag_b[i].
 *        The prf_tag is derived from AES-ECB(SHA256(plaintext[0..i-1])).
 *        Equal tags mean both values share the same prefix[0..i-1].
 *
 *     2. If tags match: both blocks were encrypted with the same mask_byte
 *        (same AES input → same AES output → same mask_byte).  Deblind:
 *          plain_a = blinded_val_a ^ mask_byte_a
 *          plain_b = blinded_val_b ^ mask_byte_b   (mask_byte_a == mask_byte_b)
 *        Compare plain_a vs plain_b to determine order at this position.
 *        Return immediately on a mismatch.
 *
 *     3. If tags differ: the prefixes already diverged before block i.
 *        The ordering was determined in an earlier iteration that returned.
 *        Skip this block — the loop will fall through to the length tiebreak,
 *        which is correct because the values already compared equal on all
 *        positions where tags matched.
 *
 *   After the loop, if all common-prefix bytes compared equal, the shorter
 *   value is ordered first.
 */
PG_FUNCTION_INFO_V1(tde_iam_ope_bytea_cmp);
Datum tde_iam_ope_bytea_cmp(PG_FUNCTION_ARGS)
{
	bytea *a = PG_GETARG_BYTEA_PP(0);
	bytea *b = PG_GETARG_BYTEA_PP(1);

	/* Extract direct pointers to the serialized OreSerializedPayload structures */
	const char *ctxt_a = (const char *)VARDATA_ANY(a);
	const char *ctxt_b = (const char *)VARDATA_ANY(b);

	unsigned long len_a = VARSIZE_ANY_EXHDR(a);
	unsigned long len_b = VARSIZE_ANY_EXHDR(b);

	int result;

	/*
	 * Safety Guard: If either index token is corrupted, empty, or missing
	 * its payload structure header, fall back to comparing raw data sizes.
	 */
	if (len_a < sizeof(OreSerializedPayload) || len_b < sizeof(OreSerializedPayload))
	{
		PG_RETURN_INT32(len_a - len_b);
	}

	/* Delegate structural evaluation directly to the new block ORE comparator */
	// result = tde_crypto_ope_compare(ctxt_a, ctxt_b);
	result = tde_crypto_ope_compare(ctxt_a, ctxt_b);

	PG_RETURN_INT32(result);
}

/*
 * Boolean operator support functions for ORE bytea operator classes
 */
PG_FUNCTION_INFO_V1(tde_iam_ope_bytea_lt);
Datum
tde_iam_ope_bytea_lt(PG_FUNCTION_ARGS)
{
    int32 cmp = DatumGetInt32(DirectFunctionCall2(tde_iam_ope_bytea_cmp,
                                                  PG_GETARG_DATUM(0),
                                                  PG_GETARG_DATUM(1)));
	PG_RETURN_BOOL(cmp < 0);
}

PG_FUNCTION_INFO_V1(tde_iam_ope_bytea_le);
Datum
tde_iam_ope_bytea_le(PG_FUNCTION_ARGS)
{
    int32 cmp = DatumGetInt32(DirectFunctionCall2(tde_iam_ope_bytea_cmp,
                                                  PG_GETARG_DATUM(0),
                                                  PG_GETARG_DATUM(1)));
	PG_RETURN_BOOL(cmp <= 0);
}

PG_FUNCTION_INFO_V1(tde_iam_ope_bytea_eq);
Datum
tde_iam_ope_bytea_eq(PG_FUNCTION_ARGS)
{
    int32 cmp = DatumGetInt32(DirectFunctionCall2(tde_iam_ope_bytea_cmp,
                                                  PG_GETARG_DATUM(0),
                                                  PG_GETARG_DATUM(1)));
	PG_RETURN_BOOL(cmp == 0);
}

PG_FUNCTION_INFO_V1(tde_iam_ope_bytea_ge);
Datum
tde_iam_ope_bytea_ge(PG_FUNCTION_ARGS)
{
    int32 cmp = DatumGetInt32(DirectFunctionCall2(tde_iam_ope_bytea_cmp,
                                                  PG_GETARG_DATUM(0),
                                                  PG_GETARG_DATUM(1)));
	PG_RETURN_BOOL(cmp >= 0);
}

PG_FUNCTION_INFO_V1(tde_iam_ope_bytea_gt);
Datum
tde_iam_ope_bytea_gt(PG_FUNCTION_ARGS)
{
    int32 cmp = DatumGetInt32(DirectFunctionCall2(tde_iam_ope_bytea_cmp,
                                                  PG_GETARG_DATUM(0),
                                                  PG_GETARG_DATUM(1)));
	PG_RETURN_BOOL(cmp > 0);
} 

/*
 * Fixed type support function 1 wrappers (delegating to tde_iam_ope_bytea_cmp)
 */
PG_FUNCTION_INFO_V1(tde_iam_ope_text_cmp);
Datum tde_iam_ope_text_cmp(PG_FUNCTION_ARGS)
{
	return DirectFunctionCall2(tde_iam_ope_bytea_cmp, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1));
}

PG_FUNCTION_INFO_V1(tde_iam_ope_int4_cmp);
Datum
tde_iam_ope_int4_cmp(PG_FUNCTION_ARGS) 
{ 
	return DirectFunctionCall2(tde_iam_ope_bytea_cmp, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1)); 
}

PG_FUNCTION_INFO_V1(tde_iam_ope_int8_cmp);
Datum
tde_iam_ope_int8_cmp(PG_FUNCTION_ARGS) 
{ 
	return DirectFunctionCall2(tde_iam_ope_bytea_cmp, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1)); 
}

PG_FUNCTION_INFO_V1(tde_iam_ope_uuid_cmp);
Datum
tde_iam_ope_uuid_cmp(PG_FUNCTION_ARGS) 
{ 
	return DirectFunctionCall2(tde_iam_ope_bytea_cmp, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1)); 
}

PG_FUNCTION_INFO_V1(tde_iam_ope_date_cmp);
Datum
tde_iam_ope_date_cmp(PG_FUNCTION_ARGS) 
{ 
	return DirectFunctionCall2(tde_iam_ope_bytea_cmp, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1)); 
}

PG_FUNCTION_INFO_V1(tde_iam_ope_timestamptz_cmp);
Datum
tde_iam_ope_timestamptz_cmp(PG_FUNCTION_ARGS) 
{ 
	return DirectFunctionCall2(tde_iam_ope_bytea_cmp, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1)); 
} 

/* ── B-TREE PROXY ACCESS METHOD IMPLEMENTATION ──────────────────────────── */

static inline void
tde_ope_assert_not_impersonated(Relation index) 
{ 
	Assert(index->rd_rel->relam != BTREE_AM_OID); 
}

/*
 * pg_vault_tde_ope_ambuild — delegates to btree's ambuild with relam impersonation.
 */
static IndexBuildResult *
pg_vault_tde_ope_ambuild(Relation heap, Relation index, IndexInfo *index_info)
{
	IndexBuildResult *result;
    Oid               saved_relam = index->rd_rel->relam;

	Assert(saved_btree_methods_valid);
	tde_ope_assert_not_impersonated(index);

	index->rd_rel->relam = BTREE_AM_OID;

	PG_TRY();
	{
		result = saved_btree_methods.ambuild(heap, index, index_info);
	}
	PG_CATCH();
	{
		index->rd_rel->relam = saved_relam;
		PG_RE_THROW();
	}
	PG_END_TRY();
	index->rd_rel->relam = saved_relam;

	return result;
}

/*
 * pg_vault_tde_ope_aminsert — encrypts values[] with ORE and forwards to btree's aminsert.
 */
static bool
pg_vault_tde_ope_aminsert(Relation index, Datum *values, bool *isnull,
                          ItemPointer heap_tid, Relation heap,
                          IndexUniqueCheck check_unique,
                          bool index_unchanged,
                          IndexInfo *index_info)
{
    Datum   enc_values[INDEX_MAX_KEYS];
    bool    enc_isnull[INDEX_MAX_KEYS];
    int     ncols = index_info->ii_NumIndexAttrs;
    int     i;
    bool    result;
    Oid     saved_relam;

	Assert(saved_btree_methods_valid);
	tde_ope_assert_not_impersonated(index);

	memcpy(enc_isnull, isnull, ncols * sizeof(bool));

	for (i = 0; i < ncols; i++)
	{
		if (isnull[i])
		{
            enc_values[i] = (Datum) 0;
		}
		else if (TDE_ope_IS_ENC_OPS_COL(index, i))
		{
			enc_values[i] = tde_iam_ope_encrypt_fixed_type_datum(
				index,
				values[i],
				index->rd_opcintype[i]);
		}
		else
		{
			Form_pg_attribute att = TupleDescAttr(index->rd_att, i);
            enc_values[i] = tde_iam_ope_encrypt_index_datum(
                                index,
                                values[i],
                                att->attbyval,
                                att->attlen);
		}
	}

	saved_relam = index->rd_rel->relam;
	index->rd_rel->relam = BTREE_AM_OID;

	PG_TRY();
	{
        result = saved_btree_methods.aminsert(index, enc_values, enc_isnull,
                                              heap_tid, heap,
                                              check_unique, index_unchanged,
                                              index_info);
	}
	PG_CATCH();
	{
		index->rd_rel->relam = saved_relam;
		PG_RE_THROW();
	}
	PG_END_TRY();

	index->rd_rel->relam = saved_relam;
	return result;
} 

/*
 * pg_vault_tde_ope_ambeginscan — delegates directly to btree.
 */
static IndexScanDesc
pg_vault_tde_ope_ambeginscan(Relation index, int nkeys, int norderbys)
{
	tde_ope_assert_not_impersonated(index);
	Assert(saved_btree_methods_valid);
	return saved_btree_methods.ambeginscan(index, nkeys, norderbys);
} 

/*
 * pg_vault_tde_ope_amrescan — intercept scan keys for ALL 5 strategy operators.
 */
static void
pg_vault_tde_ope_amrescan(IndexScanDesc scan, ScanKey keys, int nkeys,
						  ScanKey orderbys, int norderbys)
{
	int i;

	Assert(scan->indexRelation->rd_rel != NULL);

	tde_ope_assert_not_impersonated(scan->indexRelation);
	Assert(saved_btree_methods_valid);

	if (keys != NULL)
	{
		for (i = 0; i < nkeys; i++)
		{
			if ((keys[i].sk_flags & SK_ISNULL) == 0 &&
				(keys[i].sk_strategy >= BTLessStrategyNumber &&
				 keys[i].sk_strategy <= BTGreaterStrategyNumber))
			{
				int col = keys[i].sk_attno - 1;
				Oid opcintype = scan->indexRelation->rd_opcintype[col];

				/* 1. Encrypt the search arguments cleanly based on their true schema type */
				if (opcintype == INT4OID || opcintype == INT8OID ||
					opcintype == DATEOID || opcintype == TIMESTAMPTZOID ||
					opcintype == UUIDOID)
				{
					keys[i].sk_argument =
						tde_iam_ope_encrypt_fixed_type_datum(scan->indexRelation,
															 keys[i].sk_argument,
															 opcintype);
				}
				else
				{
					Form_pg_attribute att = TupleDescAttr(scan->indexRelation->rd_att, col);
					keys[i].sk_argument =
						tde_iam_ope_encrypt_index_datum(scan->indexRelation,
														keys[i].sk_argument,
														att->attbyval,
														att->attlen);
				}

				/* Rebind sk_func to corresponding bytea boolean operator */
				switch (keys[i].sk_strategy)
				{
				case BTLessStrategyNumber:
					fmgr_info(F_BYTEALT, &keys[i].sk_func);
					break;
				case BTLessEqualStrategyNumber:
					fmgr_info(F_BYTEALE, &keys[i].sk_func);
					break;
				case BTEqualStrategyNumber:
					fmgr_info(F_BYTEAEQ, &keys[i].sk_func);
					break;
				case BTGreaterEqualStrategyNumber:
					fmgr_info(F_BYTEAGE, &keys[i].sk_func);
					break;
				case BTGreaterStrategyNumber:
					fmgr_info(F_BYTEAGT, &keys[i].sk_func);
					break;
				default:
					break;
				}
			}
		}
	}

	saved_btree_methods.amrescan(scan, keys, nkeys, orderbys, norderbys);
}

/*
 * pg_vault_tde_ope_amvalidate — validates ORE operator classes.
 */
static bool
pg_vault_tde_ope_amvalidate(Oid opclassoid)
{
    HeapTuple       classtup;
	Form_pg_opclass classform;
    bool            is_enc_ops;

	Assert(saved_btree_methods_valid);

	classtup = SearchSysCache1(CLAOID, ObjectIdGetDatum(opclassoid));
	if (!HeapTupleIsValid(classtup))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("cache lookup failed for operator class %u", opclassoid)));

    classform = (Form_pg_opclass) GETSTRUCT(classtup);
    is_enc_ops = (OidIsValid(classform->opckeytype) &&
                  classform->opckeytype == BYTEAOID &&
                  classform->opcintype  != BYTEAOID);
	ReleaseSysCache(classtup);

	if (is_enc_ops)
		return true;

	return saved_btree_methods.amvalidate(opclassoid);
} 

/*
 * tde_ope_iam_init — initialize tde_ope_btree access method routine table.
 */
void
tde_ope_iam_init(void)
{
    IndexAmRoutine *tmp = (IndexAmRoutine *) DatumGetPointer(
        OidFunctionCall1(F_BTHANDLER, PointerGetDatum(NULL)));
	
	Assert(tmp != NULL);
	Assert(tmp->type == T_IndexAmRoutine);

	memcpy(&saved_btree_methods, tmp, sizeof(IndexAmRoutine));
	memcpy(&tde_ope_btree_methods, tmp, sizeof(IndexAmRoutine));
	
    pfree(tmp);
	saved_btree_methods_valid = true;

    tde_ope_btree_methods.ambuild           	= pg_vault_tde_ope_ambuild;
    tde_ope_btree_methods.aminsert          	= pg_vault_tde_ope_aminsert;
    tde_ope_btree_methods.ambeginscan       	= pg_vault_tde_ope_ambeginscan;
    tde_ope_btree_methods.amrescan          	= pg_vault_tde_ope_amrescan;
    tde_ope_btree_methods.amvalidate        	= pg_vault_tde_ope_amvalidate;
	tde_ope_btree_methods.amcanreturn       	= NULL;
	tde_ope_btree_methods.amcanbuildparallel 	= false;
    tde_ope_btree_methods.amstorage         	= true;

	tde_crypto_ope_ctx_init();

	ereport(DEBUG1,
            (errmsg("[IAM-OPE] tde_ope_btree initialized: btree AM wrapped with "
							"Order-Revealing Encryption layer")));
}															  

/*
 * Free per-backend ORE contexts.
 */
void
tde_ope_iam_ctx_cleanup(void) 
{
	tde_crypto_ope_ctx_cleanup();
} 

/*
 * pg_vault_tde_get_iam_ope_routine — returns a freshly palloc'd copy of tde_ope_btree_methods.
 */
const IndexAmRoutine *
pg_vault_tde_get_iam_ope_routine(void)
{
	IndexAmRoutine *result;

	if (!saved_btree_methods_valid)
		tde_ope_iam_init();

    result = (IndexAmRoutine *) palloc(sizeof(IndexAmRoutine));
	memcpy(result, &tde_ope_btree_methods, sizeof(IndexAmRoutine));
	return result;
}
