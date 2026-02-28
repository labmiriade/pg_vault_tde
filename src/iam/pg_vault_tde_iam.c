/*
 * pg_vault_tde_iam.c - Index Access Method (IAM) handler for pg_vault_tde
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * Encrypting B-Tree index keys presents a fundamental problem: the B-Tree
 * algorithm requires a total ordering of keys (for comparisons and range
 * scans) that probabilistic encryption (e.g. AES-256-GCM with random IV)
 * completely destroys.
 *
 * We use AES-256-SIV (RFC 5297, "Synthetic IV") for index key encryption.
 * AES-SIV is deterministic authenticated encryption: given the same DEK
 * and plaintext, it always produces the same ciphertext.  This preserves
 * equality semantics (equal plaintexts → equal ciphertexts), which is
 * sufficient for B-Tree equality lookups.
 *
 * KNOWN LIMITATION: Range scans (>, <, BETWEEN) on TDE-encrypted indexed
 * columns are NOT supported and will return empty results.  Users requiring
 * range queries must either accept unencrypted indexes (SQL ACL protection
 * only) or restructure their queries.  This is the same trade-off made by
 * MySQL Enterprise TDE and AWS RDS Transparent Data Encryption.
 *
 * AES-SIV is available in OpenSSL 3.x via EVP_aes_256_siv().  It provides:
 *  - Deterministic encryption (same key + plaintext → same ciphertext)
 *  - Authenticated encryption (built-in integrity check, no separate HMAC)
 *  - No IV required from the caller; the "synthetic" IV is derived from
 *    the plaintext and an optional set of "associated data" headers.
 */
#include "postgres.h"
#include "access/amapi.h"
#include "access/genam.h"
#include "access/nbtree.h"
#include "access/tableam.h"    /* table_index_build_scan, IndexBuildCallback */
#include "nodes/execnodes.h"   /* IndexInfo full struct definition */
#include "utils/fmgroids.h"     /* F_BTHANDLER */
#include "utils/memutils.h"
#include "storage/lwlock.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>

/*
 * Forward declarations for btree internal sort API.
 *
 * _bt_spoolinit / _bt_spool / _bt_leafbuild / _bt_spoolfreeall are compiled
 * into the postgres binary but are NOT declared in the installed extension
 * dev headers (access/nbtsort.h is an internal header).  We forward-declare
 * them here with matching signatures so the C compiler accepts the calls;
 * the dynamic linker resolves them against the postgres binary at load time
 * (all backend symbols are exported on ELF platforms).
 *
 * This is the same technique used by contrib/pg_amcheck and similar
 * extensions that need btree's sort layer without a full PG source tree.
 */
typedef struct BTSpool BTSpool;  /* opaque — we only need the pointer */
extern BTSpool *_bt_spoolinit(Relation heap, Relation index,
                              bool isunique, bool isdead);
extern void     _bt_spool(BTSpool *btspool, ItemPointer self,
                          Datum *values, bool *isnull);
extern void     _bt_leafbuild(BTSpool *btspool, BTSpool *btspooldead);
extern void     _bt_spoolfreeall(BTSpool *btspool);
/* PKCS5_PBKDF2_HMAC is declared in openssl/evp.h (included above) */

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_iam.h"
#include "src/include/pg_vault_tde_hw_accel.h"

/* AES-SIV produces a 16-byte synthetic IV prepended to ciphertext. */
#define TDE_SIV_OVERHEAD 16

/*
 * Per-backend reusable EVP contexts for AES-256-SIV.
 *
 * AES-SIV requires full EVP_EncryptInit_ex() on every call (because the
 * derived siv_key changes if the DEK rotates), but we save the
 * EVP_CIPHER_CTX_new() heap allocation (~20-30 ns) by reusing the struct.
 * EVP_CIPHER_CTX_reset() is called on reuse to zero internal state before
 * the new Init.
 */
static EVP_CIPHER_CTX *tde_iam_siv_enc_ctx = NULL;
static EVP_CIPHER_CTX *tde_iam_siv_dec_ctx = NULL;

/*
 * tde_iam_siv_ctx_cleanup -- free cached SIV contexts.
 * Called from tde_crypto_ctx_cleanup() registered via on_proc_exit().
 */
void
tde_iam_siv_ctx_cleanup(void)
{
    if (tde_iam_siv_enc_ctx != NULL)
    {
        EVP_CIPHER_CTX_free(tde_iam_siv_enc_ctx);
        tde_iam_siv_enc_ctx = NULL;
    }
    if (tde_iam_siv_dec_ctx != NULL)
    {
        EVP_CIPHER_CTX_free(tde_iam_siv_dec_ctx);
        tde_iam_siv_dec_ctx = NULL;
    }
}

/*
 * tde_iam_encrypt_key
 *
 * Encrypts a B-Tree index key datum using AES-256-SIV.
 * Returns a palloc'd buffer containing [SIV-tag (16 bytes) | ciphertext].
 * The caller MUST OPENSSL_cleanse + pfree the returned buffer after use.
 *
 * @param plaintext     raw key bytes
 * @param plaintext_len length of plaintext in bytes
 * @param out_len       set to total encrypted length on success
 * @returns             palloc'd encrypted buffer, or NULL on DEK miss
 *
 * Side effects: reads DEK from shared-memory KMS cache under shared LWLock.
 */
char *
tde_iam_encrypt_key(const char *plaintext, Size plaintext_len, Size *out_len)
{
    EVP_CIPHER_CTX *ctx;
    char            dek[TDE_DEK_LEN];
    char           *out_buf = NULL;
    int             olen1 = 0,
                    olen2 = 0;

    Assert(plaintext != NULL);
    Assert(out_len != NULL);

    /* Cache miss: we cannot encrypt without a DEK; caller must retry. */
    if (!pg_vault_tde_kms_get_dek(dek, TDE_DEK_LEN))
    {
        ereport(WARNING,
                (errmsg("[IAM] DEK unavailable for index key encryption")));
        return NULL;
    }

    /*
     * PG_TRY/PG_CATCH guarantees the DEK is wiped from the stack on ALL
     * exit paths — including palloc OOM between DEK acquisition and the
     * PBKDF2 derivation step.  Inner ereport(ERROR) calls longjmp into
     * PG_CATCH, so OPENSSL_cleanse runs before re-throw.
     */
    PG_TRY();
    {
        out_buf = (char *) palloc0(plaintext_len + TDE_SIV_OVERHEAD);

        /* Reuse the per-backend SIV encrypt context; allocate on first use. */
        if (tde_iam_siv_enc_ctx == NULL)
        {
            tde_iam_siv_enc_ctx = EVP_CIPHER_CTX_new();
            if (tde_iam_siv_enc_ctx == NULL)
            {
                pfree(out_buf);
                ereport(ERROR,
                        (errmsg("[IAM] Failed to create EVP_CIPHER_CTX for AES-SIV")));
            }
        }
        else
            EVP_CIPHER_CTX_reset(tde_iam_siv_enc_ctx);
        ctx = tde_iam_siv_enc_ctx;

        /*
         * Derive a 64-byte AES-256-SIV key from the 32-byte DEK.
         * AES-256-SIV requires two independent 256-bit keys; we obtain them
         * via PBKDF2-SHA256 with a static salt and 1 iteration (this is key
         * derivation, not password hashing — 1 iteration is intentional).
         */
        {
            unsigned char siv_key[64];

            if (PKCS5_PBKDF2_HMAC(dek, TDE_DEK_LEN,
                                   (const unsigned char *) "tde-siv", 7,
                                   1, EVP_sha256(), 64, siv_key) != 1)
            {
                EVP_CIPHER_CTX_free(tde_iam_siv_enc_ctx);
                tde_iam_siv_enc_ctx = NULL;
                ctx = NULL;
                pfree(out_buf);
                ereport(ERROR,
                        (errmsg("[IAM] PBKDF2 SIV key derivation failed")));
            }

            /*
             * AES-256-SIV via OpenSSL 3.x EVP AEAD (provider API):
             *  - Use pre-fetched cipher from hw_accel layer when available;
             *    fall back to EVP_CIPHER_fetch() otherwise (e.g. when QAT
             *    doesn't support SIV).
             *  - No IV argument for SIV (synthetic IV derived internally).
             *  - EVP_EncryptUpdate writes ciphertext into out_buf + overhead.
             *  - EVP_EncryptFinal_ex flushes remaining ciphertext bytes.
             *  - EVP_CTRL_AEAD_GET_TAG retrieves the 16-byte SIV and places
             *    it at out_buf[0..15]: [SIV-tag(16) | ciphertext(N)].
             */
            {
                const EVP_CIPHER *siv_cipher = tde_hw_accel_siv_cipher();
                EVP_CIPHER *siv_cipher_fetched = NULL;
                if (siv_cipher == NULL)
                {
                    siv_cipher_fetched = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
                    siv_cipher = siv_cipher_fetched;
                }
                if (siv_cipher == NULL)
                {
                    EVP_CIPHER_CTX_free(tde_iam_siv_enc_ctx);
                    tde_iam_siv_enc_ctx = NULL;
                    ctx = NULL;
                    OPENSSL_cleanse(siv_key, sizeof(siv_key));
                    OPENSSL_cleanse(out_buf, plaintext_len + TDE_SIV_OVERHEAD);
                    pfree(out_buf);
                    ereport(ERROR,
                            (errmsg("[IAM] AES-256-SIV cipher unavailable in this "
                                    "OpenSSL build; requires OpenSSL 3.x with "
                                    "default provider")));
                }

                if (EVP_EncryptInit_ex(ctx, siv_cipher, NULL,
                                       siv_key, NULL) != 1)
                {
                    if (siv_cipher_fetched)
                        EVP_CIPHER_free(siv_cipher_fetched);
                    EVP_CIPHER_CTX_free(tde_iam_siv_enc_ctx);
                    tde_iam_siv_enc_ctx = NULL;
                    ctx = NULL;
                    OPENSSL_cleanse(siv_key, sizeof(siv_key));
                    OPENSSL_cleanse(out_buf, plaintext_len + TDE_SIV_OVERHEAD);
                    pfree(out_buf);
                    ereport(ERROR,
                            (errmsg("[IAM] AES-256-SIV EncryptInit failed")));
                }
                if (siv_cipher_fetched)
                    EVP_CIPHER_free(siv_cipher_fetched);
            }

            if (EVP_EncryptUpdate(ctx,
                                  (unsigned char *) out_buf + TDE_SIV_OVERHEAD,
                                  &olen1,
                                  (const unsigned char *) plaintext,
                                  (int) plaintext_len) != 1 ||
                EVP_EncryptFinal_ex(ctx,
                                    (unsigned char *) out_buf + TDE_SIV_OVERHEAD + olen1,
                                    &olen2) != 1 ||
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                     TDE_SIV_OVERHEAD, out_buf) != 1)
            {
                EVP_CIPHER_CTX_free(tde_iam_siv_enc_ctx);
                tde_iam_siv_enc_ctx = NULL;
                ctx = NULL;
                OPENSSL_cleanse(siv_key, sizeof(siv_key));
                OPENSSL_cleanse(out_buf, plaintext_len + TDE_SIV_OVERHEAD);
                pfree(out_buf);
                ereport(ERROR,
                        (errmsg("[IAM] AES-256-SIV EncryptUpdate/Final/GetTag failed")));
            }

            OPENSSL_cleanse(siv_key, sizeof(siv_key));
        }

        /* ctx is kept alive in tde_iam_siv_enc_ctx for reuse — do NOT free here */

        *out_len = (Size)(TDE_SIV_OVERHEAD + olen1 + olen2);
    }
    PG_CATCH();
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        PG_RE_THROW();
    }
    PG_END_TRY();

    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    return out_buf;
}

/*
 * tde_iam_decrypt_key
 *
 * Decrypts an AES-256-SIV encrypted index key back to plaintext.
 * Returns a palloc'd buffer.  Caller MUST OPENSSL_cleanse + pfree after use.
 *
 * @param ciphertext      encrypted key buffer
 * @param ciphertext_len  length including SIV overhead
 * @param out_len         set to plaintext length on success
 * @returns               palloc'd plaintext buffer, or NULL on DEK miss
 */
char *
tde_iam_decrypt_key(const char *ciphertext, Size ciphertext_len, Size *out_len)
{
    EVP_CIPHER_CTX *ctx;
    char            dek[TDE_DEK_LEN];
    char           *out_buf = NULL;
    int             olen1 = 0,
                    olen2 = 0;

    Assert(ciphertext != NULL);
    Assert(out_len != NULL);

    if (ciphertext_len <= TDE_SIV_OVERHEAD)
        ereport(ERROR,
                (errmsg("[IAM] Ciphertext too short for AES-SIV decryption")));

    if (!pg_vault_tde_kms_get_dek(dek, TDE_DEK_LEN))
    {
        ereport(WARNING,
                (errmsg("[IAM] DEK unavailable for index key decryption")));
        return NULL;
    }

    /*
     * PG_TRY/PG_CATCH guarantees the DEK is wiped from the stack on ALL
     * exit paths — including palloc OOM between DEK acquisition and the
     * PBKDF2 derivation step.  Inner ereport(ERROR) calls longjmp into
     * PG_CATCH, so OPENSSL_cleanse runs before re-throw.
     */
    PG_TRY();
    {
        out_buf = (char *) palloc0(ciphertext_len);

        /* Reuse the per-backend SIV decrypt context; allocate on first use. */
        if (tde_iam_siv_dec_ctx == NULL)
        {
            tde_iam_siv_dec_ctx = EVP_CIPHER_CTX_new();
            if (tde_iam_siv_dec_ctx == NULL)
            {
                pfree(out_buf);
                ereport(ERROR,
                        (errmsg("[IAM] Failed to create EVP_CIPHER_CTX for AES-SIV")));
            }
        }
        else
            EVP_CIPHER_CTX_reset(tde_iam_siv_dec_ctx);
        ctx = tde_iam_siv_dec_ctx;

        {
            unsigned char siv_key[64];

            if (PKCS5_PBKDF2_HMAC(dek, TDE_DEK_LEN,
                                   (const unsigned char *) "tde-siv", 7,
                                   1, EVP_sha256(), 64, siv_key) != 1)
            {
                EVP_CIPHER_CTX_free(tde_iam_siv_dec_ctx);
                tde_iam_siv_dec_ctx = NULL;
                ctx = NULL;
                pfree(out_buf);
                ereport(ERROR,
                        (errmsg("[IAM] PBKDF2 SIV key derivation failed")));
            }

            /*
             * AES-256-SIV decryption via OpenSSL 3.x EVP AEAD (provider API):
             *  - Use pre-fetched cipher from hw_accel layer when available;
             *    fall back to per-call EVP_CIPHER_fetch() otherwise.
             *  - The first TDE_SIV_OVERHEAD bytes of ciphertext are the SIV tag.
             *  - Provide the tag BEFORE EVP_DecryptUpdate via SET_TAG.
             *  - EVP_DecryptFinal_ex returns <= 0 on auth failure;
             *    we treat that as a hard error (tampered index key).
             */
            {
                const EVP_CIPHER *siv_cipher = tde_hw_accel_siv_cipher();
                EVP_CIPHER *siv_cipher_fetched = NULL;
                if (siv_cipher == NULL)
                {
                    siv_cipher_fetched = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
                    siv_cipher = siv_cipher_fetched;
                }
                if (siv_cipher == NULL)
                {
                    EVP_CIPHER_CTX_free(tde_iam_siv_dec_ctx);
                    tde_iam_siv_dec_ctx = NULL;
                    ctx = NULL;
                    OPENSSL_cleanse(siv_key, sizeof(siv_key));
                    OPENSSL_cleanse(out_buf, ciphertext_len);
                    pfree(out_buf);
                    ereport(ERROR,
                            (errmsg("[IAM] AES-256-SIV cipher unavailable in this "
                                    "OpenSSL build; requires OpenSSL 3.x with "
                                    "default provider")));
                }

                if (EVP_DecryptInit_ex(ctx, siv_cipher, NULL,
                                       siv_key, NULL) != 1)
                {
                    if (siv_cipher_fetched)
                        EVP_CIPHER_free(siv_cipher_fetched);
                    EVP_CIPHER_CTX_free(tde_iam_siv_dec_ctx);
                    tde_iam_siv_dec_ctx = NULL;
                    ctx = NULL;
                    OPENSSL_cleanse(siv_key, sizeof(siv_key));
                    OPENSSL_cleanse(out_buf, ciphertext_len);
                    pfree(out_buf);
                    ereport(ERROR,
                            (errmsg("[IAM] AES-256-SIV DecryptInit failed")));
                }
                if (siv_cipher_fetched)
                    EVP_CIPHER_free(siv_cipher_fetched);
            }

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                     TDE_SIV_OVERHEAD,
                                     (void *) ciphertext) != 1 ||
                EVP_DecryptUpdate(ctx, (unsigned char *) out_buf, &olen1,
                                  (const unsigned char *) ciphertext + TDE_SIV_OVERHEAD,
                                  (int)(ciphertext_len - TDE_SIV_OVERHEAD)) != 1 ||
                EVP_DecryptFinal_ex(ctx,
                                    (unsigned char *) out_buf + olen1,
                                    &olen2) != 1)
            {
                EVP_CIPHER_CTX_free(tde_iam_siv_dec_ctx);
                tde_iam_siv_dec_ctx = NULL;
                ctx = NULL;
                OPENSSL_cleanse(siv_key, sizeof(siv_key));
                OPENSSL_cleanse(out_buf, ciphertext_len);
                pfree(out_buf);
                ereport(ERROR,
                        (errcode(ERRCODE_DATA_CORRUPTED),
                         errmsg("[IAM] AES-256-SIV authentication/decryption failed: "
                                "index key integrity violation or wrong DEK")));
            }

            OPENSSL_cleanse(siv_key, sizeof(siv_key));
        }

        /* ctx is kept alive in tde_iam_siv_dec_ctx for reuse — do NOT free here */

        *out_len = (Size)(olen1 + olen2);
    }
    PG_CATCH();
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        PG_RE_THROW();
    }
    PG_END_TRY();

    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    return out_buf;
}

/*
 * ================================================================
 * tde_btree full wiring (v1.4)
 *
 * Architecture
 * -----------
 * tde_btree wraps the standard btree AM.  At _PG_init() time,
 * tde_iam_init() copies the btree IndexAmRoutine into a mutable struct
 * (tde_btree_methods) and overrides the four key-touching callbacks:
 *
 *   ambuild     — scan heap, AES-SIV encrypt each indexed datum, spool
 *                 into btree's sorted bulk-loader
 *   aminsert    — encrypt values[] datums before delegating to btree
 *   ambeginscan — delegate to btree (no crypto at scan-open time)
 *   amrescan    — encrypt equality scan keys (BTEqualStrategyNumber=3)
 *                 before delegating to btree; range keys pass through
 *                 unchanged (range scans produce incomplete results —
 *                 documented limitation)
 *
 * v1.4 supports bytea-typed index columns only (or expression indexes
 * that return bytea).  The operator class tde_bytea_ops is registered
 * as the default for type bytea using tde_btree (see pg_vault_tde--1.0.sql).
 *
 * The btree spool functions (_bt_spoolinit, _bt_spool, _bt_leafbuild,
 * _bt_spoolfreeall) are exported from nbtree.h and used here to give
 * tde_btree's CREATE INDEX the same sorted-bulk-load performance as
 * native btree.
 * ================================================================
 */

/* Mutable copy of the btree AM routine, patched with our overrides */
static IndexAmRoutine  tde_btree_methods;

/* Original btree AM pointer — saved for delegation */
static IndexAmRoutine *saved_btree_am = NULL;

/*
 * tde_encrypt_bytea_datum
 *
 * Encrypts a bytea Datum using AES-256-SIV.
 * Returns a new palloc'd bytea Datum with the encrypted content,
 * or the original Datum unchanged if DEK is unavailable (degraded mode).
 *
 * Caller is responsible for pfree'ing the result when done.
 */
static Datum
tde_encrypt_bytea_datum(Datum datum)
{
    bytea  *bval    = DatumGetByteaPP(datum);
    char   *plain   = VARDATA_ANY(bval);
    Size    plen    = VARSIZE_ANY_EXHDR(bval);
    Size    enc_len = 0;
    char   *encrypted;
    bytea  *enc_bytea;

    encrypted = tde_iam_encrypt_key(plain, plen, &enc_len);
    if (encrypted == NULL)
    {
        /*
         * DEK not available.  Log a warning and pass the plaintext through
         * unchanged.  This means the index entry will be unencrypted; the
         * TAM-layer encryption of the heap tuple is still intact.
         */
        ereport(WARNING,
                (errmsg("[IAM] DEK unavailable during index insert — "
                        "index key stored unencrypted")));
        return datum;
    }

    enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
    SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
    memcpy(VARDATA(enc_bytea), encrypted, enc_len);

    OPENSSL_cleanse(encrypted, enc_len);
    pfree(encrypted);

    return PointerGetDatum(enc_bytea);
}

/* ── BUILD CALLBACK ─────────────────────────────────────────────────────── */

typedef struct TdeBuildState
{
    BTSpool    *spool;        /* btree sorted-bulk-load spool */
    IndexInfo  *indexInfo;    /* column count, uniqueness, etc. */
    Relation    heapRel;      /* heap being indexed */
    double      index_tuples; /* counter for stats */
} TdeBuildState;

/*
 * tde_build_callback
 *
 * Called by IndexBuildHeapScan for each live heap tuple.  Encrypts each
 * indexed bytea column via AES-256-SIV and spools the encrypted key into
 * the btree sorted bulk-loader.
 */
static void
tde_build_callback(Relation indexRel, ItemPointer tid,
                   Datum *values, bool *isnull,
                   bool tupleIsAlive, void *state)
{
    TdeBuildState *bstate = (TdeBuildState *) state;
    Datum          enc_values[INDEX_MAX_KEYS];
    bool           enc_isnull[INDEX_MAX_KEYS];
    int            ncols = bstate->indexInfo->ii_NumIndexAttrs;
    int            i;

    if (!tupleIsAlive)
        return;

    memcpy(enc_isnull, isnull, ncols * sizeof(bool));

    for (i = 0; i < ncols; i++)
    {
        if (isnull[i])
            enc_values[i] = (Datum) 0;
        else
            enc_values[i] = tde_encrypt_bytea_datum(values[i]);
    }

    /*
     * Feed the encrypted tuple into the btree spool.  _bt_spool buffers
     * items in a sort file; _bt_leafbuild (called after the scan) writes
     * all sorted items to the btree pages in one pass.
     */
    _bt_spool(bstate->spool, tid, enc_values, enc_isnull);
    bstate->index_tuples++;
}

/* ── AMBUILD ────────────────────────────────────────────────────────────── */

static IndexBuildResult *
pg_vault_tde_ambuild(Relation heap, Relation index, IndexInfo *index_info)
{
    IndexBuildResult *result;
    TdeBuildState     bstate;
    double            ntuples;

    Assert(saved_btree_am != NULL);

    result = (IndexBuildResult *) palloc0(sizeof(IndexBuildResult));

    /*
     * Create the btree spool: a sorted temporary file that will become
     * the index pages via _bt_leafbuild at the end.  Using the spool
     * (rather than one-at-a-time aminsert calls) gives the same
     * sorted-bulk-load performance as native btree CREATE INDEX.
     *
     * _bt_spoolinit(heap, index, isunique, isdead)
     *   isunique = index_info->ii_Unique (respect UNIQUE constraint)
     *   isdead   = false (for the non-concurrent, non-dead-tuple spool)
     */
    bstate.spool       = _bt_spoolinit(heap, index,
                                       index_info->ii_Unique, false);
    bstate.indexInfo   = index_info;
    bstate.heapRel     = heap;
    bstate.index_tuples = 0;

    /*
     * Heap scan: visits every live tuple and calls tde_build_callback
     * which encrypts the datums and _bt_spool()s them.
     */
    ntuples = table_index_build_scan(heap, index, index_info,
                                     true,  /* allow_sync */
                                     true,  /* report_progress */
                                     tde_build_callback,
                                     &bstate,
                                     NULL   /* existing TableScanDesc */);

    /*
     * Sort the spool and write all index pages in a single sorted pass.
     * The second argument is the "dead-tuple" spool — NULL for non-concurrent
     * builds.
     */
    _bt_leafbuild(bstate.spool, NULL);
    _bt_spoolfreeall(bstate.spool);

    result->heap_tuples  = ntuples;
    result->index_tuples = bstate.index_tuples;

    ereport(DEBUG1,
            (errmsg("[IAM] tde_btree ambuild: %.0f heap tuples, %.0f index tuples",
                    ntuples, bstate.index_tuples)));

    return result;
}

/* ── AMINSERT ───────────────────────────────────────────────────────────── */

static bool
pg_vault_tde_aminsert(Relation index, Datum *values, bool *isnull,
                      ItemPointer heap_tid, Relation heap,
                      IndexUniqueCheck check_unique,
                      bool index_unchanged,
                      IndexInfo *index_info)
{
    Datum   enc_values[INDEX_MAX_KEYS];
    bool    enc_isnull[INDEX_MAX_KEYS];
    int     ncols = index_info->ii_NumIndexAttrs;
    int     i;

    Assert(saved_btree_am != NULL);

    memcpy(enc_isnull, isnull, ncols * sizeof(bool));

    /* Encrypt each non-null bytea indexed column */
    for (i = 0; i < ncols; i++)
    {
        if (isnull[i])
            enc_values[i] = (Datum) 0;
        else
            enc_values[i] = tde_encrypt_bytea_datum(values[i]);
    }

    return saved_btree_am->aminsert(index, enc_values, enc_isnull,
                                    heap_tid, heap,
                                    check_unique, index_unchanged,
                                    index_info);
}

/* ── AMBEGINSCAN ────────────────────────────────────────────────────────── */

static IndexScanDesc
pg_vault_tde_ambeginscan(Relation index, int nkeys, int norderbys)
{
    /*
     * Delegate entirely to btree.  The ScanKey encryption happens in
     * amrescan, called immediately after by the executor.
     */
    Assert(saved_btree_am != NULL);
    return saved_btree_am->ambeginscan(index, nkeys, norderbys);
}

/* ── AMRESCAN ───────────────────────────────────────────────────────────── */

static void
pg_vault_tde_amrescan(IndexScanDesc scan, ScanKey keys, int nkeys,
                      ScanKey orderbys, int norderbys)
{
    int i;

    Assert(saved_btree_am != NULL);

    /*
     * Encrypt equality scan keys (strategy == BTEqualStrategyNumber = 3)
     * so they match the encrypted values stored in the index.
     *
     * Range scan keys (strategy != 3) are passed through unchanged.
     * They will produce incorrect or empty results because AES-SIV
     * encrypted values do not preserve ordering — this is the documented
     * v1.4 limitation of tde_btree.
     */
    if (keys != NULL)
    {
        for (i = 0; i < nkeys; i++)
        {
            if ((keys[i].sk_flags & SK_ISNULL) == 0 &&
                keys[i].sk_strategy == BTEqualStrategyNumber)
            {
                keys[i].sk_argument =
                    tde_encrypt_bytea_datum(keys[i].sk_argument);
            }
        }
    }

    saved_btree_am->amrescan(scan, keys, nkeys, orderbys, norderbys);
}

/* ── INIT + HANDLER ─────────────────────────────────────────────────────── */

/*
 * tde_iam_init
 *
 * Copies the btree IndexAmRoutine into our mutable tde_btree_methods
 * struct and overrides the four key-manipulating callbacks.  Must be
 * called from _PG_init() exactly once, after GUC registration and before
 * any index operation.
 *
 * Uses F_BTHANDLER (OID 330 from utils/fmgroids.h) to call the btree
 * handler function directly, which is the same mechanism PostgreSQL uses
 * internally when it creates a btree-backed index.
 */
void
tde_iam_init(void)
{
    /*
     * Call the btree handler function to get a freshly allocated
     * IndexAmRoutine populated with all btree callbacks.
     * PointerGetDatum(NULL) passes a null 'internal' argument, which is
     * what bthandler() expects (it ignores it).
     */
    saved_btree_am = (IndexAmRoutine *) DatumGetPointer(
        OidFunctionCall1(F_BTHANDLER, PointerGetDatum(NULL)));

    Assert(saved_btree_am != NULL);
    Assert(saved_btree_am->type == T_IndexAmRoutine);

    /* Base: copy ALL btree callbacks so we inherit everything by default */
    memcpy(&tde_btree_methods, saved_btree_am, sizeof(IndexAmRoutine));

    /* Override the callbacks that need to see or produce encrypted keys */
    tde_btree_methods.ambuild     = pg_vault_tde_ambuild;
    tde_btree_methods.aminsert    = pg_vault_tde_aminsert;
    tde_btree_methods.ambeginscan = pg_vault_tde_ambeginscan;
    tde_btree_methods.amrescan    = pg_vault_tde_amrescan;

    ereport(DEBUG1,
            (errmsg("[IAM] tde_btree initialized: btree AM wrapped with "
                    "AES-256-SIV encryption layer")));
}

/*
 * pg_vault_tde_get_iam_routine
 *
 * Returns a pointer to tde_btree_methods for the handler function.
 * If tde_iam_init() has not yet been called (e.g. during pg_dump or
 * a direct pg_vault_tde_iam_handler call without shared_preload_libraries),
 * it is called here as a lazy initializer to ensure the struct is valid.
 */
extern const IndexAmRoutine *pg_vault_tde_get_iam_routine(void);
const IndexAmRoutine *
pg_vault_tde_get_iam_routine(void)
{
    if (saved_btree_am == NULL)
        tde_iam_init();
    return &tde_btree_methods;
}
