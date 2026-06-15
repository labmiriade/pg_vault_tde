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
#include "utils/syscache.h"     /* SearchSysCache1, ReleaseSysCache, CLAOID */
#include "utils/uuid.h"         /* DatumGetUUIDP, pg_uuid_t */
#include "catalog/pg_opclass.h" /* Form_pg_opclass */
#include "storage/lwlock.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>

/*
 * Index build strategy: ambuildempty + per-row aminsert
 *
 * tde_btree's CREATE INDEX does NOT use the private btree sort API
 * (_bt_spoolinit / _bt_spool / _bt_leafbuild / _bt_spoolfreeall).  Those
 * symbols are defined as "static" in PostgreSQL's nbtsort.c and are therefore
 * NOT exported from the postgres binary on any platform — linking against them
 * produces an undefined-symbol FATAL at load time on debian/ubuntu packages.
 *
 * Instead, we use the public IndexAmRoutine callbacks:
 *   1. saved_btree_methods.ambuildempty(index) — creates a valid empty btree
 *      (metapage + empty root page) via WAL-safe btree initialisation.
 *   2. table_index_build_scan() with tde_build_callback() — visits each
 *      heap tuple, encrypts the key datums, and calls aminsert() one-by-one.
 *
 * Trade-off: slightly more page splits than the sorted bulk-load path
 * (O(n) sequential writes vs O(n log n) sorted writes), but fully portable
 * and correct.  For CREATE INDEX on an empty table the cost is zero.
 *
 * PKCS5_PBKDF2_HMAC is declared in openssl/evp.h (included above).
 */
#include "src/include/pg_vault_tde_catalog.h"
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
tde_iam_encrypt_key(const char* dek, int dek_len, 
                    const char *plaintext, Size plaintext_len, Size *out_len)
{
    EVP_CIPHER_CTX *ctx;
    char           *out_buf = NULL;
    int             olen1 = 0,
                    olen2 = 0;

    Assert(plaintext != NULL);
    Assert(out_len != NULL);

    /*
     * PG_TRY/PG_CATCH guarantees the DEK is wiped from the stack on ALL
     * exit paths — including palloc OOM between DEK acquisition and the
     * PBKDF2 derivation step.  Inner ereport(ERROR) calls longjmp into
     * PG_CATCH, so OPENSSL_cleanse runs before re-throw.
     */
    PG_TRY();
    {
        out_buf = (char *) palloc0(plaintext_len + TDE_SIV_OVERHEAD);

        /*
         * Reuse the per-backend SIV encrypt context; allocate on first use.
         *
         * Allocate in TopMemoryContext so the EVP_CIPHER_CTX survives
         * for the lifetime of the backend.  During index builds this
         * function is called from pg_vault_tde_index_build_range_scan
         * where the per-tuple memory context may be reset between rows;
         * allocating in TopMemoryContext ensures the context pointer
         * (tde_iam_siv_enc_ctx) remains valid across iterations.
         */
        if (tde_iam_siv_enc_ctx == NULL)
        {
            MemoryContext old_ctx = MemoryContextSwitchTo(TopMemoryContext);
            tde_iam_siv_enc_ctx = EVP_CIPHER_CTX_new();
            MemoryContextSwitchTo(old_ctx);
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

            if (PKCS5_PBKDF2_HMAC(dek, dek_len,
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
        PG_RE_THROW();
    }
    PG_END_TRY();

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
tde_iam_decrypt_key(const char* dek, int dek_len, 
                    const char *ciphertext, Size ciphertext_len, Size *out_len)
{
    EVP_CIPHER_CTX *ctx;
    char           *out_buf = NULL;
    int             olen1 = 0,
                    olen2 = 0;

    Assert(ciphertext != NULL);
    Assert(out_len != NULL);

    if (ciphertext_len <= TDE_SIV_OVERHEAD)
        ereport(ERROR,
                (errmsg("[IAM] Ciphertext too short for AES-SIV decryption")));

    /*
     * PG_TRY/PG_CATCH guarantees the DEK is wiped from the stack on ALL
     * exit paths — including palloc OOM between DEK acquisition and the
     * PBKDF2 derivation step.  Inner ereport(ERROR) calls longjmp into
     * PG_CATCH, so OPENSSL_cleanse runs before re-throw.
     */
    PG_TRY();
    {
        out_buf = (char *) palloc0(ciphertext_len);

        /*
         * Reuse the per-backend SIV decrypt context; allocate in
         * TopMemoryContext (same rationale as the encrypt context above).
         */
        if (tde_iam_siv_dec_ctx == NULL)
        {
            MemoryContext old_ctx = MemoryContextSwitchTo(TopMemoryContext);
            tde_iam_siv_dec_ctx = EVP_CIPHER_CTX_new();
            MemoryContextSwitchTo(old_ctx);
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

            if (PKCS5_PBKDF2_HMAC(dek, dek_len,
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
        PG_RE_THROW();
    }
    PG_END_TRY();

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
 * Index build uses ambuildempty + per-row aminsert (portable; see the
 * build strategy comment near the top of this file for rationale).
 * ================================================================
 */

/* Mutable copy of the btree AM routine, patched with our overrides */
static IndexAmRoutine  tde_btree_methods;

/*
 * Original (unmodified) btree AM — saved as a STATIC copy for delegation.
 *
 * Previously this was a POINTER (saved_btree_am) to a palloc'd struct
 * from _PG_init() in the POSTMASTER.  That pointer became stale in forked
 * backends because the heap block could be freed/overwritten by later
 * allocations, causing SIGSEGV when pg_vault_tde_ambuild tried to call
 * saved_btree_am->ambuild.
 *
 * Storing the full struct in BSS ensures all function pointers are
 * reliably inherited by forked backends (COW pages never change for
 * a static that is only written during _PG_init).
 */
static IndexAmRoutine  saved_btree_methods;
static bool            saved_btree_methods_valid = false;

/*
 * tde_iam_build_in_progress — process-local flag (see pg_vault_tde_iam.h).
 * Set while pg_vault_tde_ambuild is executing saved_btree_methods.ambuild
 * so pg_vault_tde_index_build_range_scan (tam.c) knows to encrypt index keys.
 */
bool tde_iam_build_in_progress = false;

/*
 * tde_iam_serialize_fixed_type
 *
 * Writes the canonical big-endian byte representation of `datum` for
 * the given `typoid` into `buf` (caller-supplied, must be ≥ 16 bytes).
 * Returns the number of bytes written, or 0 if typoid is unknown.
 *
 * Big-endian is used for int4/int8/date/timestamptz to guarantee
 * identical serialisation across x86 (little-endian) and aarch64 (BE/LE).
 * UUID is treated as a 16-byte opaque byte array (RFC 4122 representation).
 *
 * MUST NOT palloc — called from tight index-build loops.
 */
static Size
tde_iam_serialize_fixed_type(Datum datum, Oid typoid, uint8 *buf)
{
    switch (typoid)
    {
        case INT4OID:
        case DATEOID:
        {
            /* DateADT is typedef int32 — same serialisation as int4 */
            uint32 v = pg_hton32((uint32) DatumGetInt32(datum));
            memcpy(buf, &v, 4);
            return 4;
        }
        case INT8OID:
        case TIMESTAMPTZOID:
        {
            /* TimestampTz is typedef int64 — same serialisation as int8 */
            uint64 v = pg_hton64((uint64) DatumGetInt64(datum));
            memcpy(buf, &v, 8);
            return 8;
        }
        case UUIDOID:
        {
            /*
             * DatumGetUUIDP returns a pointer to pg_uuid_t whose 'data'
             * field is the 16 raw UUID bytes in RFC 4122 network byte order
             * (already big-endian for every field).
             */
            pg_uuid_t *uid = DatumGetUUIDP(datum);
            memcpy(buf, uid->data, 16);
            return 16;
        }
        default:
            return 0;   /* caller falls back to the varlena path */
    }
}

/*
 * tde_iam_encrypt_fixed_type_datum
 *
 * Encrypts a fixed-size typed Datum using AES-256-SIV.
 * Called from aminsert, amrescan, and index_build_range_scan when an
 * index attribute uses a tde_*_enc_ops operator class (detected by
 * rd_att[i].atttypid == BYTEAOID && rd_opcintype[i] != BYTEAOID).
 *
 * Returns a palloc'd bytea Datum ready for btree storage.
 * On DEK unavailability, emits a WARNING and returns the original datum
 * unchanged (index key stored unencrypted; heap still TAM-encrypted).
 *
 * The 16-byte stack buffer `plain_buf` is cleansed before return.
 */
Datum
tde_iam_encrypt_fixed_type_datum(Relation index_rel, Datum datum, Oid typoid)
{
    uint8   plain_buf[16];   /* max 16 bytes for uuid */
    Size    plain_len;
    Size    enc_len    = 0;
    char   *encrypted;
    bytea  *enc_bytea;

    unsigned char dek[TDE_DEK_LEN];

    plain_len = tde_iam_serialize_fixed_type(datum, typoid, plain_buf);

    if (plain_len == 0)
    {
        ereport(WARNING,
                (errmsg("[IAM] tde_iam_encrypt_fixed_type_datum: "
                        "unknown typoid %u, skipping encryption", typoid)));
        return datum;
    }

    if(!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
    {
        ereport(ERROR, 
                (errmsg("[IAM] tde_iam_encrypt_fixed_type_datum: "
                        "DEK unavailable for index rel: %u", RelationGetRelid(index_rel))));
    }

    encrypted = tde_iam_encrypt_key((const char *)dek, sizeof(dek), (const char *) plain_buf, plain_len, &enc_len);
    OPENSSL_cleanse(plain_buf, sizeof(plain_buf));

    if (encrypted == NULL)
    {
        ereport(WARNING,
                (errmsg("[IAM] DEK unavailable during index insert — "
                        "fixed-type index key stored unencrypted (typoid=%u)", typoid)));

        OPENSSL_cleanse(dek, sizeof(dek));
        return datum;
    }

    enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
    SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
    memcpy(VARDATA(enc_bytea), encrypted, enc_len);

    OPENSSL_cleanse(dek, sizeof(dek));
    OPENSSL_cleanse(encrypted, enc_len);

    /*
     * Do NOT pfree(encrypted) — let ecxt_per_tuple_memory reset handle it.
     * See comment in tde_iam_encrypt_index_datum for rationale.
     */

    return PointerGetDatum(enc_bytea);
}

/*
 * tde_iam_encrypt_index_datum
 *
 * Encrypts a typed Datum using AES-256-SIV.
 * Returns a new palloc'd bytea Datum with the encrypted content,
 * or the original Datum unchanged if DEK is unavailable (degraded mode).
 *
 * typbyval / typlen must come from the relevant Form_pg_attribute so that
 * pass-by-value types (int4, int8, date, timestamptz, bool) are serialised
 * from the Datum scalar — NOT detoasted as varlena, which would SIGSEGV on
 * small fixed-size types because the datum value is not a pointer.
 *
 * Called from pg_vault_tde_index_build_range_scan (tam.c) when
 * tde_iam_build_in_progress is set, and from pg_vault_tde_aminsert /
 * pg_vault_tde_amrescan for individual INSERTs and index scans.
 *
 * Caller is responsible for pfree'ing the result when done.
 */
Datum
tde_iam_encrypt_index_datum(Relation index_rel, Datum datum, bool typbyval, int16 typlen)
{

    /*
     * Serialise the Datum to a byte array according to type storage class:
     *
     * typbyval=true, typlen>0 — pass-by-value scalar (int4, int8, bool …).
     *   btree stores these directly by value (4 or 8 bytes in the IndexTuple).
     *   We CANNOT substitute a bytea Datum because btree's heap_form_tuple
     *   logic would store the lower N bytes of the bytea POINTER, not the
     *   ciphertext bytes.  Index keys for these types are stored UNENCRYPTED;
     *   the heap tuple itself is always encrypted by the TAM layer.
     *
     * typbyval=false, typlen>0 — fixed-length pass-by-reference (e.g. uuid).
     *   Same constraint: btree copies exactly typlen bytes from DatumGetPointer.
     *   We cannot change the stored size, so index keys are stored UNENCRYPTED.
     *
     * typbyval=false, typlen=-1 — variable-length varlena (text, numeric …).
     *   btree stores the full varlena inline.  We can substitute an enc_bytea
     *   varlena of different size.  AES-SIV is deterministic, so equal
     *   plaintexts → equal ciphertexts → equality comparison still works.
     *   THIS IS THE ONLY PATH THAT ENCRYPTS INDEX KEYS.
     *
     * typbyval=false, typlen=-2 — C string.  Same varlena-like treatment.
     *
     * Known limitation (v1.5): tde_int4_ops, tde_int8_ops, tde_uuid_ops,
     * tde_date_ops, tde_timestamptz_ops store index keys in plaintext.
     * The heap tuples are always encrypted by the TAM.  This limitation
     * will be addressed in v1.6 using a separate per-column encrypted
     * index type with CAST(int4 → bytea) at the access-method level.
     */
    if (typlen != -1 && typlen != -2)
    {
        /*
         * Fixed-size or pass-by-value type: cannot change the wire format.
         * Return the datum unchanged; the heap is still TAM-encrypted.
         */
        ereport(DEBUG2,
                (errmsg("[IAM] Skipping index key encryption for "
                        "fixed-size column (typlen=%d, typbyval=%s); "
                        "heap tuple is still encrypted by the TAM.",
                        (int) typlen, typbyval ? "true" : "false")));
        return datum;
    }

    /* varlena (or C-string) path — full AES-256-SIV encryption below */
    {
        bytea      *bval       = NULL;
        const char *plain;
        Size        plen;
        Size        enc_len    = 0;
        char       *encrypted;
        bytea      *enc_bytea;
        unsigned char dek[TDE_DEK_LEN];

        if (typlen == -1)
        {
            /*
             * PG_DETOAST_DATUM_COPY allocates a private palloc'd copy in
             * CurrentMemoryContext.  Using COPY (not DatumGetByteaPP)
             * prevents use-after-free if the calling context is reset
             * between iterations.  The copy is reclaimed by context reset.
             */
            bval  = (bytea *) PG_DETOAST_DATUM_COPY(datum);
            plain = VARDATA_ANY(bval);
            plen  = VARSIZE_ANY_EXHDR(bval);
        }
        else
        {
            /* typlen == -2: C string */
            plain = DatumGetCString(datum);
            plen  = strlen(plain) + 1;   /* include null terminator */
        }   

        if(!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
        {
            ereport(ERROR, 
                    errmsg("[IAM] tde_iam_encrypt_index_datum: "
                           "DEK unavailable for index relid %u", RelationGetRelid(index_rel)));
        }
        encrypted = tde_iam_encrypt_key((const char *)dek, sizeof(dek), plain, plen, &enc_len);

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

            OPENSSL_cleanse(dek, sizeof(dek));
            return datum;
        }

        enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
        SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
        memcpy(VARDATA(enc_bytea), encrypted, enc_len);

        OPENSSL_cleanse(encrypted, enc_len);
        OPENSSL_cleanse(dek, sizeof(dek));
        /*
         * Do NOT pfree(encrypted) here — let ecxt_per_tuple_memory reset
         * reclaim it.  Avoiding manual pfree prevents double-free risks
         * when the context is reset right after this function returns.
         */

        return PointerGetDatum(enc_bytea);
    }
}

/* ── BUILD CALLBACK ─────────────────────────────────────────────────────── */

/* ── AMBUILD ────────────────────────────────────────────────────────────── */

/*
 * pg_vault_tde_ambuild
 *
 * Delegates entirely to btree's ambuild but sets tde_iam_build_in_progress
 * first so that pg_vault_tde_index_build_range_scan (tam.c) will encrypt
 * index key values before passing them to btbuildCallback.
 *
 * This approach avoids the private btree spool API (_bt_spoolinit, etc.) and
 * the single-row aminsert approach (which does not work correctly because
 * btbuildempty only initialises the INIT fork, leaving MAIN fork pages
 * absent when btinsert tries to locate the index metapage).
 *
 * Flow:
 *   pg_vault_tde_ambuild
 *     → saved_btree_methods.ambuild (= btbuild)
 *       → table_index_build_scan(heap, index, ..., btbuildCallback, ...)
 *         → pg_vault_tde_index_build_range_scan (via heap's TableAmRoutine)
 *           → [for each tuple] encrypt values[], then btbuildCallback(...)
 *
 * tde_iam_build_in_progress is a process-local (not thread-local) variable;
 * PostgreSQL is multi-process, so concurrent backends are unaffected.
 */
static IndexBuildResult *
pg_vault_tde_ambuild(Relation heap, Relation index, IndexInfo *index_info)
{
    IndexBuildResult *result;

    Assert(saved_btree_methods_valid);

    /*
     * Signal pg_vault_tde_index_build_range_scan to encrypt index keys.
     * PG_TRY ensures the flag is cleared even if btbuild raises an error.
     */
    tde_iam_build_in_progress = true;

    PG_TRY();
    {
        result = saved_btree_methods.ambuild(heap, index, index_info);
    }
    PG_CATCH();
    {
        tde_iam_build_in_progress = false;
        PG_RE_THROW();
    }
    PG_END_TRY();
    tde_iam_build_in_progress = false;

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

    Assert(saved_btree_methods_valid);

    memcpy(enc_isnull, isnull, ncols * sizeof(bool));

    /* Encrypt each non-null indexed column */
    for (i = 0; i < ncols; i++)
    {
        if (isnull[i])
        {
            enc_values[i] = (Datum) 0;
        }
        else if (TDE_IS_ENC_OPS_COL(index, i))
        {
            enc_values[i] = tde_iam_encrypt_fixed_type_datum(
                                index,
                                values[i],
                                index->rd_opcintype[i]);
        }
        else
        {
            Form_pg_attribute att = TupleDescAttr(index->rd_att, i);

            enc_values[i] = tde_iam_encrypt_index_datum(index,
                                                        values[i],
                                                         att->attbyval,
                                                         att->attlen);
        }
    }

    return saved_btree_methods.aminsert(index, enc_values, enc_isnull,
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
    Assert(saved_btree_methods_valid);
    return saved_btree_methods.ambeginscan(index, nkeys, norderbys);
}

/* ── AMRESCAN ───────────────────────────────────────────────────────────── */

static void
pg_vault_tde_amrescan(IndexScanDesc scan, ScanKey keys, int nkeys,
                      ScanKey orderbys, int norderbys)
{
    int i;

    Assert(saved_btree_methods_valid);

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
                int col = keys[i].sk_attno - 1;

                if (TDE_IS_ENC_OPS_COL(scan->indexRelation, col))
                {
                    keys[i].sk_argument =
                        tde_iam_encrypt_fixed_type_datum(scan->indexRelation, keys[i].sk_argument, scan->indexRelation->rd_opcintype[col]);

                    /* Set the sk_func (boolean cmp function for rd_opcintype) to the bytea one*/
                    fmgr_info(F_BYTEAEQ, &keys[i].sk_func); 
                }
                else
                {
                    Form_pg_attribute att = TupleDescAttr(scan->indexRelation->rd_att, col);
                    keys[i].sk_argument =
                        tde_iam_encrypt_index_datum(scan->indexRelation,
                                                    keys[i].sk_argument,
                                                    att->attbyval,
                                                    att->attlen);
                }
            }
        }
    }

    saved_btree_methods.amrescan(scan, keys, nkeys, orderbys, norderbys);
}

/* ── AMVALIDATE ─────────────────────────────────────────────────────────── */

/*
 * pg_vault_tde_amvalidate
 *
 * Validates an operator class.  For standard tde_*_ops classes (no STORAGE
 * override) this delegates to btvalidate.  For tde_*_enc_ops classes
 * (opckeytype = BYTEAOID, opcintype ≠ BYTEAOID) we return true directly:
 * those classes register strategy operators with the original column type
 * (e.g. int4 = int4) instead of (bytea = bytea), so btvalidate would reject
 * them, but they are correct by construction.
 */
static bool
pg_vault_tde_amvalidate(Oid opclassoid)
{
    HeapTuple       classtup;
    Form_pg_opclass classform;
    bool            is_enc_ops;

    Assert(saved_btree_methods_valid);

    /*
     * enc_ops operator classes (tde_int4_enc_ops, tde_int8_enc_ops, etc.)
     * register their strategy operators with the original column type
     * (int4, int8, …) so the planner can match equality clauses against
     * the index.  btvalidate, however, expects operator types to equal
     * opckeytype (BYTEAOID) when STORAGE bytea is set and would emit
     * warnings and return false.  Skip btvalidate for these classes; they
     * are valid by construction.
     *
     * Detection: enc_ops classes have opckeytype = BYTEAOID and
     * opcintype ≠ BYTEAOID.  Plain tde_*_ops and tde_text_ops have
     * opckeytype = InvalidOid (same as opcintype), so they delegate
     * normally.
     */
    classtup = SearchSysCache1(CLAOID, ObjectIdGetDatum(opclassoid));
    if (!HeapTupleIsValid(classtup))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("cache lookup failed for operator class %u",
                        opclassoid)));

    classform = (Form_pg_opclass) GETSTRUCT(classtup);
    is_enc_ops = (OidIsValid(classform->opckeytype) &&
                  classform->opckeytype == BYTEAOID &&
                  classform->opcintype  != BYTEAOID);
    ReleaseSysCache(classtup);

    if (is_enc_ops)
        return true;

    return saved_btree_methods.amvalidate(opclassoid);
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
    IndexAmRoutine *tmp = (IndexAmRoutine *) DatumGetPointer(
        OidFunctionCall1(F_BTHANDLER, PointerGetDatum(NULL)));

    Assert(tmp != NULL);
    Assert(tmp->type == T_IndexAmRoutine);

    /*
     * Copy the btree callbacks into TWO static structs:
     *  - saved_btree_methods: unchanged original, used for delegation
     *  - tde_btree_methods:   patched copy returned to PG via handler
     *
     * Both are BSS statics, so their content is reliably inherited by
     * forked backends (no stale heap pointers).
     */
    memcpy(&saved_btree_methods, tmp, sizeof(IndexAmRoutine));
    memcpy(&tde_btree_methods, tmp, sizeof(IndexAmRoutine));

    /* Safe to free now — we've memcpy'd everything we need */
    pfree(tmp);

    saved_btree_methods_valid = true;

    /* Override the callbacks that need to see or produce encrypted keys */
    tde_btree_methods.ambuild     = pg_vault_tde_ambuild;
    tde_btree_methods.aminsert    = pg_vault_tde_aminsert;
    tde_btree_methods.ambeginscan = pg_vault_tde_ambeginscan;
    tde_btree_methods.amrescan    = pg_vault_tde_amrescan;
    tde_btree_methods.amvalidate  = pg_vault_tde_amvalidate;


    /* Encrypted tuples are unencryptable only if they comes from the table */
    tde_btree_methods.amcanreturn = NULL;

    /*
     * Allow STORAGE type ≠ opcintype for tde_*_enc_ops operator classes.
     * Standard btree sets amstorage=false; we need true so that
     * CREATE OPERATOR CLASS ... STORAGE bytea does not fail with
     * "storage type cannot be different from data type".
     */
    tde_btree_methods.amstorage   = true;

    ereport(DEBUG1,
            (errmsg("[IAM] tde_btree initialized: btree AM wrapped with "
                    "AES-256-SIV encryption layer")));
}

/*
 * pg_vault_tde_get_iam_routine
 *
 * Returns a palloc'd copy of tde_btree_methods for the handler function.
 *
 * PostgreSQL's InitIndexAmRoutine() calls GetIndexAmRoutine() to obtain
 * the IndexAmRoutine struct, copies it into rd_indexcxt, then pfree()'s
 * the original pointer.  If we returned &tde_btree_methods (a static BSS
 * variable), pfree would crash with "invalid pointer (header 0x0)".
 * Therefore we must return a freshly palloc'd copy that pfree can safely
 * reclaim.
 *
 * If tde_iam_init() has not yet been called (e.g. during pg_dump or
 * a direct pg_vault_tde_iam_handler call without shared_preload_libraries),
 * it is called here as a lazy initializer to ensure the struct is valid.
 */
extern const IndexAmRoutine *pg_vault_tde_get_iam_routine(void);
const IndexAmRoutine *
pg_vault_tde_get_iam_routine(void)
{
    IndexAmRoutine *result;

    if (!saved_btree_methods_valid)
        tde_iam_init();

    result = (IndexAmRoutine *) palloc(sizeof(IndexAmRoutine));
    memcpy(result, &tde_btree_methods, sizeof(IndexAmRoutine));
    return result;
}

/*
 * tde_enc_bytea_cmp
 *
 * B-Tree support function 1 (three-way comparator) for tde_*_enc_ops
 * operator classes.  Both arguments are AES-256-SIV ciphertexts of the
 * same length (20, 24, or 32 bytes depending on the original type).
 *
 * AES-SIV is deterministic: equal plaintexts → equal ciphertexts under
 * the same DEK.  The memcmp order has no semantic meaning; range scans
 * on enc_ops indexes return arbitrary results (documented limitation).
 */
PG_FUNCTION_INFO_V1(tde_enc_bytea_cmp);
Datum
tde_enc_bytea_cmp(PG_FUNCTION_ARGS)
{
    bytea  *a   = PG_GETARG_BYTEA_PP(0);
    bytea  *b   = PG_GETARG_BYTEA_PP(1);
    int     la  = VARSIZE_ANY_EXHDR(a);
    int     lb  = VARSIZE_ANY_EXHDR(b);
    int     cmp = memcmp(VARDATA_ANY(a), VARDATA_ANY(b), Min(la, lb));

    if (cmp != 0)
        PG_RETURN_INT32(cmp > 0 ? 1 : -1);
    PG_RETURN_INT32(la > lb ? 1 : (la < lb ? -1 : 0));
}
