/*
 * pg_vault_tde_crypto.c - Core AES-256-GCM encrypt/decrypt primitives
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * All symmetric encryption in pg_vault_tde uses AES-256-GCM via the OpenSSL
 * EVP layer.  GCM provides both confidentiality and integrity (AEAD) with a
 * single pass, eliminating the need for a separate HMAC.
 *
 * AES-NI acceleration: OpenSSL 3.x EVP dispatch automatically selects the
 * hardware-accelerated AES-NI path when the CPU supports it (CPUID flag).
 * We do NOT hardcode an ENGINE; the default provider handles this, meaning
 * the code benefits from AES-NI on modern x86/ARM without any extra work.
 *
 * Ciphertext wire format:
 *   [  IV  (12 bytes) ][ CIPHERTEXT (plaintext_len bytes) ][ GCM TAG (16 bytes) ]
 *
 * A 12-byte (96-bit) IV is the NIST-recommended size for GCM.
 * We generate it via PostgreSQL's pg_strong_random() which is /dev/urandom
 * backed on Linux \u2014 we do NOT use OpenSSL's RAND_bytes to stay within the
 * PostgreSQL memory/resource model.
 *
 * The GCM tag (16 bytes) is appended last, matching the common TLS layout
 * and simplifying audits against known implementations.
 */
#include "postgres.h"
#include "miscadmin.h"          /* MyDatabaseId — needed for v3 AAD binding */
#include "utils/memutils.h"
#include "common/pg_prng.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_hw_accel.h"
#include "src/include/pg_vault_tde_catalog.h" /* pg_vault_tde_kms_get_rel_dek (v1.5) */

/* ============================================================
 * Per-backend reusable EVP contexts.
 *
 * Allocating EVP_CIPHER_CTX via EVP_CIPHER_CTX_new() invokes a heap malloc
 * (~20-30 ns) on every call.  On the multi_insert path this fires once per
 * tuple, adding 200-300 ms of pure allocation overhead for a 10M-row load.
 *
 * Instead we allocate once per backend on first use and reset the context
 * between calls via EVP_CIPHER_CTX_reset().  On any fatal error path we free
 * and NULL-out the pointer so the next call re-allocates cleanly.
 *
 * Thread safety: each PostgreSQL backend is single-threaded, so no locking
 * is required for these file-scope statics.
 * ============================================================ */
static EVP_CIPHER_CTX *tde_gcm_enc_ctx = NULL;  /* encrypt context */
static EVP_CIPHER_CTX *tde_gcm_dec_ctx = NULL;  /* decrypt context */

/* ============================================================
 * Per-backend IV batch buffer.
 *
 * pg_strong_random() opens /dev/urandom (or calls getrandom(2)) on every
 * invocation.  For bulk INSERT this adds ~1 µs/tuple of entropy overhead.
 * We amortise that cost by requesting 256 IVs at once and serving them from
 * a local array.  The array is wiped in tde_crypto_ctx_cleanup().
 *
 * Security note: AES-256-GCM with random 96-bit IVs has an IV-collision
 * probability of roughly 2^{-32} after 2^{32} encryptions under the same DEK
 * (birthday bound).  With DEK rotation at sane intervals this is far below
 * the safety threshold.  pg_strong_random uses /dev/urandom which is
 * automatically reseeded after fork() via getrandom(GRND_NONBLOCK);
 * fork-safety is maintained.
 * ============================================================ */
#define TDE_IV_BATCH_SIZE   256
#define TDE_IV_BATCH_BYTES  (TDE_IV_BATCH_SIZE * TDE_GCM_IV_LEN)

static char  iv_batch[TDE_IV_BATCH_BYTES];

/*
 * Initialise the cursor past the end so the very first tde_next_iv() call
 * triggers a full batch refill from pg_strong_random().
 */
static int   iv_batch_pos = TDE_IV_BATCH_SIZE;

/*
 * tde_next_iv -- return the next IV from the per-backend batch.
 *
 * Refills the batch (one pg_strong_random call for 256 × 12 bytes) when
 * the current batch is exhausted.
 */
static void
tde_next_iv(unsigned char *iv_out)
{
    if (iv_batch_pos >= TDE_IV_BATCH_SIZE)
    {
        /* Refill: one system call covers 256 IVs */
        if (!pg_strong_random(iv_batch, TDE_IV_BATCH_BYTES))
            ereport(ERROR,
                    (errmsg("[CRYPTO] Failed to generate IV batch")));
        iv_batch_pos = 0;
    }
    memcpy(iv_out, iv_batch + iv_batch_pos * TDE_GCM_IV_LEN, TDE_GCM_IV_LEN);
    iv_batch_pos++;
}

/*
 * tde_crypto_ctx_cleanup -- free cached EVP contexts and wipe the IV batch.
 *
 * Registered via on_proc_exit() in _PG_init so it runs when the backend
 * exits normally or via proc_exit().  Wipes sensitive key-schedule material
 * from OpenSSL's internal buffers.
 */
void
tde_crypto_ctx_cleanup(void)
{
    if (tde_gcm_enc_ctx != NULL)
    {
        EVP_CIPHER_CTX_free(tde_gcm_enc_ctx);
        tde_gcm_enc_ctx = NULL;
    }
    if (tde_gcm_dec_ctx != NULL)
    {
        EVP_CIPHER_CTX_free(tde_gcm_dec_ctx);
        tde_gcm_dec_ctx = NULL;
    }
    /* Wipe IV batch so key-adjacent entropy is not left in process memory */
    OPENSSL_cleanse(iv_batch, TDE_IV_BATCH_BYTES);
    iv_batch_pos = TDE_IV_BATCH_SIZE; /* mark exhausted */
}

/*
 * tde_compute_aad -- build the 16-byte AEAD Additional Authenticated Data
 *                    for the v3 wire format.
 *
 * AAD layout (all fields little-endian):
 *   [MyDatabaseId(4) | relid(4) | generation(8)]
 *
 * The AAD is fed to EVP_EncryptUpdate / EVP_DecryptUpdate with a NULL output
 * pointer, which signals GCM to authenticate-but-not-encrypt the data.  It
 * is NOT stored on disk (zero wire overhead); the decrypt path recomputes it
 * from the live context.
 *
 * Binding the database OID and relation OID to the ciphertext prevents a
 * cross-table paste attack: ciphertext from table A cannot be replayed into
 * table B even if both share the same DEK.  Binding the generation ensures
 * that a tuple encrypted before a key rotation cannot silently pass the old
 * tag check after rotation (belt-and-suspenders on top of the prev_dek path).
 */
static void
tde_compute_aad(Oid relid, uint64 generation, unsigned char aad[TDE_V3_AAD_LEN])
{
    uint32 dboid = (uint32) MyDatabaseId;
    uint32 rel   = (uint32) relid;

    memcpy(aad,          &dboid,      4);
    memcpy(aad + 4,      &rel,        4);
    memcpy(aad + 8,      &generation, 8);
}

/*
 * tde_gcm_encrypt
 *
 * Encrypts @plaintext_len bytes at @plaintext using AES-256-GCM.
 *
 * When relid is a valid table OID, produces a v3 wire format:
 *   [VERSION(1:0x03) | GENERATION(8) | IV(12) | CT(N) | TAG(16)]
 * where the GCM tag covers a 16-byte AAD computed from
 *   (MyDatabaseId, relid, generation).
 *
 * When relid == InvalidOid (backup path, test wrappers), falls back to the
 * v2 wire format without AAD.
 *
 * Returns a palloc'd buffer.  The caller MUST call OPENSSL_cleanse + pfree
 * on the returned buffer when done.
 *
 * @param relid           relation OID for AAD (InvalidOid = no AAD / v2)
 * @param plaintext       pointer to plaintext data
 * @param plaintext_len   number of bytes to encrypt
 * @param out_len         on return, total buffer length
 * @returns               palloc'd [VERSION|GEN|IV|CT|TAG] buffer, or aborts
 */
char *
tde_gcm_encrypt(Oid relid, const char *plaintext, Size plaintext_len, Size *out_len)
{
    EVP_CIPHER_CTX *ctx;
    char            dek[TDE_DEK_LEN];
    char           *out_buf;
    unsigned char  *iv_ptr;
    unsigned char  *ct_ptr;
    unsigned char  *tag_ptr;
    int             olen = 0,
                    flen = 0;
    Size            total;
    uint64          gen;    /* captured here so AAD step can reference it */

    Assert(plaintext != NULL);
    Assert(out_len != NULL);

    if (!pg_vault_tde_kms_get_rel_dek(relid, (unsigned char *) dek, TDE_DEK_LEN))
        ereport(ERROR,
                (errmsg("[CRYPTO] DEK unavailable for relid=%u; cannot encrypt data", relid)));

    /*
     * Wire format selection:
     *   v3 (0x03) when relid is a valid table OID — includes GCM AAD binding.
     *   v2 (0x02) when relid == InvalidOid (backup blocks, test SQL wrappers).
     * Layout for both: [VERSION(1) | GENERATION(8) | IV(12) | CT(N) | TAG(16)]
     * The AAD is fed to GCM but is NOT stored in the wire buffer (zero overhead).
     */
    {
        gen = pg_vault_tde_kms_get_generation();

        total = plaintext_len + TDE_V2_OVERHEAD;
        out_buf = (char *) palloc0(total);

        /* Write version byte: v3 when table-scoped, v2 for unscoped paths */
        ((unsigned char *) out_buf)[0] =
            OidIsValid(relid) ? TDE_V3_VERSION_BYTE : TDE_V2_VERSION_BYTE;

        /* Write generation (little-endian uint64) */
        memcpy(out_buf + 1, &gen, TDE_V2_GEN_LEN);
    }

    iv_ptr  = (unsigned char *) out_buf + 1 + TDE_V2_GEN_LEN;
    ct_ptr  = iv_ptr  + TDE_GCM_IV_LEN;
    tag_ptr = ct_ptr  + plaintext_len;

    /*
     * Fetch the next IV from per-backend batch (256 IVs per pg_strong_random
     * call).  See tde_next_iv() for security rationale.
     */
    tde_next_iv(iv_ptr);

    /*
     * Reuse the per-backend encrypt context; allocate on first use.
     * EVP_CIPHER_CTX_reset() restores the context to its post-new() state
     * without releasing the underlying memory allocation.
     */
    if (tde_gcm_enc_ctx == NULL)
    {
        tde_gcm_enc_ctx = EVP_CIPHER_CTX_new();
        if (tde_gcm_enc_ctx == NULL)
        {
            OPENSSL_cleanse(dek, TDE_DEK_LEN);
            OPENSSL_cleanse(out_buf, total);
            pfree(out_buf);
            ereport(ERROR,
                    (errmsg("[CRYPTO] Failed to allocate GCM encrypt context")));
        }
    }
    else
        EVP_CIPHER_CTX_reset(tde_gcm_enc_ctx);
    ctx = tde_gcm_enc_ctx;

    /*
     * EVP_EncryptInit_ex2: use the cipher from the hw_accel provider layer.
     * This routes to QAT if loaded, or AES-NI via the default provider.
     * The NULL params argument means OpenSSL picks the algorithm-specific
     * defaults (96-bit IV for GCM, standard tag length).
     */
    if (EVP_EncryptInit_ex2(ctx, tde_hw_accel_gcm_cipher(),
                            (unsigned char *) dek, iv_ptr, NULL) != 1)
        goto gcm_error;

    /*
     * v3 wire format: feed AEAD Additional Authenticated Data.
     *
     * Passing NULL as the output pointer is the EVP GCM convention for
     * "authenticate only, do not encrypt".  The AAD is bound into the
     * GCM tag so decryption will fail if the tuple is replayed into a
     * different table or database.  The 16-byte AAD itself is not stored
     * on disk — zero wire overhead.
     */
    if (OidIsValid(relid))
    {
        unsigned char aad[TDE_V3_AAD_LEN];
        int           aad_len = 0;

        tde_compute_aad(relid, gen, aad);
        if (EVP_EncryptUpdate(ctx, NULL, &aad_len, aad, TDE_V3_AAD_LEN) != 1)
        {
            OPENSSL_cleanse(aad, TDE_V3_AAD_LEN);
            goto gcm_error;
        }
        OPENSSL_cleanse(aad, TDE_V3_AAD_LEN);
    }

    if (EVP_EncryptUpdate(ctx, ct_ptr, &olen,
                          (const unsigned char *) plaintext,
                          (int) plaintext_len) != 1)
        goto gcm_error;

    if (EVP_EncryptFinal_ex(ctx, ct_ptr + olen, &flen) != 1)
        goto gcm_error;

    /* Extract the 16-byte authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             TDE_GCM_TAG_LEN, tag_ptr) != 1)
        goto gcm_error;

    /* ctx is kept alive in tde_gcm_enc_ctx for reuse — do NOT free here */
    OPENSSL_cleanse(dek, TDE_DEK_LEN);

    *out_len = total;
    return out_buf;

gcm_error:
    /*
     * Free and NULL-out the cached context so the next encrypt call gets a
     * fresh allocation.  The context state is unknown after an OpenSSL error;
     * retaining it would risk using corrupted key-schedule material.
     */
    EVP_CIPHER_CTX_free(tde_gcm_enc_ctx);
    tde_gcm_enc_ctx = NULL;
    ctx = NULL;
    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    OPENSSL_cleanse(out_buf, total);
    pfree(out_buf);
    ereport(ERROR, (errmsg("[CRYPTO] AES-256-GCM encryption failed")));
    return NULL; /* unreachable */
}

/*
 * tde_gcm_decrypt
 *
 * Decrypts a buffer previously produced by tde_gcm_encrypt.
 * Authenticates the GCM tag before returning plaintext; any tampering
 * causes an ereport(ERROR) (not a WARNING) \u2014 we must never return
 * unauthenticated plaintext to the query executor.
 *
 * @param ciphertext      [IV|CIPHERTEXT|TAG] buffer
 * @param ciphertext_len  total buffer length
 * @param out_len         on return, plaintext length
 * @returns               palloc'd plaintext buffer; caller cleans up
 */
char *
tde_gcm_decrypt(Oid relid, const char *ciphertext, Size ciphertext_len, Size *out_len)
{
    EVP_CIPHER_CTX     *ctx;
    char                dek[TDE_DEK_LEN];
    const unsigned char *iv_ptr;
    const unsigned char *ct_ptr;
    const unsigned char *tag_ptr;
    char               *out_buf;
    Size                pt_len;
    int                 olen = 0,
                        flen = 0;
    int                 auth_ok;
    bool                is_v2 = false; /* tracks which parse path was used */
    bool                is_v3 = false; /* v3 = v2 layout + AAD tag binding */

    Assert(ciphertext != NULL);
    Assert(out_len != NULL);

    if (ciphertext_len <= (Size)(TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN))
        ereport(ERROR,
                (errmsg("[CRYPTO] Ciphertext too short for AES-256-GCM")));

    /*
     * Wire format auto-detection.
     *
     * v3 format: first byte == TDE_V3_VERSION_BYTE (0x03).
     *   [VERSION(1) | GENERATION(8) | IV(12) | CT(N) | TAG(16)]
     *   GCM tag covers 16-byte AAD = [dboid(4) | relid(4) | gen(8)].
     *   Minimum length = TDE_V2_OVERHEAD (37) bytes.
     *
     * v2 format: first byte == TDE_V2_VERSION_BYTE (0x02).
     *   Same on-disk layout as v3; no AAD in the GCM tag.
     *   Minimum length = TDE_V2_OVERHEAD (37) bytes.
     *
     * v1 format: anything else — starts directly with the IV.
     *   [IV(12) | CT(N) | TAG(16)]
     *   Minimum length = TDE_GCM_OVERHEAD (28) bytes.
     *
     * False-positive risk for v2/v3 detection (first byte of a v1 IV is 0x02
     * or 0x03): probability 2/256 (~0.8%).  When that happens GCM tag
     * authentication fails on the v2/v3 try and we fall back to the v1 path.
     */
    if ((unsigned char) ciphertext[0] == TDE_V3_VERSION_BYTE &&
        ciphertext_len > (Size) TDE_V2_OVERHEAD)
    {
        /*
         * v3 path: same layout as v2; AAD will be fed to GCM below.
         * Generation is read from the wire header for AAD recomputation.
         */
        is_v3   = true;
        is_v2   = true; /* v3 is a superset of v2 layout */
        pt_len  = ciphertext_len - TDE_V2_OVERHEAD;
        iv_ptr  = (const unsigned char *) ciphertext + 1 + TDE_V2_GEN_LEN;
        ct_ptr  = iv_ptr + TDE_GCM_IV_LEN;
        tag_ptr = ct_ptr + pt_len;
    }
    else if ((unsigned char) ciphertext[0] == TDE_V2_VERSION_BYTE &&
             ciphertext_len > (Size) TDE_V2_OVERHEAD)
    {
        /*
         * v2 path: skip version byte + generation prefix, then parse
         * the standard GCM layout.  Generation is currently read but not
         * used for DEK selection (reserved for v1.5 smart-selection).
         */
        is_v2   = true;
        pt_len  = ciphertext_len - TDE_V2_OVERHEAD;
        iv_ptr  = (const unsigned char *) ciphertext + 1 + TDE_V2_GEN_LEN;
        ct_ptr  = iv_ptr + TDE_GCM_IV_LEN;
        tag_ptr = ct_ptr + pt_len;
    }
    else
    {
        /* v1 path: no prefix, IV starts at byte 0 */
        pt_len  = ciphertext_len - TDE_GCM_IV_LEN - TDE_GCM_TAG_LEN;
        iv_ptr  = (const unsigned char *) ciphertext;
        ct_ptr  = iv_ptr + TDE_GCM_IV_LEN;
        tag_ptr = ct_ptr + pt_len;
    }

    if (!pg_vault_tde_kms_get_rel_dek(relid, (unsigned char *) dek, TDE_DEK_LEN))
        ereport(ERROR,
                (errmsg("[CRYPTO] DEK unavailable for relid=%u; cannot decrypt data", relid)));

    out_buf = (char *) palloc0(pt_len + 1); /* +1: safe zero terminator */

    /*
     * Reuse the per-backend decrypt context; allocate on first use.
     */
    if (tde_gcm_dec_ctx == NULL)
    {
        tde_gcm_dec_ctx = EVP_CIPHER_CTX_new();
        if (tde_gcm_dec_ctx == NULL)
        {
            OPENSSL_cleanse(dek, TDE_DEK_LEN);
            pfree(out_buf);
            ereport(ERROR,
                    (errmsg("[CRYPTO] Failed to allocate GCM decrypt context")));
        }
    }
    else
        EVP_CIPHER_CTX_reset(tde_gcm_dec_ctx);
    ctx = tde_gcm_dec_ctx;

    if (EVP_DecryptInit_ex2(ctx, tde_hw_accel_gcm_cipher(),
                            (unsigned char *) dek, iv_ptr, NULL) != 1)
        goto gcm_dec_error;

    /* Set the expected tag BEFORE calling Final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             TDE_GCM_TAG_LEN, (void *) tag_ptr) != 1)
        goto gcm_dec_error;

    /*
     * v3 wire format: feed AEAD AAD before decrypting ciphertext.
     *
     * The generation used for AAD recomputation MUST come from the wire
     * header (the generation stored at encrypt time), NOT from the current
     * live generation — they may differ after a key rotation.
     */
    if (is_v3 && OidIsValid(relid))
    {
        uint64        stored_gen;
        unsigned char aad[TDE_V3_AAD_LEN];
        int           aad_len = 0;

        memcpy(&stored_gen, ciphertext + 1, TDE_V2_GEN_LEN);
        tde_compute_aad(relid, stored_gen, aad);
        if (EVP_DecryptUpdate(ctx, NULL, &aad_len, aad, TDE_V3_AAD_LEN) != 1)
        {
            OPENSSL_cleanse(aad, TDE_V3_AAD_LEN);
            goto gcm_dec_error;
        }
        OPENSSL_cleanse(aad, TDE_V3_AAD_LEN);
    }

    if (EVP_DecryptUpdate(ctx, (unsigned char *) out_buf, &olen,
                          ct_ptr, (int) pt_len) != 1)
        goto gcm_dec_error;

    /*
     * EVP_DecryptFinal_ex returns 0 if the GCM tag does not match.
     * We MUST check this: returning 0 means authentication failure, which
     * could indicate data tampering or a wrong DEK.  Returning unauthenticated
     * plaintext would be a critical security vulnerability.
     */
    auth_ok = EVP_DecryptFinal_ex(ctx,
                                  (unsigned char *) out_buf + olen, &flen);

    /* ctx is kept alive in tde_gcm_dec_ctx for reuse — do NOT free here */
    OPENSSL_cleanse(dek, TDE_DEK_LEN);

    if (auth_ok != 1)
    {
        /*
         * GCM authentication failed with the current DEK.  This may indicate
         * data corruption, tampering, or a key rotation: the tuple might have
         * been encrypted with the previous DEK.  Try the prev_dek if available.
         *
         * This fallback is the key mechanism that enables graceful key rotation:
         * after rotate_key() + set_test_dek()/vault_fetch_dek(), rows encrypted
         * with the old key remain readable during the re-encryption window.
         */
        char prev_dek[TDE_DEK_LEN];

        if (pg_vault_tde_kms_get_rel_prev_dek(relid, (unsigned char *) prev_dek, TDE_DEK_LEN))
        {
            int  prev_olen = 0, prev_flen = 0;
            bool prev_ok   = true;

            /* Reset the context for a fresh decrypt attempt */
            EVP_CIPHER_CTX_reset(ctx);

            /* Wipe the output buffer from the failed attempt */
            OPENSSL_cleanse(out_buf, pt_len + 1);

            if (EVP_DecryptInit_ex2(ctx, tde_hw_accel_gcm_cipher(),
                                    (unsigned char *) prev_dek, iv_ptr, NULL) != 1)
                prev_ok = false;

            if (prev_ok &&
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                    TDE_GCM_TAG_LEN, (void *) tag_ptr) != 1)
                prev_ok = false;

            /*
             * For v3 tuples, the AAD must be fed before data, even during
             * the prev_dek retry — the stored generation and table OID have
             * not changed; only the DEK differs.
             */
            if (prev_ok && is_v3 && OidIsValid(relid))
            {
                uint64        stored_gen;
                unsigned char aad[TDE_V3_AAD_LEN];
                int           aad_len = 0;

                memcpy(&stored_gen, ciphertext + 1, TDE_V2_GEN_LEN);
                tde_compute_aad(relid, stored_gen, aad);
                if (EVP_DecryptUpdate(ctx, NULL, &aad_len,
                                      aad, TDE_V3_AAD_LEN) != 1)
                    prev_ok = false;
                OPENSSL_cleanse(aad, TDE_V3_AAD_LEN);
            }

            if (prev_ok &&
                EVP_DecryptUpdate(ctx, (unsigned char *) out_buf, &prev_olen,
                                  ct_ptr, (int) pt_len) != 1)
                prev_ok = false;

            if (prev_ok)
            {
                auth_ok = EVP_DecryptFinal_ex(ctx,
                                              (unsigned char *) out_buf + prev_olen,
                                              &prev_flen);
            }

            OPENSSL_cleanse(prev_dek, TDE_DEK_LEN);

            if (auth_ok == 1)
            {
                /* Success with prev_dek — tuple encrypted with old key */
                ereport(DEBUG1,
                        (errmsg("[CRYPTO] Decrypted with previous DEK (rotation fallback)")));
                *out_len = (Size)(prev_olen + prev_flen);
                return out_buf;
            }
        }

        /* Both current and prev DEK failed.
         *
         * If we took the v2 parse path due to a false-positive (first byte
         * of a v1 IV happened to be 0x02, probability ~1/256), retry with
         * the v1 parse layout.  This handles backward-compatibility for
         * existing v1 tables being read by a v1.4+ server.
         */
        if (is_v2 && ciphertext_len > (Size) TDE_GCM_OVERHEAD)
        {
            Size                 v1_pt_len = ciphertext_len - TDE_GCM_IV_LEN - TDE_GCM_TAG_LEN;
            const unsigned char *v1_iv     = (const unsigned char *) ciphertext;
            const unsigned char *v1_ct     = v1_iv + TDE_GCM_IV_LEN;
            const unsigned char *v1_tag    = v1_ct + v1_pt_len;
            char                 v1_dek[TDE_DEK_LEN];
            char                *v1_buf    = (char *) palloc0(v1_pt_len + 1);
            int                  v1_olen = 0, v1_flen = 0, v1_ok = 0;

            if (pg_vault_tde_kms_get_rel_dek(relid, (unsigned char *) v1_dek, TDE_DEK_LEN))
            {
                EVP_CIPHER_CTX_reset(ctx);
                if (EVP_DecryptInit_ex2(ctx, tde_hw_accel_gcm_cipher(),
                                        (unsigned char *) v1_dek, v1_iv, NULL) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                        TDE_GCM_TAG_LEN, (void *) v1_tag) == 1 &&
                    EVP_DecryptUpdate(ctx, (unsigned char *) v1_buf, &v1_olen,
                                      v1_ct, (int) v1_pt_len) == 1)
                {
                    v1_ok = EVP_DecryptFinal_ex(ctx,
                                                (unsigned char *) v1_buf + v1_olen,
                                                &v1_flen);
                }
                OPENSSL_cleanse(v1_dek, TDE_DEK_LEN);

                if (v1_ok == 1)
                {
                    /* Success: this was a v1 tuple with a 0x02 IV prefix */
                    OPENSSL_cleanse(out_buf, pt_len + 1);
                    pfree(out_buf);
                    ereport(DEBUG1,
                            (errmsg("[CRYPTO] v2 false-positive resolved via v1 fallback")));
                    *out_len = (Size)(v1_olen + v1_flen);
                    return v1_buf;
                }
            }

            OPENSSL_cleanse(v1_buf, v1_pt_len + 1);
            pfree(v1_buf);
        }

        /* All parse paths failed — genuine integrity violation */
        OPENSSL_cleanse(out_buf, pt_len + 1);
        pfree(out_buf);
        ereport(ERROR,
                (errmsg("[CRYPTO] AES-256-GCM authentication FAILED: "
                        "data integrity violation or wrong DEK")));
    }

    *out_len = (Size)(olen + flen);
    return out_buf;

gcm_dec_error:
    /*
     * Free and NULL-out the cached context — unknown state after an error.
     */
    EVP_CIPHER_CTX_free(tde_gcm_dec_ctx);
    tde_gcm_dec_ctx = NULL;
    ctx = NULL;
    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    OPENSSL_cleanse(out_buf, pt_len + 1);
    pfree(out_buf);
    ereport(ERROR, (errmsg("[CRYPTO] AES-256-GCM decryption setup failed")));
    return NULL; /* unreachable */
}

/* ----------------------------------------------------------------
 * SQL-callable test wrappers for integration testing.
 * These expose the raw crypto primitives so we can verify that
 * AES-256-GCM encrypt → decrypt round-trips correctly, and that
 * ciphertext does NOT contain plaintext.
 * ----------------------------------------------------------------
 */
#include "fmgr.h"
#include "utils/builtins.h"
#include "varatt.h"

/*
 * pg_vault_tde_encrypt_test(text) → bytea
 *
 * Encrypts the input text and returns the ciphertext as bytea.
 * Requires a DEK to be set (via pg_vault_tde_set_test_dek first).
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_encrypt_test);
PGDLLEXPORT Datum
pg_vault_tde_encrypt_test(PG_FUNCTION_ARGS)
{
    text   *input   = PG_GETARG_TEXT_PP(0);
    char   *plain   = VARDATA_ANY(input);
    Size    plen    = VARSIZE_ANY_EXHDR(input);
    Size    enc_len = 0;
    char   *encrypted;
    bytea  *result;

    encrypted = tde_gcm_encrypt(InvalidOid, plain, plen, &enc_len);

    result = (bytea *) palloc(VARHDRSZ + enc_len);
    SET_VARSIZE(result, VARHDRSZ + enc_len);
    memcpy(VARDATA(result), encrypted, enc_len);

    OPENSSL_cleanse(encrypted, enc_len);
    pfree(encrypted);

    PG_RETURN_BYTEA_P(result);
}

/*
 * pg_vault_tde_decrypt_test(bytea) → text
 *
 * Decrypts a ciphertext produced by pg_vault_tde_encrypt_test.
 * Verifies GCM authentication tag — fails if tampered.
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_decrypt_test);
PGDLLEXPORT Datum
pg_vault_tde_decrypt_test(PG_FUNCTION_ARGS)
{
    bytea  *input   = PG_GETARG_BYTEA_PP(0);
    char   *ct      = VARDATA_ANY(input);
    Size    ct_len  = VARSIZE_ANY_EXHDR(input);
    Size    pt_len  = 0;
    char   *decrypted;
    text   *result;

    decrypted = tde_gcm_decrypt(InvalidOid, ct, ct_len, &pt_len);

    result = cstring_to_text_with_len(decrypted, pt_len);

    OPENSSL_cleanse(decrypted, pt_len);
    pfree(decrypted);

    PG_RETURN_TEXT_P(result);
}
