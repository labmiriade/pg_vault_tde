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
 * Ciphertext wire format (v4 IV-first trailer):
 *   [ IV(12) ][ CIPHERTEXT(plaintext_len) ][ GCM TAG(16) ][ VERSION(1) ][ GEN(8) ]
 *
 * A 12-byte (96-bit) IV is the NIST-recommended size for GCM.
 * We generate it via PostgreSQL's pg_strong_random() which is /dev/urandom
 * backed on Linux \u2014 we do NOT use OpenSSL's RAND_bytes to stay within the
 * PostgreSQL memory/resource model.
 *
 * IV-first so the blob differs from byte 0 every time: heap_update never sees
 * a constant prefix, so HOT is never wrongly chosen and tde_btree stays coherent.
 */
#include "postgres.h"
#include "miscadmin.h"          /* MyDatabaseId — needed for AAD binding */
#include "utils/memutils.h"
#include "common/pg_prng.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_hw_accel.h"
#include "src/include/pg_vault_tde_catalog.h" /* pg_vault_tde_kms_get_rel_dek (v1.5) */

/* ============================================================
 * Per-backend reusable EVP contexts, keyed by (relid, generation).
 *
 * Allocating an EVP_CIPHER_CTX per call costs a heap malloc; installing the
 * AES-256 key schedule (EVP_EncryptInit_ex2 with the DEK) costs more still.
 * On bulk INSERT/scan both fire once per tuple.
 *
 * We allocate each context once per backend (first use) and cache the
 * (relid, generation) it is keyed for.  As long as consecutive tuples share
 * the same relation and generation we reuse the installed key schedule and
 * only rearm the IV per call; the schedule is re-installed only when relid or
 * generation changes.  On any fatal error path tde_crypto_ctx_cleanup() frees
 * and NULL-outs both contexts so the next call re-allocates and re-keys.
 *
 * Thread safety: each PostgreSQL backend is single-threaded, so no locking
 * is required for these file-scope statics.
 * ============================================================ */
/* One reusable EVP context per direction; re-keyed only when (relid, gen) changes. */
typedef struct TdeCipherSlot
{
    EVP_CIPHER_CTX  *ctx;
    Oid              relid;
    uint64           generation;
} TdeCipherSlot;

static TdeCipherSlot tde_enc = { NULL, InvalidOid, 0 };
static TdeCipherSlot tde_dec = { NULL, InvalidOid, 0 };
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

/* Allocate the two per-backend GCM contexts on first use. Idempotent. */
static bool
tde_crypto_ctx_init(void)
{
    if (tde_enc.ctx == NULL)
        tde_enc.ctx = EVP_CIPHER_CTX_new();
    if (tde_dec.ctx == NULL)
        tde_dec.ctx = EVP_CIPHER_CTX_new();

    return tde_enc.ctx != NULL && tde_dec.ctx != NULL;
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
    if (tde_enc.ctx != NULL)
    {
        EVP_CIPHER_CTX_free(tde_enc.ctx);
        tde_enc.ctx = NULL;
    }
    if (tde_dec.ctx != NULL)
    {
        EVP_CIPHER_CTX_free(tde_dec.ctx);
        tde_dec.ctx = NULL;
    }
    tde_enc.relid = InvalidOid;
    tde_dec.relid = InvalidOid;

    OPENSSL_cleanse(iv_batch, TDE_IV_BATCH_BYTES);
    iv_batch_pos = TDE_IV_BATCH_SIZE;
}

/*
 * tde_compute_aad -- build the 16-byte AEAD Additional Authenticated Data.
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
tde_compute_aad(Oid relid, uint64 generation, unsigned char aad[TDE_V4_AAD_LEN])
{
    uint32 dboid = (uint32) MyDatabaseId;
    uint32 rel   = (uint32) relid;

    memcpy(aad,          &dboid,      4);
    memcpy(aad + 4,      &rel,        4);
    memcpy(aad + 8,      &generation, 8);
}

/*
 * tde_gcm_encrypt_core
 *
 * Encrypts @plaintext_len bytes at @plaintext using AES-256-GCM.
 *
 * Produces the v4 wire format [IV(12) | CT(N) | TAG(16) | VERSION(1) | GEN(8)];
 * the tag covers a 16-byte AAD from (MyDatabaseId, relid, generation).
 *
 * Returns a palloc'd buffer. The caller MUST OPENSSL_cleanse + pfree it.
 * 
 * @param dek           Data Encryption Key used for encryption
 * @param dek_len       Data Encryption Key length
 * @param relid         relation OID for AAD
 * @param plaintext     pointer to plaintext data
 * @param plaintext_len number of byte to be encrypted
 * @param out_len       on return, total buffer length
 *
 * @returns             palloc'd [IV|CT|TAG|VERSION|GEN] buffer or die
 *  
 */

static char* 
tde_gcm_encrypt_core(const unsigned char* dek, int dek_len, Oid relid,
                                 const char* plaintext, Size plaintext_len, Size *out_len)
{
    EVP_CIPHER_CTX* ctx;
    char*           out_buf;
    unsigned char*  iv_ptr;
    unsigned char*  ct_ptr;
    unsigned char*  tag_ptr;
    unsigned char*  version_ptr; 
    unsigned char*  gen_ptr;
    int             olen = 0;
    int             flen = 0;
    Size            total;
    uint64          gen;

    Assert(plaintext != NULL);
    Assert(out_len != NULL);
    Assert(OidIsValid(relid));

    /* Wire format: [IV(12) | CT(N) | TAG(16) | VERSION(1) | GEN(8) |] */
    total = plaintext_len + TDE_V4_OVERHEAD;

    out_buf = (char*) palloc0(total);
   
    /*Calculate ptr position for every component of the layout*/
    iv_ptr = (unsigned char *) out_buf;
    ct_ptr = iv_ptr + TDE_GCM_IV_LEN;
    tag_ptr = ct_ptr + plaintext_len;
    version_ptr = tag_ptr + TDE_GCM_TAG_LEN;
    gen_ptr = version_ptr + 1;

    version_ptr[0] = TDE_V4_VERSION_BYTE;

    gen = pg_vault_tde_catalog_get_rel_generation(relid);
    memcpy(gen_ptr, &gen, TDE_V4_GEN_LEN);


    /*
     * Fetch the next IV from per-backend batch (256 IVs per pg_strong_random call)
     * NEVER reuse the same IV 
     */
    tde_next_iv(iv_ptr);

    /* Re-key only when relid/gen changed; otherwise just rearm the IV. */
    if (!tde_crypto_ctx_init())
        goto gcm_error;

    if (tde_enc.relid != relid || tde_enc.generation != gen)
    {
        if (EVP_EncryptInit_ex2(tde_enc.ctx, tde_hw_accel_gcm_cipher(),
                                dek, NULL, NULL) != 1)
            goto gcm_error;

        tde_enc.relid = relid;
        tde_enc.generation = gen;
    }

    ctx = tde_enc.ctx;

    if (EVP_EncryptInit_ex2(ctx, NULL, NULL, iv_ptr, NULL) != 1)
       goto gcm_error;

    /*
     * Feed AAD: NULL output pointer signals GCM "authenticate only, do not
     * encrypt". Binds dboid+relid+generation into the tag so a ciphertext
     * cannot be replayed into a different table or database.
     */
    {
        unsigned char aad[TDE_V4_AAD_LEN];
        int           aad_len = 0;

        tde_compute_aad(relid, gen, aad);
        if(EVP_EncryptUpdate(ctx, NULL, &aad_len, aad, TDE_V4_AAD_LEN) != 1)
        {
            OPENSSL_cleanse(aad, TDE_V4_AAD_LEN);
            goto gcm_error;
        }
        OPENSSL_cleanse(aad, TDE_V4_AAD_LEN);
    }

    if(EVP_EncryptUpdate(ctx, ct_ptr, &olen,
                         (const unsigned char*) plaintext,
                         (int) plaintext_len) != 1)
       goto gcm_error;

    if(EVP_EncryptFinal_ex(ctx, ct_ptr + olen, &flen) != 1)
       goto gcm_error;
    
    /* Extract the 16-byte authentication tag */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 
                            TDE_GCM_TAG_LEN, tag_ptr) != 1)
       goto gcm_error;

    *out_len = total;
    return out_buf;
    
gcm_error:
    tde_crypto_ctx_cleanup();
    ctx = NULL;
    OPENSSL_cleanse(out_buf, total);
    pfree(out_buf);
    return NULL;
}

char *
tde_gcm_encrypt(Oid relid, const char *plaintext, Size plaintext_len, Size *out_len)
{

    unsigned char   dek[TDE_DEK_LEN];
    char*           encrypted;
    Size            enc_len;

    Assert(plaintext != NULL);
    Assert(out_len != NULL);

    if (!pg_vault_tde_kms_get_rel_dek(relid, (unsigned char *) dek, TDE_DEK_LEN))
        ereport(ERROR,
                (errmsg("[CRYPTO] DEK unavailable for relid=%u; cannot encrypt data", relid)));

    if(!(encrypted = tde_gcm_encrypt_core(dek, TDE_DEK_LEN, relid, 
                            plaintext, plaintext_len, &enc_len)))
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        ereport(ERROR, 
                errmsg("[CRYPTO] AES-256-GCM encryption failed"));
    }

    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    *out_len = enc_len;

    return encrypted;
}

/*
 * tde_gcm_decrypt
 *
 * Decrypts a buffer previously produced by tde_gcm_encrypt.
 * Authenticates the GCM tag before returning plaintext; any tampering
 * causes an ereport(ERROR) (not a WARNING) \u2014 we must never return
 * unauthenticated plaintext to the query executor.
 *
 * @param ciphertext      [IV|CT|TAG|VERSION|GEN] buffer
 * @param ciphertext_len  total buffer length
 * @param out_plain       caller buffer; cap = ciphertext_len - TDE_V4_OVERHEAD
 * @param out_len         on return, plaintext length
 * @returns               true on success; false if version byte is not v4
 */
bool
tde_gcm_decrypt(Oid relid, const char *ciphertext, Size ciphertext_len,
                char *out_plain, Size *out_len)
{
    EVP_CIPHER_CTX      *ctx;
    char                dek[TDE_DEK_LEN];

    const unsigned char *iv_ptr;
    const unsigned char *ct_ptr;
    const unsigned char *tag_ptr;
    const unsigned char *version_ptr;
    const unsigned char *gen_ptr;

    Size                pt_len;
    int                 olen = 0,
                        flen = 0;
    int                 auth_ok;
    uint64              stored_gen;
    uint64              current_gen;

    Assert(ciphertext != NULL);
    Assert(out_len != NULL);

    if (ciphertext_len <= (Size) TDE_V4_OVERHEAD)
        ereport(ERROR,
                (errmsg("[CRYPTO] Ciphertext too short for AES-256-GCM")));

    /* Wire format: [IV(12) | CT(N) | TAG(16) | VERSION(1) | GEN(8)] */
    pt_len  = ciphertext_len - TDE_V4_OVERHEAD;
    iv_ptr  = (const unsigned char *) ciphertext;
    ct_ptr  = iv_ptr + TDE_GCM_IV_LEN;
    tag_ptr = ct_ptr + pt_len;
    version_ptr = tag_ptr + TDE_GCM_TAG_LEN;
    gen_ptr = version_ptr + 1;

    if ((unsigned char) version_ptr[0] != TDE_V4_VERSION_BYTE)
        return false;

    {

        TdeRelDekMap cache_entry;
        Oid dek_relid = resolve_effective_relid(relid);
        bool    found = false;

        memcpy(&stored_gen, gen_ptr, TDE_V4_GEN_LEN);

        if(!tde_catalog_cache_entry(dek_relid, &cache_entry))
        {   
            current_gen = pg_vault_tde_catalog_get_rel_generation(dek_relid);
                
            if(stored_gen == current_gen)
            {
                found = pg_vault_tde_kms_get_rel_dek(dek_relid, (unsigned char *) dek, TDE_DEK_LEN);
            } 
            else if(stored_gen == current_gen - 1)
            {
                found = pg_vault_tde_kms_get_rel_prev_dek(dek_relid, (unsigned char *) dek, TDE_DEK_LEN);
            }
        }
        else
        {
            current_gen = cache_entry.generation;

            if(stored_gen == current_gen && cache_entry.dek_valid)
            {
                memcpy(dek, cache_entry.dek, TDE_DEK_LEN);
                found = true;
            }
            else if(stored_gen == current_gen - 1 && cache_entry.prev_dek_valid)
            {
                memcpy(dek, cache_entry.prev_dek, TDE_DEK_LEN);
                found = true;
            }
        }

        OPENSSL_cleanse(&cache_entry, sizeof(TdeRelDekMap));

        if(!found)
            return false;

    }

    /* Cache key is stored_gen: the generation of the DEK loaded above. */
    if (!tde_crypto_ctx_init())
        goto gcm_dec_error;

    if (tde_dec.relid != relid || tde_dec.generation != stored_gen)
    {
        if (EVP_DecryptInit_ex2(tde_dec.ctx, tde_hw_accel_gcm_cipher(),
                                (unsigned char *) dek, NULL, NULL) != 1)
            goto gcm_dec_error;

        tde_dec.relid = relid;
        tde_dec.generation = stored_gen;
    }

    ctx = tde_dec.ctx;

    if(EVP_DecryptInit_ex2(ctx, NULL, NULL, iv_ptr, NULL) != 1)
       goto gcm_dec_error;

    /* Set the expected tag BEFORE calling Final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             TDE_GCM_TAG_LEN, (void *) tag_ptr) != 1)
        goto gcm_dec_error;

    /*
     * Feed AAD using the generation from the wire header, NOT the current
     * live generation — they may differ after a key rotation.
     */
    {
        unsigned char aad[TDE_V4_AAD_LEN];
        int           aad_len = 0;

        tde_compute_aad(relid, stored_gen, aad);
        if (EVP_DecryptUpdate(ctx, NULL, &aad_len, aad, TDE_V4_AAD_LEN) != 1)
        {
            OPENSSL_cleanse(aad, TDE_V4_AAD_LEN);
            goto gcm_dec_error;
        }
        OPENSSL_cleanse(aad, TDE_V4_AAD_LEN);
    }

    if (EVP_DecryptUpdate(ctx, (unsigned char *) out_plain, &olen,
                          ct_ptr, (int) pt_len) != 1)
        goto gcm_dec_error;

    /*
     * EVP_DecryptFinal_ex returns 0 if the GCM tag does not match.
     * We MUST check this: returning 0 means authentication failure, which
     * could indicate data tampering or a wrong DEK.  Returning unauthenticated
     * plaintext would be a critical security vulnerability.
     */
    auth_ok = EVP_DecryptFinal_ex(ctx,
                                  (unsigned char *) out_plain + olen, &flen);

    /* ctx is retained in tde_dec.ctx for reuse — do NOT free here */
    OPENSSL_cleanse(dek, TDE_DEK_LEN);

    if (auth_ok != 1)
    {
        /* Wipe the caller buffer: never expose unauthenticated plaintext. */
        OPENSSL_cleanse(out_plain, pt_len);

        ereport(ERROR,
                (errmsg("[CRYPTO] AES-256-GCM authentication FAILED: "
                        "data integrity violation or wrong DEK")));
    }

    *out_len = (Size)(olen + flen);
    return true;

gcm_dec_error:
    tde_crypto_ctx_cleanup();
    ctx = NULL;
    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    OPENSSL_cleanse(out_plain, pt_len);
    ereport(ERROR, (errmsg("[CRYPTO] AES-256-GCM decryption setup failed")));
    return false; /* unreachable */
}

