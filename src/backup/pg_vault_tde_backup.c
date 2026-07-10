/*
 * pg_vault_tde_backup.c - Logical backup (pg_dump) encryption support
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * pg_dump works by executing SELECT queries against the live database.
 * When it reads from a TDE-encrypted table, the TAM decrypts each tuple
 * on-the-fly, so pg_dump naturally receives PLAINTEXT.  Left unprotected,
 * the dump file is a complete bypass of the TDE perimeter.
 *
 * Our strategy has three layers:
 *
 *  Layer 1 \u2013 DUMP-TIME RE-ENCRYPTION (this file)
 *    A C utility (pg_dump_tde) wraps pg_dump output through a streaming
 *    AES-256-GCM cipher before touching disk.  The encrypted stream is
 *    prefixed with a TDE Backup Header (tde_backup_header) that contains:
 *      \u2022 Magic + format version
 *      \u2022 The current DEK, wrapped (encrypted) with the KEK from Vault
 *        (RSA-4096 OAEP or ECDH-derived wrapping key)
 *      \u2022 The per-backup GCM IV
 *    On restore, pg_restore_tde reads the header, unwraps the DEK from Vault,
 *    decrypts the stream, and pipes it to pg_restore.
 *
 *  Layer 2 \u2013 SQL-LEVEL GUARD (event trigger)
 *    A DDL event trigger fires on COPY TO / pg_dump connections and logs
 *    a WARNING if the dump is not going through the encrypted wrapper.
 *    This is advisory, not a hard block (pg_dump must not be broken for
 *    the superuser DBA who is aware of the risk).
 *
 *  Layer 3 \u2013 TAP TEST MOCK
 *    A TAP test (tap/02_backup.t) spawns a mock Vault, runs pg_dump_tde,
 *    verifies the output is not plaintext, then runs pg_restore_tde and
 *    verifies the data round-trips correctly.
 *
 * Wire format for encrypted dump file:
 *
 *    [ tde_backup_header (fixed size) ]
 *    [ encrypted pg_dump stream (AES-256-GCM, chunked 64KB blocks) ]
 *
 * Each 64KB block is independently authenticated so corruption is detected
 * at the block level, not only at EOF.
 */
#include "postgres_fe.h"
#include "libpq-fe.h"
#include "common/logging.h"
#include "port/pg_bswap.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include "pg_vault_tde_backup.h"

static PGconn *init_db_conn(ConnParams *params);

const PdeKmsProvider* dump_tde_active_provider = NULL;
static EVP_CIPHER_CTX* dump_evp_ctx = NULL;

/*
 * tde_backup_init
 *
 * Initialises the backup operation: opens a database connection, reads the
 * pg_vault_tde.kms_provider GUC, and calls the matching provider's init()
 * to load credentials from the remaining GUCs.
 *
 * @param params    pointer to ConnParams struct with connection info
 * @returns         true on success
 */

bool tde_backup_init(ConnParams* params)
{
    PGconn* conn = init_db_conn(params);
    char kms_provider[64];

    if(!conn) {
        fprintf(stderr, "pg_dump_tde: can't connect to db %s", params->dbname);
        return false;
    }

    PGresult *r = PQexec(conn, "SHOW pg_vault_tde.kms_provider");
    if(PQresultStatus(r) != PGRES_TUPLES_OK) 
    {
        fprintf(stderr, "pg_dump_tde: cannot read GUC pg_vault_tde.kms_provider: %s",
                        PQerrorMessage(conn));                   
        PQclear(r);                                               
        return false;                            
    }
    snprintf(kms_provider, sizeof(kms_provider), "%s", PQgetvalue(r, 0, 0));
    PQclear(r);

    if(strcmp(kms_provider, VAULT_PROVIDER) == 0)
    {
        dump_tde_active_provider = pg_dump_tde_kms_vault_provider();
    }
    else if(strcmp(kms_provider, LOCAL_PROVIDER) == 0)
    {
        dump_tde_active_provider = pg_dump_tde_kms_local_provider();
    }
    else{
        fprintf(stderr, "pg_dump_tde: unknown KMS provider %s", kms_provider);
        return false;
    }

    if(!dump_tde_active_provider->init(conn))
    {
        PQfinish(conn);
        return false;
    }

    PQfinish(conn);
    return true;
}

/*
 * tde_backup_header_init
 *
 * Initialises an in-memory tde_backup_header struct by:
 *  1. Generating a fresh DEK via the active KMS provider.
 *  2. Wrapping (encrypting) the DEK with the KEK held by the provider
 *     (AES-256-WRAP for the local wallet; Vault Transit /encrypt for vault).
 *  3. Storing the wrapped DEK in the header and the plaintext DEK in ctx->dek
 *     for subsequent use by tde_backup_encrypt_block().
 *
 * @param hdr     pointer to caller-allocated tde_backup_header struct
 * @param ctx     pointer to caller-allocated TdeBackupContext to populate
 * @returns       true on success
 */
bool
tde_backup_header_init(tde_backup_header *hdr, TdeBackupContext* ctx)
{
    unsigned char wrapped_dek[TDE_BACKUP_WRAPPED_LEN]; 

    int new_len = sizeof(wrapped_dek);

    Assert(hdr != NULL);

    memset(hdr, 0, sizeof(*hdr));

    sprintf(hdr->magic, TDE_BACKUP_MAGIC);
    hdr->format_version = TDE_BACKUP_FORMAT_VERSION;

    if(!dump_tde_active_provider->generate_dek(ctx->dek, TDE_DEK_LEN))
    {
        pg_log_error("[BACKUP] Failed to generate backup DEK");
        return false;
    }

    if(!dump_tde_active_provider->wrap_dek(ctx->dek, TDE_DEK_LEN, 
                                            wrapped_dek, &new_len))
    {
        pg_log_error("[BACKUP] Failed to wrap backup dek");
        return false;
    }

    memcpy(hdr->wrapped_dek, wrapped_dek, new_len);
    hdr->wrapped_dek_len = new_len;
    
    OPENSSL_cleanse(wrapped_dek, sizeof(wrapped_dek));

    dump_tde_active_provider->shutdown();
     
    return true;
}


/*
 * tde_backup_header_validate
 *
 * Validates a tde_backup_header read from a pg_dump_tde file: checks magic,
 * format version, and wrapped_dek_len, then unwraps the DEK via the active
 * KMS provider into ctx->dek.
 *
 * @param hdr     pointer to tde_backup_header read from the backup file
 * @param ctx     pointer to caller-allocated TdeBackupContext to populate
 * @returns       true on success, false if the header is invalid or DEK unwrap fails
 */

bool tde_backup_header_validate(tde_backup_header *hdr, TdeBackupContext* ctx)
{

    unsigned char dek[TDE_DEK_LEN];
    int dek_len = sizeof(dek);

    Assert(hdr != NULL);
    Assert(ctx != NULL);
    
    if(hdr->wrapped_dek_len > TDE_BACKUP_WRAPPED_LEN)
    {
        pg_log_error("pg_dump_tde: wrapped DEK too long");
        return false;
    }

    if(strcmp(hdr->magic, TDE_BACKUP_MAGIC) != 0) return false;
    if(hdr->format_version != TDE_BACKUP_FORMAT_VERSION) return false;

    if(!dump_tde_active_provider->unwrap_dek(hdr->wrapped_dek, hdr->wrapped_dek_len,
                                             dek, &dek_len))
    {
        pg_log_error("pg_dump_tde: cant unwrap DEK: wrong passphrase or corrupted wrapped dek");
        return false;
    }
    
    memcpy(ctx->dek, dek, TDE_DEK_LEN);
    ctx->dek_len = dek_len;
    
    OPENSSL_cleanse(dek, dek_len);

    return true;
}



/** Open a libpq connection; returns NULL and logs on failure. */
static PGconn* init_db_conn(ConnParams* params)
{
    PGconn* conn = PQsetdbLogin(params->pghost, params->pgport, NULL, NULL,
                                params->dbname, params->pguser, NULL);

    if (PQstatus(conn) != CONNECTION_OK)
    {
        fprintf(stderr, "pg_dump_tde: can't connect to the database: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }

    return conn;
}

/*
 * tde_backup_encrypt_block
 *
 * Encrypts one plaintext block using AES-256-GCM.  Generates a fresh random
 * IV per block.  Returns a palloc'd buffer (caller must pfree) with layout:
 *   [ 0x02 (1) | IV (12) | CT (block_len) | TAG (16) ]
 *
 * block_seq is encoded as big-endian uint64 and passed as GCM AAD, so
 * reordering or truncating blocks is detectable at decryption time.
 *
 * @param ctx           backup context holding the DEK
 * @param block_data    plaintext block
 * @param block_len     length of plaintext (up to TDE_BACKUP_BLOCK_SIZE)
 * @param block_seq     monotonically increasing block counter (used as AAD)
 * @param out_len       set to total encrypted output length on success
 * @returns             palloc'd encrypted buffer, or NULL on error
 */
char*
tde_backup_encrypt_block(const TdeBackupContext* tde_ctx,
                         const char *block_data, Size block_len,
                         uint64 block_seq, Size *out_len)
{  
    EVP_CIPHER_CTX  *evp_ctx;
    char*           out_buf;
    int             flen;
    int             olen;
    int             aad_len;
    Size            total;
    unsigned char*  iv_ptr;
    unsigned char*  ct_ptr;
    unsigned char*  tag_ptr;

    total = block_len + TDE_BACKUP_ENCRYPT_OVERHEAD;
    out_buf = (char*) palloc0(total);

    /* Write version byte. */
    ((unsigned char*) out_buf)[0] = TDE_V2_VERSION_BYTE;

    /* Set pointers to each field within the output buffer. */
    iv_ptr = (unsigned char *) out_buf + 1;
    ct_ptr = iv_ptr + TDE_GCM_IV_LEN;
    tag_ptr = ct_ptr + block_len;

    /* Generate per-block random IV */
    if (!pg_strong_random(iv_ptr, TDE_GCM_IV_LEN))
    {
        OPENSSL_cleanse(out_buf, total);
        pfree(out_buf);
        pg_log_error("pg_dump_tde: failed to generate random IV (entropy source unavailable)");
        return NULL;
    }

    if(dump_evp_ctx == NULL){
        dump_evp_ctx = EVP_CIPHER_CTX_new();
        if(dump_evp_ctx == NULL)
        {
            OPENSSL_cleanse(out_buf, total);
            pfree(out_buf);
            pg_log_error("pg_dump_tde: failed to allocate GCM encrypt context");
            return NULL;
        }
    }
    else 
    {
        EVP_CIPHER_CTX_reset(dump_evp_ctx);
    }
    evp_ctx = dump_evp_ctx;

    if(EVP_EncryptInit_ex2(evp_ctx, EVP_aes_256_gcm(), tde_ctx->dek, iv_ptr, NULL) != 1)
        goto gcm_error;

    /* Pass block_seq (big-endian) as GCM AAD. */
    uint64 seq_n = pg_hton64(block_seq);
    if(EVP_EncryptUpdate(evp_ctx, NULL, &aad_len, (const uint8 *) &seq_n, sizeof(seq_n)) != 1)
    {
        OPENSSL_cleanse(&seq_n, sizeof(seq_n));
        goto gcm_error;
    }
    OPENSSL_cleanse(&seq_n, sizeof(seq_n));

    /* Encrypt the payload. */
    if(EVP_EncryptUpdate(evp_ctx, ct_ptr, &olen,
                      (const unsigned char*) block_data, 
                      (int) block_len) != 1)
        goto gcm_error;
    
    if(EVP_EncryptFinal_ex(evp_ctx, ct_ptr + olen, &flen) != 1)
        goto gcm_error;

    if(flen != 0)
        goto gcm_error;

    if(EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, 
                         TDE_GCM_TAG_LEN, tag_ptr) != 1)
        goto gcm_error;

    *out_len = total;
    return out_buf;

gcm_error:
        EVP_CIPHER_CTX_free(evp_ctx);
        evp_ctx = NULL;
        dump_evp_ctx = NULL;
        OPENSSL_cleanse(out_buf, total);
        pfree(out_buf);
        pg_log_error("pg_dump_tde: error while encrypting a block");
        return NULL;
} 


/**
 * Decrypt one AES-256-GCM block produced by tde_backup_encrypt_block().
 *
 * Verifies the version byte, GCM tag, and block_seq AAD before returning
 * plaintext.  Returns a palloc'd buffer (caller must pfree), or NULL on
 * any authentication or decryption failure.
 *
 * @param ctx       backup context holding the DEK
 * @param block_data encrypted block (version byte + IV + CT + TAG)
 * @param block_len  total length of block_data
 * @param block_seq  expected block sequence number (AAD)
 * @param out_len    set to plaintext length on success
 */
char *tde_backup_decrypt_block(const TdeBackupContext* ctx,
                                const char* block_data, Size block_len,
                                uint64 block_seq, Size* out_len)
{
    EVP_CIPHER_CTX  *evp_ctx;
    const unsigned char* iv_ptr;
    const unsigned char* ct_ptr;
    const unsigned char* tag_ptr;   
    char* out_buf;
    Size pt_len;
    int olen = 0;
    int flen = 0;
    int aad_len = 0;
    uint64 seq_n;

    Assert(block_data != NULL);
    Assert(out_len != NULL);
    Assert(ctx->dek != NULL);
    Assert(ctx->dek_len == TDE_DEK_LEN);

    if(block_len < (Size)(TDE_BACKUP_ENCRYPT_OVERHEAD)){
        pg_log_error("pg_dump_tde: [CRYPTO] Ciphertext too short for AES-256-GCM");
        return NULL;
    }
        
    if((unsigned char) block_data[0] != TDE_V2_VERSION_BYTE)
    {
        pg_log_error("pg_dump_tde [CRYPTO]: error while decrypting");
        return NULL;
    }

    pt_len = block_len - TDE_BACKUP_ENCRYPT_OVERHEAD;
    iv_ptr = (const unsigned char* ) block_data + 1;
    ct_ptr = iv_ptr + TDE_GCM_IV_LEN;
    tag_ptr = ct_ptr + pt_len;

    out_buf = (char*) palloc0(pt_len + 1);

    if(dump_evp_ctx == NULL)
    {
        dump_evp_ctx = EVP_CIPHER_CTX_new();
        if(dump_evp_ctx == NULL)
        {
            pfree(out_buf);
            pg_log_error("pg_dump_tde [CRYPTO]: Failed to allocate GCM decrypt context");
            return NULL;
        }
    }
    else
    {
        EVP_CIPHER_CTX_reset(dump_evp_ctx);
    }
    evp_ctx = dump_evp_ctx;

    if(EVP_DecryptInit_ex2(evp_ctx, EVP_aes_256_gcm(), ctx->dek, iv_ptr, NULL) != 1)
        goto gcm_dec_error;
        
    /* Set the expected GCM tag BEFORE calling DecryptFinal. */
    if(EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, 
                        TDE_GCM_TAG_LEN, (void*) tag_ptr) != 1)
        goto gcm_dec_error;

    /* Reproduce the same AAD that was used during encryption. */
    seq_n = pg_hton64(block_seq);
    if(EVP_DecryptUpdate(evp_ctx, NULL, &aad_len, (const uint8 *)&seq_n, sizeof(seq_n)) != 1)
    {
        OPENSSL_cleanse(&seq_n, sizeof(seq_n));
        goto gcm_dec_error;
    }
    OPENSSL_cleanse(&seq_n, sizeof(seq_n));

    if(EVP_DecryptUpdate(evp_ctx, (unsigned char*)out_buf, &olen, 
                         ct_ptr, (int)pt_len) != 1)
        goto gcm_dec_error;
    
    if(EVP_DecryptFinal_ex(evp_ctx, (unsigned char*)out_buf + olen, &flen) != 1)
        goto gcm_dec_error;
    
    
    *out_len = pt_len;
    return out_buf;

gcm_dec_error:
    /*
     * Free and NULL-out the cached context — unknown state after an error.
     */
    EVP_CIPHER_CTX_free(dump_evp_ctx);
    dump_evp_ctx = NULL;
    evp_ctx = NULL;
    OPENSSL_cleanse(out_buf, pt_len + 1);
    pfree(out_buf);
    pg_log_error("[CRYPTO] AES-256-GCM decryption setup failed");
    return NULL; 

}
