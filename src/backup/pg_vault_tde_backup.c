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
#include "fe_utils/connect_utils.h"
#include "common/logging.h"
#include "port/pg_bswap.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include "pg_vault_tde_backup.h"
#include "pg_dump_tde_kms.h"

static PGconn *init_db_conn(ConnParams *params);

const PdeKmsProvider* dump_tde_active_provider = NULL;
static EVP_CIPHER_CTX* dump_evp_ctx = NULL;

/*
 * tde_backup_init
 * 
 * Initalises the backup operation, opening the 
 * db connection and defining the kms operator 
 * that will provide DEK and KEK.
 * 
 * @param params    pointer to ConnParams struct with connection info
 * @returns         true on success
 * 
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
 *  1. Fetching the current DEK from shared memory.
 *  2. Fetching the RSA-4096 public key (KEK pub) from Vault.
 *  3. Encrypting (wrapping) the DEK with RSA-OAEP-SHA256.
 *  4. Storing the wrapped DEK and a fresh GCM IV in the header.
 *
 * The caller MUST OPENSSL_cleanse the local DEK copy immediately after this
 * function returns (see: dek[] in the caller's stack frame).
 *
 * @param hdr     pointer to caller-allocated tde_backup_header struct
 * @returns       true on success, false if DEK unavailable
 */
bool
tde_backup_header_init(tde_backup_header *hdr, TdeBackupContext* ctx)
{
    unsigned char wrapped_dek[TDE_BACKUP_WRAPPED_LEN]; 

    int new_len = sizeof(wrapped_dek);

    Assert(hdr != NULL);

    memcpy(hdr->magic, TDE_BACKUP_MAGIC, TDE_BACKUP_MAGIC_LEN);
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

/* Utility to open a connection to the db */
static PGconn* init_db_conn(ConnParams* params)
{
    PGconn* conn = connectDatabase(params, "pg_dump_tde", false, true, false);

    if(PQstatus(conn) != CONNECTION_OK)
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
 * Encrypts one TDE_BACKUP_BLOCK_SIZE block from an open pg_dump stream.
 * Produces an authenticated ciphertext block written to @out_buf.
 * Returns the number of encrypted bytes written (always
 * block_len + TDE_GCM_OVERHEAD).
 *
 * Because each block uses the same stream IV + a block counter as GCM AAD
 * (additional authenticated data), reordering or truncating blocks is
 * detectable at decryption time.
 *
 * @param block_data    plaintext block
 * @param block_len     length of plaintext (up to TDE_BACKUP_BLOCK_SIZE)
 * @param block_seq     block sequence number (used as AAD; prevents reorder)
 * @param out_buf       caller-allocated output buffer
 *                      (must be at least block_len + TDE_GCM_OVERHEAD)
 * @param out_len       set to encrypted output length
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

    total = block_len + TDE_V2_OVERHEAD;
    out_buf = (char*) palloc0(total);

    /*Calculate ptr position for every component of the layout*/
    iv_ptr = (unsigned char *) out_buf + TDE_V2_GEN_LEN;
    ct_ptr = iv_ptr + TDE_GCM_IV_LEN;
    tag_ptr = ct_ptr + block_len;

    /* Generate per-block random IV */
    pg_strong_random(iv_ptr, TDE_GCM_IV_LEN);

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

    /* Use block_seq as AAD*/
    uint64 seq_n = pg_hton64(block_seq);
    if(EVP_EncryptUpdate(evp_ctx, NULL, &aad_len, (const uint8 *) &seq_n, sizeof(seq_n)) != 1)
    {
        OPENSSL_cleanse(&seq_n, sizeof(seq_n));
        goto gcm_error;
    }
    OPENSSL_cleanse(&seq_n, sizeof(seq_n));

    /*Actual encrypting of payload*/
    if(EVP_EncryptUpdate(evp_ctx, ct_ptr, &olen,
                      (const unsigned char*) block_data, 
                      (int) block_len) != 1)
        goto gcm_error;
    
    if(EVP_EncryptFinal_ex(evp_ctx, ct_ptr + olen, &flen) != 1)
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

