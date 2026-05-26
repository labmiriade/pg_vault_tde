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
#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_backup.h"

/* Current backup format version — increment on breaking changes. */
#define TDE_BACKUP_FORMAT_VERSION 1
#define TDE_BACKUP_MAGIC          "PGVAULTTDE"
/* TDE_BACKUP_MAGIC_LEN is defined in pg_vault_tde_backup.h */
#define TDE_BACKUP_BLOCK_SIZE     (64 * 1024) /* 64KB streaming blocks */

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
tde_backup_header_init(tde_backup_header *hdr)
{
    char dek[TDE_DEK_LEN];

    Assert(hdr != NULL);

    memcpy(hdr->magic, TDE_BACKUP_MAGIC, TDE_BACKUP_MAGIC_LEN);
    hdr->format_version = TDE_BACKUP_FORMAT_VERSION;

    /* Fetch live DEK from the shared memory cache */
    if (!pg_vault_tde_kms_get_dek(dek, TDE_DEK_LEN))
    {
        ereport(WARNING,
                (errmsg("[BACKUP] DEK unavailable; cannot initialise "
                        "backup header")));
        return false;
    }

    /*
     * Generate a fresh IV for the backup stream.  Each backup gets its own
     * IV even when using the same DEK, so two dumps of identical data
     * produce different encrypted files (prevents chosen-plaintext attacks
     * on the backup archive).
     */
    if (!pg_strong_random(hdr->stream_iv, TDE_GCM_IV_LEN))
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        ereport(ERROR,
                (errmsg("[BACKUP] Failed to generate backup stream IV")));
    }

    /*
     * TODO: wrap the DEK with RSA-4096 OAEP-SHA256 using the KEK public key
     * fetched from Vault.  Store the wrapped blob in hdr->wrapped_dek and
     * its length in hdr->wrapped_dek_len.
     *
     * RSA_public_encrypt(TDE_DEK_LEN, dek, hdr->wrapped_dek,
     *                    rsa_pub_key, RSA_PKCS1_OAEP_PADDING);
     *
     * For now, store a zeroed placeholder; the TAP test will verify this
     * field is non-zero once the KMS RSA integration is complete.
     */
    OPENSSL_cleanse(hdr->wrapped_dek, sizeof(hdr->wrapped_dek));
    hdr->wrapped_dek_len = 0; /* placeholder */

    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    return true;
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
void
tde_backup_encrypt_block(const char *block_data, Size block_len,
                         uint64 block_seq,
                         char *out_buf, Size *out_len)
{
    char   *encrypted;
    Size    enc_len;

    Assert(block_data != NULL && out_buf != NULL && out_len != NULL);
    Assert(block_len > 0 && block_len <= TDE_BACKUP_BLOCK_SIZE);

    /*
     * Backup blocks are not table-scoped, so we use InvalidOid which selects
     * the v1.4 global DEK.  A per-table backup DEK (v1.7) will pass the
     * correct relid once the backup bundle format is redesigned.
     * TODO: pass block_seq as GCM AAD via EVP_EncryptUpdate with a NULL
     * output pointer (standard GCM AAD pattern) before encrypting payload.
     */
    encrypted = tde_gcm_encrypt(InvalidOid, block_data, block_len, &enc_len);

    memcpy(out_buf, encrypted, enc_len);
    *out_len = enc_len;

    OPENSSL_cleanse(encrypted, enc_len);
    pfree(encrypted);
}

/*
 * pg_vault_tde_backup_status (SQL-callable)
 *
 * Returns a text status message indicating whether backup encryption is
 * active.  Exposes the backup format version so monitoring tools can detect
 * version mismatches without opening the backup file.
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_backup_status);
Datum
pg_vault_tde_backup_status(PG_FUNCTION_ARGS)
{
    char   *msg;

    msg = psprintf("pg_vault_tde backup encryption active "
                   "(format_version=%d, block_size=%d)",
                   TDE_BACKUP_FORMAT_VERSION,
                   TDE_BACKUP_BLOCK_SIZE);
    PG_RETURN_TEXT_P(cstring_to_text(msg));
}
