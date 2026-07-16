/*
 * pg_vault_tde_seal.c - Physical backup key sealing
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License.
 *
 * Provides three SQL-callable functions to accompany a pg_basebackup:
 *   pg_vault_tde_seal_keys(dest, seal_passphrase, label)
 *   pg_vault_tde_seal_keys_bytea(seal_passphrase, label)
 *   pg_vault_tde_unseal_keys(src, seal_passphrase)
 *
 * The bundle contains ONLY the wrapped DEKs (every kms_provider), signed with
 * HMAC-SHA256 (key = PBKDF2 of seal_passphrase).  The KEK is never included:
 * it stays in the KMS/wallet and is provisioned on the standby separately.
 *
 * seal_keys writes the bundle to a server-side file; seal_keys_bytea returns
 * the same bundle as bytea so a remote client (pg_basebackup_tde) can store
 * it next to the backup on the client host.  Both share seal_build_bundle().
 */
#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"              /* superuser() */
#include "lib/stringinfo.h"         /* StringInfo */
#include "utils/builtins.h"         /* text_to_cstring */
#include "utils/timestamp.h"        /* GetCurrentTimestamp */
#include "port/pg_bswap.h"          /* pg_hton32/64, pg_ntoh16/32/64 */
#include "varatt.h"                 /* VARSIZE_ANY_EXHDR, VARDATA_ANY, SET_VARSIZE */
#include <fcntl.h>                  /* open, O_WRONLY|O_CREAT|O_TRUNC */
#include <unistd.h>                 /* unlink, close */

#include <openssl/hmac.h>           /* HMAC-SHA256 */
#include <openssl/evp.h>            /* PKCS5_PBKDF2_HMAC */
#include <openssl/crypto.h>         /* OPENSSL_cleanse, CRYPTO_memcmp */

#include "src/include/pg_vault_tde_catalog.h"  /* pg_vault_tde_catalog_evict_all  pg_vault_tde_catalog_read_all_wrapped*/


/* --- Bundle format constants (independent from the local-wallet bundle) --- */
#define SEAL_MAGIC        "TDESEAL"     /* 8 bytes incl. trailing NUL padding */
#define SEAL_MAGIC_LEN    8
#define SEAL_VERSION      0x01
#define SEAL_LABEL_LEN    63            /* NUL-padded */
#define SEAL_HMAC_SALT    "tde-seal-hmac-v1"
#define SEAL_HMAC_LEN     32            /* HMAC-SHA256 */
#define SEAL_PBKDF2_ITERS 600000        /* match LOCAL_PBKDF2_ITERS */

/*
 * Derive the 32-byte HMAC key from the seal passphrase (PBKDF2-SHA256).
 * The passphrase buffer is always cleansed here, including on the error path.
 */
static void
seal_derive_hmac_key(char *pass, size_t passbuf_len, unsigned char *hmac_key)
{
    int ok = PKCS5_PBKDF2_HMAC(pass, strlen(pass),
                               (unsigned char *) SEAL_HMAC_SALT,
                               strlen(SEAL_HMAC_SALT),
                               SEAL_PBKDF2_ITERS, EVP_sha256(), 32, hmac_key);

    OPENSSL_cleanse(pass, passbuf_len);
    if (ok != 1)
        ereport(ERROR, errmsg("pg_vault_tde: seal_keys: PBKDF2 for HMAC key failed"));
}

/*
 * Serialize all wrapped DEKs (every provider) into a signed bundle:
 *   magic(8) | ver(1) | label(63) | ts(8 BE) | count(4 BE)
 *   per row: relid(4 BE) | generation(8 BE) | prov_len(1) | provider | wdek_len(2 BE) | wdek
 *   HMAC-SHA256(32) over all preceding bytes
 *
 * Returns the bundle as bytea in the caller's memory context; *nrows_out
 * reports how many catalog rows were sealed.  Runs its own SPI session.
 */
static bytea *
seal_build_bundle(unsigned char *hmac_key, const char *label, int *nrows_out)
{
    StringInfoData buf;
    unsigned char hmac_out[SEAL_HMAC_LEN];
    unsigned int  hmac_len;
    bytea  *bundle;
    TdeCatalogSealRow *rows = NULL;
    int     nrows;
    int     i;

    initStringInfo(&buf);

    /* Enumerate ALL providers; rows without a wrapped DEK are skipped */
    nrows = pg_vault_tde_catalog_read_all_wrapped(&rows);

    /* Header: magic(8) | ver(1) | label(63) | ts(8 BE) | count(4 BE) */
    {
        char     label_buf[SEAL_LABEL_LEN];
        uint8    ver = SEAL_VERSION;
        uint32   nrows_be = pg_hton32((uint32) nrows);
        int64    ts = (int64) GetCurrentTimestamp();
        uint64   ts_be = pg_hton64((uint64) ts);

        appendBinaryStringInfo(&buf, SEAL_MAGIC, SEAL_MAGIC_LEN);
        appendBinaryStringInfo(&buf, (char *) &ver, 1);
        memset(label_buf, 0, sizeof(label_buf));
        strlcpy(label_buf, label, sizeof(label_buf));
        appendBinaryStringInfo(&buf, label_buf, SEAL_LABEL_LEN);
        appendBinaryStringInfo(&buf, (char *) &ts_be, 8);
        appendBinaryStringInfo(&buf, (char *) &nrows_be, 4);
    }

    /* Rows: relid(4 BE) | generation(8 BE) | prov_len(1) | provider | wdek_len(2 BE) | wdek */
    for (i = 0; i < nrows; i++)
    {
        TdeCatalogSealRow *r = &rows[i];
    
        uint32     relid_be = pg_hton32(r->relid);
        uint64     gen_be   = pg_hton64(r->generation);
        uint32     wdek_len = VARSIZE_ANY_EXHDR(r->wrapped_dek);
        uint16     wdek_len_be = pg_hton16((uint16) wdek_len);
        uint32     prov_len = strlen(r->kms_provider);
        uint8      prov_len8;
    
        if (prov_len > 255)
        {
            OPENSSL_cleanse(hmac_key, 32);
            ereport(ERROR, errmsg("pg_vault_tde: seal_keys: provider name too long"));
        }
        if (wdek_len > PG_UINT16_MAX)
        {
            OPENSSL_cleanse(hmac_key, 32);
            ereport(ERROR, errmsg("pg_vault_tde: seal_keys: wrapped DEK too long"));
        }
        prov_len8 = (uint8) prov_len;
    
        appendBinaryStringInfo(&buf, (char *) &relid_be, 4);
        appendBinaryStringInfo(&buf, (char *) &gen_be, 8);
        appendBinaryStringInfo(&buf, (char *) &prov_len8, 1);
        appendBinaryStringInfo(&buf, r->kms_provider, prov_len);
        appendBinaryStringInfo(&buf, (char *) &wdek_len_be, 2);
        appendBinaryStringInfo(&buf, VARDATA_ANY(r->wrapped_dek), wdek_len);
    }

    /* HMAC-SHA256 trailer over everything appended so far */
    if (HMAC(EVP_sha256(), hmac_key, 32,
             (unsigned char *) buf.data, buf.len,
             hmac_out, &hmac_len) == NULL || hmac_len != SEAL_HMAC_LEN)
    {
        OPENSSL_cleanse(hmac_key, 32);
        ereport(ERROR, errmsg("pg_vault_tde: seal_keys: HMAC computation failed"));
    }
    OPENSSL_cleanse(hmac_key, 32);
    appendBinaryStringInfo(&buf, (char *) hmac_out, SEAL_HMAC_LEN);

    bundle = (bytea *) palloc(VARHDRSZ + buf.len);
    SET_VARSIZE(bundle, VARHDRSZ + buf.len);
    memcpy(VARDATA(bundle), buf.data, buf.len);
    pfree(buf.data);

    *nrows_out = nrows;
    return bundle;
}

PG_FUNCTION_INFO_V1(pg_vault_tde_seal_keys_sql);
PGDLLEXPORT Datum
pg_vault_tde_seal_keys_sql(PG_FUNCTION_ARGS)
{
    text   *dest_t  = PG_GETARG_TEXT_PP(0);
    text   *pass_t  = PG_GETARG_TEXT_PP(1);
    text   *label_t = PG_GETARG_TEXT_PP(2);
    char   *dest    = text_to_cstring(dest_t);
    char    pass[1024];
    char   *label   = text_to_cstring(label_t);
    FILE   *bf;
    unsigned char hmac_key[32];
    bytea  *bundle;
    size_t  bundle_len;
    int     nrows;

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_seal_keys requires superuser"));


    {
        char *pass_tmp = text_to_cstring(pass_t);

        strlcpy(pass, pass_tmp, sizeof(pass));
        OPENSSL_cleanse(pass_tmp, strlen(pass_tmp));
    }


    seal_derive_hmac_key(pass, sizeof(pass), hmac_key);
    bundle = seal_build_bundle(hmac_key, label, &nrows);
    bundle_len = VARSIZE_ANY_EXHDR(bundle);

    /*
     * Create with mode 0600 atomically (no fopen()+chmod() window during
     * which the file would sit at the umask-default, more permissive mode).
     * No O_EXCL: re-sealing to the same dest_path to realign after a KEK/DEK
     * rotation (see the README "Key-rotation note") must keep overwriting.
     */
    {
        int fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0600);

        if (fd < 0)
            ereport(ERROR,
                    errmsg("pg_vault_tde: seal_keys: could not open \"%s\" for write: %m", dest));
        bf = fdopen(fd, "wb");
        if (!bf)
        {
            close(fd);
            ereport(ERROR, errmsg("pg_vault_tde: seal_keys: fdopen(\"%s\") failed: %m", dest));
        }
    }
    if (fwrite(VARDATA_ANY(bundle), 1, bundle_len, bf) != bundle_len)
    {
        fclose(bf); unlink(dest);
        ereport(ERROR, errmsg("pg_vault_tde: seal_keys: write error on \"%s\": %m", dest));
    }
    fclose(bf);
    pfree(bundle);

    ereport(LOG,
            errmsg("pg_vault_tde: sealed %d wrapped DEK(s) to \"%s\"", nrows, dest));

    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pg_vault_tde_seal_keys_bytea_sql);
PGDLLEXPORT Datum
pg_vault_tde_seal_keys_bytea_sql(PG_FUNCTION_ARGS)
{
    text   *pass_t  = PG_GETARG_TEXT_PP(0);
    text   *label_t = PG_GETARG_TEXT_PP(1);
    char    pass[1024];
    char   *label   = text_to_cstring(label_t);
    unsigned char hmac_key[32];
    bytea  *bundle;
    int     nrows;

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_seal_keys_bytea requires superuser"));

    {
        char *pass_tmp = text_to_cstring(pass_t);

        strlcpy(pass, pass_tmp, sizeof(pass));
        OPENSSL_cleanse(pass_tmp, strlen(pass_tmp));
    }

    seal_derive_hmac_key(pass, sizeof(pass), hmac_key);
    bundle = seal_build_bundle(hmac_key, label, &nrows);

    ereport(LOG,
            errmsg("pg_vault_tde: sealed %d wrapped DEK(s) to bytea bundle", nrows));

    PG_RETURN_BYTEA_P(bundle);
}

PG_FUNCTION_INFO_V1(pg_vault_tde_unseal_keys_sql);
PGDLLEXPORT Datum
pg_vault_tde_unseal_keys_sql(PG_FUNCTION_ARGS)
{

    text   *src_t  = PG_GETARG_TEXT_PP(0);
    text   *pass_t = PG_GETARG_TEXT_PP(1);
    char   *src    = text_to_cstring(src_t);
    char    pass[1024];
    FILE   *bf;
    long    fsize;
    unsigned char *buf;
    unsigned char  hmac_key[32];
    unsigned char  hmac_computed[SEAL_HMAC_LEN];
    unsigned int   hmac_len;
    size_t  pos;
    uint32  count;
    uint32  i;
    int     imported = 0;

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_unseal_keys requires superuser"));

    {
        char *pass_tmp = text_to_cstring(pass_t);

        strlcpy(pass, pass_tmp, sizeof(pass));
        OPENSSL_cleanse(pass_tmp, strlen(pass_tmp));
    }

    /* Read whole file */
    bf = fopen(src, "rb");
    if (!bf)
    {
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(ERROR, errmsg("pg_vault_tde: unseal_keys: could not open \"%s\": %m", src));
    }
    fseek(bf, 0, SEEK_END);
    fsize = ftell(bf);
    fseek(bf, 0, SEEK_SET);

    /* Minimum: magic(8)+ver(1)+label(63)+ts(8)+count(4)+hmac(32) = 116 */
    if (fsize < 116)
    {
        fclose(bf);
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(ERROR, errmsg("pg_vault_tde: unseal_keys: \"%s\" too small (corrupt)", src));
    }
    buf = palloc(fsize);
    if ((long) fread(buf, 1, fsize, bf) != fsize)
    {
        fclose(bf);
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(ERROR, errmsg("pg_vault_tde: unseal_keys: short read on \"%s\"", src));
    }
    fclose(bf);

    /* Magic */
    if (memcmp(buf, SEAL_MAGIC, SEAL_MAGIC_LEN) != 0)
    {
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(ERROR, 
            errcode(ERRCODE_DATA_CORRUPTED),
            errmsg("pg_vault_tde: unseal_keys: bad magic in \"%s\"", src));
    }

    /* Version: this parser only knows the v1 layout */
    if (buf[SEAL_MAGIC_LEN] != SEAL_VERSION)
    {
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(ERROR,
                errcode(ERRCODE_DATA_CORRUPTED),
                errmsg("pg_vault_tde: unseal_keys: unsupported bundle version %u (expected %u)",
                        (unsigned) buf[SEAL_MAGIC_LEN], (unsigned) SEAL_VERSION));
    }

    /* Derive HMAC key and verify the trailer BEFORE trusting any field */
    if (PKCS5_PBKDF2_HMAC(pass, strlen(pass),
                        (unsigned char *) SEAL_HMAC_SALT, strlen(SEAL_HMAC_SALT),
                        SEAL_PBKDF2_ITERS, EVP_sha256(), 32, hmac_key) != 1)
    {
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(ERROR, errmsg("pg_vault_tde: unseal_keys: PBKDF2 failed"));
    }
    OPENSSL_cleanse(pass, sizeof(pass));
    {
        HMAC_CTX *hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx, hmac_key, 32, EVP_sha256(), NULL);
        HMAC_Update(hctx, buf, (size_t)(fsize - SEAL_HMAC_LEN));
        HMAC_Final(hctx, hmac_computed, &hmac_len);
        HMAC_CTX_free(hctx);
    }
    OPENSSL_cleanse(hmac_key, 32);

    if (CRYPTO_memcmp(hmac_computed, buf + fsize - SEAL_HMAC_LEN, SEAL_HMAC_LEN) != 0)
    {
        pfree(buf);
        ereport(ERROR,
                errcode(ERRCODE_DATA_CORRUPTED),
                errmsg("pg_vault_tde: unseal_keys: HMAC verification failed — "
                        "wrong passphrase or tampered file"));
    }

    /* Parse header */
    pos = SEAL_MAGIC_LEN;           /* skip magic */
    pos += 1;                       /* version */
    pos += SEAL_LABEL_LEN;          /* label */
    pos += 8;                       /* timestamp */
    memcpy(&count, buf + pos, 4);
    count = pg_ntoh32(count);
    pos += 4;

    /* Rows */

    for (i = 0; i < count; i++)
    {
        Oid     rel_oid;
        uint64  gen;
        uint32  relid_be;
        uint64  gen_be;
        uint8   prov_len;
        char    provbuf[64];
        uint16  wdek_len_be;
        uint16  wdek_len;
        bytea  *wdek_b;

        /* bounds: relid(4)+gen(8)+prov_len(1) */
        if (pos + 13 > (size_t)(fsize - SEAL_HMAC_LEN)) break;
        memcpy(&relid_be, buf + pos, 4); rel_oid = pg_ntoh32(relid_be); pos += 4;
        memcpy(&gen_be,   buf + pos, 8); gen = pg_ntoh64(gen_be);       pos += 8;
        prov_len = buf[pos]; pos += 1;

        if (prov_len >= sizeof(provbuf) ||
            pos + prov_len + 2 > (size_t)(fsize - SEAL_HMAC_LEN)) break;
        memcpy(provbuf, buf + pos, prov_len); provbuf[prov_len] = '\0'; pos += prov_len;

        memcpy(&wdek_len_be, buf + pos, 2); wdek_len = pg_ntoh16(wdek_len_be); pos += 2;
        if (pos + wdek_len > (size_t)(fsize - SEAL_HMAC_LEN)) break;

        wdek_b = (bytea *) palloc(VARHDRSZ + wdek_len);
        SET_VARSIZE(wdek_b, VARHDRSZ + wdek_len);
        memcpy(VARDATA(wdek_b), buf + pos, wdek_len); pos += wdek_len;

        pg_vault_tde_catalog_upsert_row(rel_oid, gen, wdek_b, provbuf);
        imported++;
    }

    pfree(buf);

    pg_vault_tde_catalog_evict_all();

    ereport(LOG,
            errmsg("pg_vault_tde: unsealed %d wrapped DEK(s) from \"%s\"", imported, src));

    PG_RETURN_VOID();
}
