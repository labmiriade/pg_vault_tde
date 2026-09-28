/*
 * pg_dump_tde_kms_local.c — PKCS#12 wallet KMS provider for pg_dump_tde.
 *
 * Implements PdeKmsProvider using a PKCS#12 file as the Key Encryption Key
 * (KEK) store.  The KEK is a raw 32-byte private key stored inside the
 * wallet.  DEK wrapping uses AES-256-WRAP (RFC 3394).
 *
 * The wallet passphrase is read from exactly one of:
 *   1. GUC pg_vault_tde.wallet_passphrase_command  (shell command, stdout)
 *   2. GUC pg_vault_tde.wallet_passphrase_env      (environment variable name)
 *   3. GUC pg_vault_tde.wallet_passphrase_file     (file path, mode 0400/0600)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */

#include "postgres_fe.h"
#include "common/logging.h"
#include "common/fe_memutils.h"
#include "pg_dump_tde_kms.h"

#include <stdio.h>              /* popen / pclose for passphrase_command */
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/hmac.h>       /* HMAC-SHA256 for bundle authentication */
#include <openssl/aes.h>        /* EVP_aes_256_wrap */
#include <openssl/crypto.h>

#define KEK_LEN 32

/*
 * The server keeps every KEK version in the wallet (PSQLE-185): one PKCS#12
 * key bag per version, friendlyName "pg_vault_tde_kek.v<N>", current first; a
 * wallet written before 1.7.2 has one bag, "pg_vault_tde_kek", version 1.  A
 * dump taken before a KEK rotation carries a DEK wrapped under an older
 * version, so unwrap tries them all, newest first; wrap uses the current one.
 */
#define KEK_BAG_NAME        "pg_vault_tde_kek"
#define KEK_MAX_VERSIONS    256

typedef struct KekRing
{
    int           n;
    unsigned int  version[KEK_MAX_VERSIONS];      /* [0] is current */
    unsigned char kek[KEK_MAX_VERSIONS][KEK_LEN];
} KekRing;

#define LOCAL_ENV_MAX       256
#define LOCAL_CMD_MAX      1024
#define LOCAL_PATH_MAX     1024

typedef struct PdeLocalConfig
{
    char    passphrase_env[LOCAL_ENV_MAX];
    char    passphrase_command[LOCAL_CMD_MAX];
    char    passphrase_file[LOCAL_PATH_MAX];
    char    wallet_path[LOCAL_PATH_MAX];
} PdeLocalConfig;

static PdeLocalConfig* config = NULL;


static bool     local_init(PGconn* conn);
static bool     pg_vault_tde_catalog_generate_dek(unsigned char* out, int len);
static bool     local_wrap_dek(const unsigned char* dek, int dek_len,
                                unsigned char* out, int* out_len);
static bool     local_unwrap_dek(const unsigned char* wrapped_dek, int wrapped_len,
                                 unsigned char* dek_out, int *dek_len);
static bool     local_config_load(PGconn* conn, PdeLocalConfig* config);
static bool     local_get_passphrase(char *pass_out, Size pass_max);
static bool     local_passphrase_from_command(char *pass_out, Size pass_max);
static bool     local_passphrase_from_file(char *pass_out, Size pass_max);
static bool     local_passphrase_from_env(char *pass_out, Size pass_max);
static bool     local_open_wallet_ring(const char* path, const char* passphrase,
                                       KekRing* out);
static bool     local_open_wallet(const char* path, const char* passphrase, 
                                  unsigned char* kek_out);
static bool     local_wrap_dek_with_pass(const unsigned char *dek, int dek_len,
                         unsigned char *wrapped_out, int *out_len,
                         const char *passphrase, const char *wallet_path);
static bool     local_unwrap_dek_with_pass(const unsigned char* wrapped_dek, int wrapped_len,
                                            unsigned char* dek_out, int *dek_len,
                                            const char* passphrase, const char* wallet_path);
static void     local_shutdown(void);



/**
 * Unwrap a DEK from @wrapped_dek using AES-256-WRAP with the KEK from the wallet.
 *
 * @param wrapped_dek   wrapped DEK blob (from tde_backup_header.wrapped_dek)
 * @param wrapped_len   length of wrapped_dek
 * @param dek_out       output buffer for the recovered plaintext DEK
 * @param dek_len       capacity of dek_out (must be >= TDE_DEK_LEN)
 * @param passphrase    PKCS#12 wallet passphrase
 * @param wallet_path   path to the .p12 wallet file
 */
static bool local_unwrap_dek_with_pass(const unsigned char* wrapped_dek, int wrapped_len,
                                        unsigned char* dek_out, int *dek_len,
                                        const char* passphrase, const char* wallet_path)
{
    KekRing        *ring;
    EVP_CIPHER_CTX *evp_ctx;
    bool            ok = false;
    int             i;

    Assert(wrapped_dek != NULL);
    Assert(dek_out != NULL && dek_len != NULL);
    Assert(passphrase != NULL);
    Assert(wallet_path != NULL);

    ring = (KekRing *) pg_malloc0(sizeof(KekRing));
    if(!local_open_wallet_ring(wallet_path, passphrase, ring))
    {
        pg_free(ring);
        pg_log_error("pg_dump_tde: local_unwrap_dek_with_pass: "
                     "could not open wallet \"%s\"", wallet_path);
        return false;
    }

    evp_ctx = EVP_CIPHER_CTX_new();
    if(!evp_ctx)
    {
        OPENSSL_cleanse(ring, sizeof(KekRing));
        pg_free(ring);
        pg_log_error("pg_dump_tde: cant allocate CIPHER_CTX");
        return false;
    }

    /* AES key wrap's integrity check rejects every version but the right one. */
    for(i = 0; i < ring->n && !ok; i++)
    {
        int update_len = 0;
        int final_len = 0;

        if(EVP_DecryptInit_ex2(evp_ctx, EVP_aes_256_wrap(), ring->kek[i], NULL, NULL) == 1 &&
           EVP_DecryptUpdate(evp_ctx, dek_out, &update_len, wrapped_dek, wrapped_len) == 1 &&
           EVP_DecryptFinal_ex(evp_ctx, dek_out + update_len, &final_len) == 1)
        {
            *dek_len = update_len + final_len;
            ok = true;
        }
        else
            ERR_clear_error();
    }
    if(!ok)
        pg_log_error("pg_dump_tde: AES-256-UNWRAP failed with all %d KEK "
                     "version(s) of the wallet (wrong passphrase or corrupt "
                     "wrapped DEK)", ring->n);

    EVP_CIPHER_CTX_free(evp_ctx);
    OPENSSL_cleanse(ring, sizeof(KekRing));
    pg_free(ring);
    return ok;
}

/**
 * PdeKmsProvider.unwrap_dek — recover DEK from header using wallet + passphrase.
 * Reads passphrase via local_get_passphrase() (env/command/file priority order).
 */
static bool local_unwrap_dek(const unsigned char* wrapped_dek, int wrapped_len,
                             unsigned char* dek_out, int *dek_len)
{
    const char* path;
    char pass[1024];
    bool ok;

    Assert(wrapped_dek != NULL);
    Assert(dek_out != NULL && dek_len != NULL);

    if(!local_get_passphrase(pass, sizeof(pass)))
    {
        pg_log_error("pg_dump_tde: local unwrap_dek: passphrase unavailable");
        return false;
    }

    path = config->wallet_path[0] ? config->wallet_path : NULL;

    if(!path)
    {
        pg_log_error("pg_dump_tde: cannot find the wallet at \"%s\"", path);
        return false;
    } 


    ok = local_unwrap_dek_with_pass(wrapped_dek, 
                                    wrapped_len, 
                                    dek_out, 
                                    dek_len, 
                                    pass, 
                                    path);

    OPENSSL_cleanse(pass, sizeof(pass));
    return ok;
}


/** PdeKmsProvider.shutdown — cleanse and free config. */
static void local_shutdown(void)
{
    OPENSSL_cleanse(config, sizeof(*config));
    pfree(config);
    config = NULL;
}

/**
 * Wrap @dek using AES-256-WRAP (RFC 3394) with the KEK from the wallet.
 * Output is always dek_len + 8 bytes (AES-WRAP overhead).
 *
 * @param dek           plaintext DEK to wrap
 * @param dek_len       must equal TDE_DEK_LEN
 * @param wrapped_out   output buffer (capacity set via *out_len on entry)
 * @param out_len       on exit: bytes written to wrapped_out
 * @param passphrase    PKCS#12 wallet passphrase
 * @param wallet_path   path to the .p12 wallet file
 */
static bool local_wrap_dek_with_pass(const unsigned char *dek, int dek_len,
                         unsigned char *wrapped_out, int *out_len,
                         const char *passphrase, const char *wallet_path)
{
    unsigned char   kek[KEK_LEN];
    EVP_CIPHER_CTX *ctx;
    int             update_len = 0;
    int             final_len = 0;
    bool            ok = false;

    Assert(dek != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(wrapped_out != NULL);
    Assert(out_len != NULL);
    Assert(passphrase != NULL);
    Assert(wallet_path != NULL);

    if(!local_open_wallet(wallet_path, passphrase, kek))
    {
        pg_log_error("pg_dump_tde: could not open wallet \"%s\"", wallet_path);
        return false;
    }

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    {
        OPENSSL_cleanse(kek, KEK_LEN);
        pg_log_error("pg_dump_tde: error while creating CIPHER_CTX");
        return false;
    }

     /*
     * AES-256-WRAP (RFC 3394) via OpenSSL 3.x EVP interface.
     * EVP_aes_256_wrap() uses the default IV 0xA6A6A6A6A6A6A6A6.
     * Output is always plaintext_len + 8 = LOCAL_WRAPPED_DEK_LEN bytes.
     */

    if(EVP_EncryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL) == 1 &&
       EVP_EncryptUpdate(ctx, wrapped_out, &update_len, dek, dek_len) == 1 &&
       EVP_EncryptFinal_ex(ctx, wrapped_out + update_len, &final_len) == 1 )
    {
        *out_len = update_len + final_len;
        ok = true;
    }
    else
    {
        pg_log_error("pg_dump_tde: AES-256-WRAP encryption failed: %s", 
                     ERR_reason_error_string(ERR_get_error()));
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(kek, KEK_LEN);

    return ok;
}

                                  
/**
 * Parse a PKCS#12 wallet and extract the raw 32-byte private key as the KEK.
 *
 * @param path       path to the .p12 wallet file
 * @param passphrase wallet passphrase (verified via PKCS12_verify_mac)
 * @param kek_out    output buffer; must be at least KEK_LEN bytes
 */
static bool local_open_wallet_ring(const char* path, const char* passphrase,
                                   KekRing* out)
{
    FILE            *fp;
    PKCS12          *p12;
    STACK_OF(PKCS7) *asafes;
    int              i, j;

    Assert(path != NULL);
    Assert(passphrase != NULL);
    Assert(out != NULL);

    memset(out, 0, sizeof(KekRing));

    fp = fopen(path, "rb");
    if(!fp)
    {
        pg_log_error("pg_dump_tde: cannot open wallet \"%s\"", path);
        return false;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    if(!p12)
    {
        pg_log_error("pg_dump_tde: failed to parse PKCS#12 wallet \"%s\"", path);
        return false;
    }

    if(!PKCS12_verify_mac(p12, passphrase, -1))
    {
        PKCS12_free(p12);
        pg_log_error("pg_dump_tde: wallet MAC verification failed - "
                     "wrong passphrase or corrupt wallet");
        return false;
    }

    asafes = PKCS12_unpack_authsafes(p12);
    PKCS12_free(p12);
    if(!asafes)
    {
        pg_log_error("pg_dump_tde: PKCS#12 parsing failed");
        return false;
    }

    for(i = 0; i < sk_PKCS7_num(asafes); i++)
    {
        PKCS7                    *p7 = sk_PKCS7_value(asafes, i);
        STACK_OF(PKCS12_SAFEBAG) *bags = NULL;

        if(PKCS7_type_is_data(p7))
            bags = PKCS12_unpack_p7data(p7);
        else if(PKCS7_type_is_encrypted(p7))
            bags = PKCS12_unpack_p7encdata(p7, passphrase, -1);
        if(!bags)
            continue;

        for(j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++)
        {
            PKCS12_SAFEBAG            *bag = sk_PKCS12_SAFEBAG_value(bags, j);
            PKCS8_PRIV_KEY_INFO       *shrouded = NULL;
            const PKCS8_PRIV_KEY_INFO *p8 = NULL;
            EVP_PKEY                  *pkey;
            char                      *name;
            unsigned int               version = 0;
            char                       tail;
            size_t                     klen = KEK_LEN;

            if(PKCS12_SAFEBAG_get_nid(bag) == NID_pkcs8ShroudedKeyBag)
                p8 = shrouded = PKCS12_decrypt_skey(bag, passphrase, -1);
            else if(PKCS12_SAFEBAG_get_nid(bag) == NID_keyBag)
                p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
            if(!p8)
                continue;

            pkey = EVP_PKCS82PKEY(p8);
            if(shrouded)
                PKCS8_PRIV_KEY_INFO_free(shrouded);
            name = PKCS12_get_friendlyname(bag);

            if(name && strcmp(name, KEK_BAG_NAME) == 0)
                version = 1;
            else if(name && sscanf(name, KEK_BAG_NAME ".v%u%c", &version, &tail) != 1)
                version = 0;

            if(pkey && version > 0 && out->n < KEK_MAX_VERSIONS &&
               EVP_PKEY_get_raw_private_key(pkey, out->kek[out->n], &klen) == 1 &&
               klen == KEK_LEN)
            {
                out->version[out->n] = version;
                out->n++;
            }
            if(name)
                OPENSSL_free(name);
            if(pkey)
                EVP_PKEY_free(pkey);
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }
    sk_PKCS7_pop_free(asafes, PKCS7_free);

    if(out->n == 0)
    {
        pg_log_error("pg_dump_tde: wallet \"%s\" holds no KEK", path);
        return false;
    }

    /* Newest first, whatever order the file had. */
    for(i = 1; i < out->n; i++)
        for(j = i; j > 0 && out->version[j] > out->version[j - 1]; j--)
        {
            unsigned int  v = out->version[j];
            unsigned char k[KEK_LEN];

            out->version[j]     = out->version[j - 1];
            out->version[j - 1] = v;
            memcpy(k, out->kek[j], KEK_LEN);
            memcpy(out->kek[j], out->kek[j - 1], KEK_LEN);
            memcpy(out->kek[j - 1], k, KEK_LEN);
            OPENSSL_cleanse(k, KEK_LEN);
        }

    return true;
}

/* The current KEK — what a new dump wraps its DEK with. */
static bool local_open_wallet(const char* path, const char* passphrase,
                                unsigned char* kek_out)
{
    KekRing *ring = (KekRing *) pg_malloc0(sizeof(KekRing));
    bool     ok   = local_open_wallet_ring(path, passphrase, ring);

    if(ok)
        memcpy(kek_out, ring->kek[0], KEK_LEN);
    OPENSSL_cleanse(ring, sizeof(KekRing));
    pg_free(ring);
    return ok;
}

/*
 * local_passphrase_from_env — read passphrase from an environment variable.
 */
static bool
local_passphrase_from_env(char *pass_out, Size pass_max)
{
    const char *env_name;
    const char *env_val;

    env_name = config->passphrase_env;
    if (!env_name || env_name[0] == '\0')
        return false;

    env_val = getenv(env_name);
    if (!env_val || env_val[0] == '\0')
        return false;

    strncpy(pass_out, env_val, pass_max - 1);
    pass_out[pass_max - 1] = '\0';
    return true;
}

/*
 * local_passphrase_from_file — read passphrase from a file.
 *
 * GUC wallet_passphrase_file is the absolute path.  File must be
 * mode 0400 or 0600 (owner-only); wider permissions trigger WARNING.
 * Leading/trailing whitespace (including newline) is stripped.
 */
static bool
local_passphrase_from_file(char *pass_out, Size pass_max)
{
    const char *fpath;
    FILE       *fp;
    struct stat st;
    size_t      n;
    char       *p;
    int         fd;

    fpath = config->passphrase_file;
    if (!fpath || fpath[0] == '\0')
        return false;

    /*
     * Open first, validate the descriptor afterwards. Checking the path with
     * stat() and opening it in a second step leaves a window in which the path
     * can be repointed at a different file, so the permissions that get
     * approved need not be those of the file actually read. O_NOFOLLOW refuses
     * a symlink outright: a passphrase file is never legitimately one.
     */
    fd = open(fpath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
    {
        pg_log_error("pg_vault_tde: cannot open passphrase file \"%s\": %m",
                       fpath);
        return false;
    }

    /* Permission sanity check, against the descriptor actually opened */
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        pg_log_error("pg_vault_tde: passphrase file \"%s\": %m", fpath);
        return false;
    }
    if ((st.st_mode & 0777) & ~0600){
        pg_log_error("pg_vault_tde: passphrase file \"%s\" is mode %04o; "
                       "expected 0400 or 0600 (owner-only)",
                       fpath, (unsigned)(st.st_mode & 0777));
        close(fd);
        return false;
    }
    if ((st.st_mode & 0777) & 0044)  /* group/other readable */
    {
        pg_log_error("pg_vault_tde: passphrase file \"%s\" is group- or "
                       "world-readable (mode %04o); refusing to read passphrase",
                       fpath, (unsigned)(st.st_mode & 0777));
        close(fd);
        return false;
    }

    fp = fdopen(fd, "r");
    if (!fp)
    {
        close(fd);
        pg_log_error("pg_vault_tde: cannot open passphrase file \"%s\": %m",
                       fpath);
        return false;
    }

    n = fread(pass_out, 1, pass_max - 1, fp);
    fclose(fp);
    pass_out[n] = '\0';

    /* Strip trailing whitespace (newline, spaces) */
    p = pass_out + n;
    while (p > pass_out && (p[-1] == '\n' || p[-1] == '\r' ||
                            p[-1] == ' '  || p[-1] == '\t'))
        *--p = '\0';

    return pass_out[0] != '\0';
}


/*
 * local_passphrase_from_command — run a shell command and read stdout as
 * the passphrase.
 *
 * GUC wallet_passphrase_command is the shell command.  Stdout is read,
 * trimmed, and returned.  The command runs in a popen() subprocess.
 * Analogous to PostgreSQL's ssl_passphrase_command.
 */
static bool
local_passphrase_from_command(char *pass_out, Size pass_max)
{
    const char *cmd;
    FILE       *fp;
    size_t      n;
    char       *p;

    cmd = config->passphrase_command;
    if (!cmd || cmd[0] == '\0')
        return false;

    fp = popen(cmd, "r");
    if (!fp)
    {
        pg_log_error("pg_vault_tde: passphrase_command popen() failed");
        return false;
    }

    n = fread(pass_out, 1, pass_max - 1, fp);
    pclose(fp);
    pass_out[n] = '\0';

    p = pass_out + n;
    while (p > pass_out && (p[-1] == '\n' || p[-1] == '\r' ||
                            p[-1] == ' '  || p[-1] == '\t'))
        *--p = '\0';

    if (pass_out[0] == '\0')
    {
        pg_log_error("pg_vault_tde: passphrase_command produced empty output");
        return false;
    }
    return true;
}

/**
 * Read the wallet passphrase from the configured source (command > env > file).
 * Exactly one source must be configured; logs an error if multiple are set.
 *
 * @param pass_out  output buffer to fill with the passphrase
 * @param pass_max  capacity of pass_out (including NUL terminator)
 */
static bool local_get_passphrase(char *pass_out, Size pass_max)
{
    int active_sources = 0;

    bool has_env = (config->passphrase_env[0] != '\0');

    bool has_command = (config->passphrase_command[0] != '\0');

    bool has_file = (config->passphrase_file[0] != '\0');
    
    if(has_env) active_sources++;
    if(has_command) active_sources++;
    if(has_file) active_sources++;

    if(active_sources > 1)
    {
        pg_log_error("pg_vault_tde: multiple wallet passphrase sources "
                       "are configured (command=%s, env=%s, file=%s); "
                       "set at most one",
                       has_command ? "yes" : "no",
                       has_env     ? "yes" : "no",
                       has_file    ? "yes" : "no");
        return false;
    }
        
    if(has_command && local_passphrase_from_command(pass_out, pass_max))
        return true;
    
    if(has_env && local_passphrase_from_env(pass_out, pass_max))
        return true;

    if(has_file && local_passphrase_from_file(pass_out, pass_max))
        return true;

    pg_log_error("pg_dump_tde: no wallet passphrase source configured "
                 "or all sources failed");

    return false;
}


/** Read all local-wallet GUCs from @conn into @config via LOAD_PARAM. */
static bool local_config_load(PGconn* conn, PdeLocalConfig* config)
{
    LOAD_PARAM(passphrase_env,      "pg_vault_tde.wallet_passphrase_env");
    LOAD_PARAM(passphrase_command,   "pg_vault_tde.wallet_passphrase_command");
    LOAD_PARAM(passphrase_file,     "pg_vault_tde.wallet_passphrase_file");
    LOAD_PARAM(wallet_path,         "pg_vault_tde.wallet_path");

    return true;
}

/** PdeKmsProvider.generate_dek — fill @out with @len random bytes via pg_strong_random(). */
static bool
pg_vault_tde_catalog_generate_dek(unsigned char *out, int len)
{
    Assert(out != NULL);
    Assert(len == TDE_DEK_LEN);

    if (!pg_strong_random(out, len))
    {
        pg_log_error("pg_dump_tde: error while generating DEK");
        return false;
    }
    return true;
}

/** PdeKmsProvider.wrap_dek — read passphrase, open wallet, AES-256-WRAP the DEK. */
static bool
local_wrap_dek(const unsigned char *dek, int dek_len,
               unsigned char *out, int *out_len)
{   
    const char* path;
    char pass[1024];
    bool ok;

    Assert(dek != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(out != NULL);
    Assert(out_len != NULL);

    if(!local_get_passphrase(pass, sizeof(pass)))
    {
        pg_log_error("pg_dump_tde: local wrap_dek: passphrase unavailable");
        return false;
    }

    path = config->wallet_path[0] ? config->wallet_path : NULL;

    if(!path)
    {
        pg_log_error("pg_dump_tde: cannot find the wallet at \"%s\"", path);
        return false;
    } 


    ok = local_wrap_dek_with_pass(dek, dek_len, out, out_len,
                                    pass, path);

    OPENSSL_cleanse(pass, sizeof(pass));
    return ok;
}

/** PdeKmsProvider.init — allocate config and load GUCs from @conn. */
static bool local_init(PGconn *conn)
{
    config = palloc0(sizeof(PdeLocalConfig));
    if(!local_config_load(conn, config))
    {
        OPENSSL_cleanse(config, sizeof(*config));
        pfree(config);
        config = NULL;
        return false;
    }
    return true;
}

static const PdeKmsProvider local_provider_impl = {
    .name           = "local",
    .init           = local_init, 
    .generate_dek   = pg_vault_tde_catalog_generate_dek, 
    .wrap_dek       = local_wrap_dek, 
    .unwrap_dek     = local_unwrap_dek,
    .shutdown       = local_shutdown, 
};

const PdeKmsProvider * 
pg_dump_tde_kms_local_provider(void)
{
    return &local_provider_impl;
}