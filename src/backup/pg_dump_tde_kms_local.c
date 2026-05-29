/*
 * pg_dump_tde_kms_local.c — PCKS#12 KMS provider for pg_dump_tde.
 *
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
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/hmac.h>       /* HMAC-SHA256 for bundle authentication */
#include <openssl/aes.h>        /* EVP_aes_256_wrap */
#include <openssl/crypto.h>

#define KEK_LEN 32

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
static bool     local_generate_dek(unsigned char* out, int len);
static bool     local_wrap_dek(const unsigned char* dek, int dek_len,
                                unsigned char* out, int* out_len);
static bool     local_config_load(PGconn* conn, PdeLocalConfig* config);
static bool     local_get_passphrase(char *pass_out, Size pass_max);
static bool     local_passphrase_from_command(char *pass_out, Size pass_max);
static bool     local_passphrase_from_file(char *pass_out, Size pass_max);
static bool     local_passphrase_from_env(char *pass_out, Size pass_max);
static bool     local_open_wallet(const char* path, const char* passphrase, 
                                  unsigned char* kek_out);
static bool     local_wrap_dek_with_pass(const unsigned char *dek, int dek_len,
                         unsigned char *wrapped_out, int *out_len,
                         const char *passphrase, const char *wallet_path);
static void     local_shutdown(void);

static void local_shutdown(void)
{
    OPENSSL_cleanse(config, sizeof(*config));
    pfree(config);
    config = NULL;
}

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

                                  
static bool local_open_wallet(const char* path, const char* passphrase, 
                                unsigned char* kek_out)
{
    FILE    *fp;
    PKCS12  *p12        = NULL;
    EVP_PKEY *pkey       = NULL;
    X509    *cert       = NULL;
    STACK_OF(X509) *ca  = NULL;
    bool   ok          = false;
    unsigned char kek_buffer[KEK_LEN];
    size_t kek_len     = sizeof(kek_buffer);

    Assert(path != NULL);
    Assert(passphrase != NULL);
    Assert(kek_out != NULL);

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

    /* Verify if the password opens the wallet */
    if(PKCS12_verify_mac(p12, passphrase, -1))
    {
        if(PKCS12_parse(p12, passphrase, &pkey, &cert, &ca)){
            if(EVP_PKEY_get_raw_private_key(pkey, kek_buffer, &kek_len) != 1)
                pg_log_error("pg_dump_tde: error while extracting the kek");
            else 
                ok = true;
        }
        else
            pg_log_error("pg_dump_tde: PKCS#12 parsing failed");
    }
    else    
        pg_log_error("pg_dump_tde: wallet MAC verification failed - "
                     "wrong passphrase or corrupt wallet");

    if(pkey) EVP_PKEY_free(pkey);
    if(cert) X509_free(cert);
    if(ca) sk_X509_pop_free(ca, X509_free);
    
    PKCS12_free(p12);
   
    memcpy(kek_out, kek_buffer, kek_len);

    OPENSSL_cleanse(kek_buffer, kek_len);
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

    fpath = config->passphrase_file;
    if (!fpath || fpath[0] == '\0')
        return false;

    /* Permission sanity check */
    if (stat(fpath, &st) != 0)
    {
        pg_log_error("pg_vault_tde: passphrase file \"%s\": %m", fpath);
        return false;
    }
    if ((st.st_mode & 0777) & ~0600)
        pg_log_error("pg_vault_tde: passphrase file \"%s\" is mode %04o; "
                       "expected 0400 or 0600 (owner-only)",
                       fpath, (unsigned)(st.st_mode & 0777));
    if ((st.st_mode & 0777) & 0044)  /* group/other readable */
    {
        pg_log_error("pg_vault_tde: passphrase file \"%s\" is group- or "
                       "world-readable (mode %04o); refusing to read passphrase",
                       fpath, (unsigned)(st.st_mode & 0777));
    }

    fp = fopen(fpath, "r");
    if (!fp)
    {
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
        pg_log_error("pg_vault_tde: multiple wallet passphrase sources "
                       "are configured (command=%s, env=%s, file=%s); "
                       "set at most one",
                       has_command ? "yes" : "no",
                       has_env     ? "yes" : "no",
                       has_file    ? "yes" : "no");

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


static bool local_config_load(PGconn* conn, PdeLocalConfig* config)
{
    LOAD_PARAM(passphrase_env,      "pg_vault_tde.wallet_passphrase_env");
    LOAD_PARAM(passphrase_command,   "pg_vault_tde.wallet_passphrase_command");
    LOAD_PARAM(passphrase_file,     "pg_vault_tde.wallet_passphrase_file");
    LOAD_PARAM(wallet_path,         "pg_vault_tde.wallet_path");

    return true;
}

static bool 
local_generate_dek(unsigned char *out, int len)
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
    .generate_dek   = local_generate_dek, 
    .wrap_dek       = local_wrap_dek, 
    .shutdown       = local_shutdown, 
};

const PdeKmsProvider * 
pg_dump_tde_kms_local_provider(void)
{
    return &local_provider_impl;
}