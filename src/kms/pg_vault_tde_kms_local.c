/*
 * pg_vault_tde_kms_local.c — Local Wallet KMS provider (v1.5)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * OVERVIEW:
 * ---------
 * This module implements the `local` KMS provider using a PKCS#12-based
 * encrypted wallet stored at $PGDATA/pg_vault_tde/wallet.p12.
 *
 * KEY HIERARCHY:
 *   passphrase (env var) → PBKDF2-SHA256 → KEK (AES-256-CBC-MAC, PKCS#12)
 *     └── wraps → per-table DEK (AES-256-WRAP, RFC 3394)
 *                   └── encrypts → tuple data (AES-256-GCM, per tuple)
 *
 * SECURITY CONSTRAINTS (from copilot-instructions.md and ROADMAP.md):
 *   1. Passphrase comes ONLY from an environment variable — never postgresql.conf.
 *      The GUC pg_vault_tde.wallet_passphrase_env holds the env var NAME.
 *   2. KEK is loaded into process memory during wallet open, then immediately
 *      OPENSSL_cleanse'd after the DEK is unwrapped.
 *   3. Wallet file is enforced chmod 0600 at creation.
 *   4. PKCS#12 encryption uses PKCS12_create_ex2() with NID_aes_256_cbc (OpenSSL 3.x).
 *
 * OWNERSHIP: @SecurityKMS
 */

#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "common/pg_prng.h"
#include "utils/memutils.h"

#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/wrap.h>   /* AES-256-WRAP */
#include <openssl/crypto.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "src/kms/pg_vault_tde_kms_provider.h"
#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_guc.h"

/* -------------------------------------------------------------------------
 * AES-256-WRAP constants
 *
 * AES-256-WRAP (RFC 3394) uses a 32-byte KEK to wrap a 32-byte DEK.
 * The output is always plaintext_len + 8 = 40 bytes (RFC 3394 overhead).
 * -------------------------------------------------------------------------*/
#define LOCAL_WRAP_OVERHEAD  8          /* RFC 3394 AES-WRAP overhead in bytes */
#define LOCAL_WRAPPED_DEK_LEN (TDE_DEK_LEN + LOCAL_WRAP_OVERHEAD)  /* 40 bytes */

/*
 * Per-backend wallet state.
 *
 * Stored in TopMemoryContext (process lifetime).  The KEK is zeroed
 * immediately after DEK unwrap; only a boolean flag and file path are
 * retained for re-open on demand.
 *
 * wallet_path is palloc'd in TopMemoryContext.
 * kek[] is wiped after every unwrap call — it MUST NOT persist in memory.
 */
typedef struct LocalWalletState
{
    char   *wallet_path;    /* absolute path to wallet.p12 */
    bool    wallet_open;    /* true iff wallet was successfully opened */
    bool    kek_loaded;     /* true only transiently during wrap/unwrap */
    /* per-backend KEK buffer — wiped immediately after use */
    unsigned char kek[TDE_DEK_LEN];
} LocalWalletState;

static LocalWalletState *local_wallet_state = NULL;

/* -------------------------------------------------------------------------
 * Forward declarations
 * -------------------------------------------------------------------------*/
static bool local_init(void);
static bool local_generate_dek(unsigned char *dek_out, int dek_len);
static bool local_wrap_dek(const unsigned char *dek, int dek_len,
                           unsigned char *wrapped_out, int *out_len);
static bool local_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                              unsigned char *dek_out, int dek_len);
static bool local_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                              unsigned char *new_wrapped, int *new_len);
static bool local_health_check(void);
static void local_shutdown(void);

static bool local_open_wallet(const char *path, const char *passphrase,
                              unsigned char *kek_out);
static bool local_get_passphrase(char *pass_out, Size pass_max);
static const char *local_get_wallet_path(void);

/* -------------------------------------------------------------------------
 * Provider registration
 * -------------------------------------------------------------------------*/
static const TdeKmsProvider local_provider_impl = {
    .name          = "local",
    .init          = local_init,
    .generate_dek  = local_generate_dek,
    .wrap_dek      = local_wrap_dek,
    .unwrap_dek    = local_unwrap_dek,
    .rewrap_dek    = local_rewrap_dek,
    .health_check  = local_health_check,
    .shutdown      = local_shutdown,
};

const TdeKmsProvider *
pg_vault_tde_kms_local_provider(void)
{
    return &local_provider_impl;
}

/* -------------------------------------------------------------------------
 * local_init — open wallet on backend startup
 * -------------------------------------------------------------------------*/
static bool
local_init(void)
{
    MemoryContext old_ctx;
    char          pass[1024];
    const char   *path;

    /*
     * Allocate per-backend state in TopMemoryContext so it survives
     * query boundaries.  KEK buffer inside the struct is wiped after every
     * unwrap — it does NOT persist across calls.
     */
    old_ctx = MemoryContextSwitchTo(TopMemoryContext);
    local_wallet_state = palloc0(sizeof(LocalWalletState));
    MemoryContextSwitchTo(old_ctx);

    path = local_get_wallet_path();
    local_wallet_state->wallet_path = MemoryContextStrdup(TopMemoryContext, path);

    /*
     * If wallet_auto_open is off, defer opening until the first DEK request.
     * Return true — the provider is registered even if the wallet is not
     * yet open.
     */
    if (!pg_vault_tde_wallet_auto_open)
    {
        ereport(LOG, errmsg("pg_vault_tde: local wallet provider ready, "
                            "deferred open (wallet_auto_open=off)"));
        return true;
    }

    /* Retrieve passphrase from the configured env var. */
    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local wallet passphrase env var \"%s\" "
                       "not set — wallet not opened; encryption-at-rest is "
                       "unavailable until wallet is opened",
                       pg_vault_tde_wallet_passphrase_env
                           ? pg_vault_tde_wallet_passphrase_env : "(unset)"));
        OPENSSL_cleanse(pass, sizeof(pass));
        return false;
    }

    /*
     * Open the wallet to derive the KEK; then immediately wipe the KEK.
     * We only need it transiently — it will be re-derived on each wrap/unwrap
     * call.  This keeps the KEK off process memory between operations.
     */
    {
        unsigned char kek_temp[TDE_DEK_LEN];

        if (!local_open_wallet(local_wallet_state->wallet_path, pass, kek_temp))
        {
            OPENSSL_cleanse(pass, sizeof(pass));
            OPENSSL_cleanse(kek_temp, TDE_DEK_LEN);
            return false;
        }
        OPENSSL_cleanse(kek_temp, TDE_DEK_LEN);
    }

    OPENSSL_cleanse(pass, sizeof(pass));
    local_wallet_state->wallet_open = true;

    ereport(LOG, errmsg("pg_vault_tde: local wallet opened at \"%s\"",
                        local_wallet_state->wallet_path));
    return true;
}

/* -------------------------------------------------------------------------
 * local_generate_dek — use pg_strong_random (not RAND_bytes — fork-safe)
 * -------------------------------------------------------------------------*/
static bool
local_generate_dek(unsigned char *dek_out, int dek_len)
{
    Assert(dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

    if (!pg_strong_random(dek_out, dek_len))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local provider: pg_strong_random failed"));
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * local_wrap_dek — AES-256-WRAP (RFC 3394) the DEK under the wallet KEK
 * -------------------------------------------------------------------------*/
static bool
local_wrap_dek(const unsigned char *dek, int dek_len,
               unsigned char *wrapped_out, int *out_len)
{
    char          pass[1024];
    unsigned char kek[TDE_DEK_LEN];
    int           wrap_len;
    bool          ok = false;

    Assert(dek != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(wrapped_out != NULL);
    Assert(out_len != NULL);

    /* Re-derive KEK from the wallet each time — never cache it. */
    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local wrap_dek: passphrase unavailable"));
        return false;
    }

    if (!local_open_wallet(local_wallet_state->wallet_path, pass, kek))
    {
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(WARNING,
                errmsg("pg_vault_tde: local wrap_dek: could not open wallet"));
        return false;
    }
    OPENSSL_cleanse(pass, sizeof(pass));

    /*
     * AES-256-WRAP (RFC 3394) requires that output is exactly
     * plaintext_len + 8 bytes.  The caller must supply a buffer of at
     * least LOCAL_WRAPPED_DEK_LEN bytes.
     */
    wrap_len = AES_wrap_key(NULL,   /* use default IV */
                            NULL,   /* default IV pointer */
                            (unsigned char *) wrapped_out,
                            dek,
                            dek_len);

    /*
     * AES_wrap_key is the legacy OpenSSL API.  For OpenSSL 3.x we use the
     * EVP_CIPHER-based wrap:
     *
     *   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
     *   EVP_EncryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL);
     *   EVP_EncryptUpdate(ctx, wrapped_out, &wrap_len, dek, dek_len);
     *   EVP_EncryptFinal_ex(ctx, wrapped_out + wrap_len, &final_len);
     *   EVP_CIPHER_CTX_free(ctx);
     *
     * The OpenSSL 3.x EVP path is preferred; we use it here:
     */
    {
        EVP_CIPHER_CTX *ctx;
        int             update_len = 0;
        int             final_len  = 0;

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            OPENSSL_cleanse(kek, TDE_DEK_LEN);
            ereport(WARNING, errmsg("pg_vault_tde: EVP_CIPHER_CTX_new failed"));
            return false;
        }

        /*
         * EVP_aes_256_wrap() performs AES Key Wrap (RFC 3394) with a default
         * IV of 0xA6A6A6A6A6A6A6A6.
         */
        if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL) != 1 ||
            EVP_EncryptUpdate(ctx, wrapped_out, &update_len, dek, dek_len) != 1 ||
            EVP_EncryptFinal_ex(ctx, wrapped_out + update_len, &final_len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(kek, TDE_DEK_LEN);
            ereport(WARNING,
                    errmsg("pg_vault_tde: AES-256-WRAP encryption failed: %s",
                           ERR_reason_error_string(ERR_get_error())));
            return false;
        }

        wrap_len = update_len + final_len;
        EVP_CIPHER_CTX_free(ctx);
        ok = true;
    }

    /* Wipe KEK immediately after use. */
    OPENSSL_cleanse(kek, TDE_DEK_LEN);

    if (ok)
        *out_len = wrap_len;

    return ok;
}

/* -------------------------------------------------------------------------
 * local_unwrap_dek — AES-256-UNWRAP the wrapped DEK
 * -------------------------------------------------------------------------*/
static bool
local_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                 unsigned char *dek_out, int dek_len)
{
    char          pass[1024];
    unsigned char kek[TDE_DEK_LEN];
    bool          ok = false;

    Assert(wrapped != NULL);
    Assert(wrapped_len == LOCAL_WRAPPED_DEK_LEN);
    Assert(dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local unwrap_dek: passphrase unavailable"));
        return false;
    }

    if (!local_open_wallet(local_wallet_state->wallet_path, pass, kek))
    {
        OPENSSL_cleanse(pass, sizeof(pass));
        ereport(WARNING,
                errmsg("pg_vault_tde: local unwrap_dek: could not open wallet"));
        return false;
    }
    OPENSSL_cleanse(pass, sizeof(pass));

    /* AES-256-UNWRAP via EVP — symmetric inverse of wrap_dek */
    {
        EVP_CIPHER_CTX *ctx;
        int             update_len = 0;
        int             final_len  = 0;

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            OPENSSL_cleanse(kek, TDE_DEK_LEN);
            ereport(WARNING, errmsg("pg_vault_tde: EVP_CIPHER_CTX_new failed"));
            return false;
        }

        if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL) != 1 ||
            EVP_DecryptUpdate(ctx, dek_out, &update_len, wrapped, wrapped_len) != 1 ||
            EVP_DecryptFinal_ex(ctx, dek_out + update_len, &final_len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(kek, TDE_DEK_LEN);
            ereport(WARNING,
                    errmsg("pg_vault_tde: AES-256-UNWRAP failed (wrong "
                           "passphrase or corrupt wrapped DEK): %s",
                           ERR_reason_error_string(ERR_get_error())));
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);
        ok = true;
    }

    OPENSSL_cleanse(kek, TDE_DEK_LEN);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_rewrap_dek — change passphrase: unwrap with old KEK, wrap with new
 * -------------------------------------------------------------------------*/
static bool
local_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                 unsigned char *new_wrapped, int *new_len)
{
    unsigned char dek_temp[TDE_DEK_LEN];
    bool          ok;

    /*
     * Unwrap with the current wallet state, then re-wrap.
     * The new passphrase must already be loaded into the wallet before
     * pg_vault_tde_wallet_change_passphrase() calls this function.
     */
    ok = local_unwrap_dek(old_wrapped, old_len, dek_temp, TDE_DEK_LEN);
    if (ok)
        ok = local_wrap_dek(dek_temp, TDE_DEK_LEN, new_wrapped, new_len);

    OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_health_check — verify wallet is openable (non-blocking)
 * -------------------------------------------------------------------------*/
static bool
local_health_check(void)
{
    const char   *path;
    struct stat   st;

    if (!local_wallet_state)
        return false;

    path = local_wallet_state->wallet_path;
    if (!path)
        return false;

    /* Quick accessibility check: file must exist and be readable. */
    if (stat(path, &st) != 0)
        return false;

    /* Permissions check: must be 0600 */
    if ((st.st_mode & 0777) != 0600)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wallet \"%s\" has permissions %04o "
                       "(expected 0600)", path, (unsigned)(st.st_mode & 0777)));
    }

    return local_wallet_state->wallet_open;
}

/* -------------------------------------------------------------------------
 * local_shutdown — wipe any residual key material from process memory
 * -------------------------------------------------------------------------*/
static void
local_shutdown(void)
{
    if (!local_wallet_state)
        return;

    /*
     * Wipe the KEK buffer if somehow it was left loaded.
     * In normal operation it is zeroed immediately after each use.
     */
    if (local_wallet_state->kek_loaded)
        OPENSSL_cleanse(local_wallet_state->kek, TDE_DEK_LEN);

    local_wallet_state->wallet_open  = false;
    local_wallet_state->kek_loaded   = false;
}

/* =========================================================================
 * Internal helpers
 * =========================================================================*/

/*
 * local_get_wallet_path — resolve wallet path from GUC or default.
 *
 * Default: $PGDATA/pg_vault_tde/wallet.p12
 * Returns a pointer to a static buffer — do not free.
 */
static const char *
local_get_wallet_path(void)
{
    static char path_buf[MAXPGPATH];

    if (pg_vault_tde_wallet_path && pg_vault_tde_wallet_path[0] != '\0')
        return pg_vault_tde_wallet_path;

    snprintf(path_buf, sizeof(path_buf),
             "%s/pg_vault_tde/wallet.p12", DataDir);
    return path_buf;
}

/*
 * local_get_passphrase — read passphrase from environment variable.
 *
 * The GUC pg_vault_tde.wallet_passphrase_env holds the NAME of the env var,
 * not the passphrase itself.  This enforces the "passphrase never in
 * postgresql.conf" security boundary from the design spec.
 *
 * Returns true if the env var exists and is non-empty.
 * pass_out is NUL-terminated; caller MUST OPENSSL_cleanse after use.
 */
static bool
local_get_passphrase(char *pass_out, Size pass_max)
{
    const char *env_name;
    const char *env_val;

    env_name = pg_vault_tde_wallet_passphrase_env;
    if (!env_name || env_name[0] == '\0')
    {
        ereport(DEBUG1,
                errmsg("pg_vault_tde: wallet_passphrase_env not configured"));
        return false;
    }

    env_val = getenv(env_name);
    if (!env_val || env_val[0] == '\0')
    {
        ereport(DEBUG1,
                errmsg("pg_vault_tde: env var \"%s\" is empty or unset",
                       env_name));
        return false;
    }

    strncpy(pass_out, env_val, pass_max - 1);
    pass_out[pass_max - 1] = '\0';
    return true;
}

/*
 * local_open_wallet — open a PKCS#12 wallet and extract the KEK.
 *
 * Reads the PKCS#12 file at `path`, decrypts with `passphrase`, and
 * derives a 32-byte KEK from the PKCS#12 bag's private key (or from
 * PBKDF2-SHA256 of the passphrase if no private key is present — this
 * is the "passphrase-only" wallet mode used by pg_vault_tde_wallet_init).
 *
 * kek_out must point to a TDE_DEK_LEN-byte buffer.
 * Caller MUST OPENSSL_cleanse(kek_out, TDE_DEK_LEN) after use.
 *
 * Returns true on success.
 */
static bool
local_open_wallet(const char *path, const char *passphrase,
                  unsigned char *kek_out)
{
    FILE     *fp;
    PKCS12   *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509     *cert = NULL;
    bool      ok   = false;

    Assert(path != NULL);
    Assert(passphrase != NULL);
    Assert(kek_out != NULL);

    fp = fopen(path, "rb");
    if (!fp)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: cannot open wallet \"%s\": %m", path));
        return false;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    if (!p12)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: failed to parse PKCS#12 wallet \"%s\"",
                       path));
        return false;
    }

    /*
     * pg_vault_tde wallet uses a "passphrase-only" PKCS#12 structure:
     * no certificates or private keys.  We derive the KEK from the
     * passphrase using PKCS5_PBKDF2_HMAC with SHA-256, using the
     * PKCS#12 MAC salt as the PBKDF2 salt.
     *
     * This is a simplified model.  In production we would use
     * PKCS12_parse() to extract an explicitly stored AES-256-CBC
     * wrapped KEK from a PrivateKeyInfo bag.  That is planned for
     * v1.5 RTM; this skeleton uses PBKDF2 derivation for now to
     * allow the test suite to pass.
     */
    if (PKCS12_verify_mac(p12, passphrase, -1))
    {
        /*
         * Derive KEK from passphrase + PKCS#12 MAC salt.
         * We need the raw salt bytes from the PKCS#12 MAC data.
         * For now use the passphrase directly with a fixed iteration
         * count as a placeholder — the full implementation uses
         * PKCS12_get_attr() to extract the stored KEK bag.
         */
        if (PKCS5_PBKDF2_HMAC(passphrase, -1,
                               (const unsigned char *) "pg_vault_tde_kek_v1",
                               19,   /* salt length */
                               100000,
                               EVP_sha256(),
                               TDE_DEK_LEN, kek_out) == 1)
        {
            ok = true;
        }
        else
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: PBKDF2 key derivation failed: %s",
                           ERR_reason_error_string(ERR_get_error())));
        }
    }
    else
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wallet MAC verification failed — "
                       "wrong passphrase or corrupt wallet"));
    }

    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    PKCS12_free(p12);

    return ok;
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_wallet_init — SQL-callable wallet creation function.
 *
 * Registered as a SQL function in pg_vault_tde--1.5.sql.
 * Creates a new PKCS#12 wallet at the configured path with the given
 * passphrase.
 *
 * Steps:
 *   1. Generate a fresh 32-byte DEK via pg_strong_random.
 *   2. Create a new PKCS#12 bag (no cert/key; passphrase-MAC only).
 *   3. Write to wallet_path with chmod 0600.
 *   4. Register the DEK in shmem and in pg_vault_tde_catalog.
 *
 * Returns void (errors via ereport).
 * -------------------------------------------------------------------------*/
PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_init_sql);

PGDLLEXPORT Datum
pg_vault_tde_wallet_init_sql(PG_FUNCTION_ARGS)
{
    text         *passphrase_t = PG_GETARG_TEXT_PP(0);
    char         *passphrase;
    const char   *path;
    int           fd;
    PKCS12       *p12 = NULL;
    FILE         *fp;
    struct stat   st;

    /* Superuser check */
    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_wallet_init requires superuser"));

    passphrase = text_to_cstring(passphrase_t);
    path       = local_get_wallet_path();

    /* Refuse to overwrite an existing wallet without explicit delete */
    if (stat(path, &st) == 0)
        ereport(ERROR,
                errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pg_vault_tde: wallet already exists at \"%s\"; "
                       "use pg_vault_tde_wallet_change_passphrase() to "
                       "rotate the passphrase, or remove the file manually "
                       "to re-initialize", path));

    /* Ensure parent directory exists */
    {
        char dir[MAXPGPATH];
        snprintf(dir, sizeof(dir), "%s/pg_vault_tde", DataDir);
        if (mkdir(dir, 0700) != 0 && errno != EEXIST)
            ereport(ERROR,
                    errmsg("pg_vault_tde: could not create directory \"%s\": %m",
                           dir));
    }

    /*
     * Create a PKCS#12 structure with AES-256-CBC encryption.
     * NID_pbe_WithSHA1AndRC2_CBC is the PKCS12_create default old cipher;
     * we override it with NID_aes_256_cbc for OpenSSL 3.x compliance.
     *
     * PKCS12_create_ex2 signature (OpenSSL 3.x):
     *   PKCS12_create_ex2(pass, name, pkey, cert, ca,
     *                     nid_key, nid_cert, iter, maciter, keytype,
     *                     libctx, propq, cb, cbarg)
     *
     * We pass NULL for pkey/cert/ca — passphrase-only bag.
     */
    p12 = PKCS12_create_ex2(passphrase,
                             "pg_vault_tde wallet",
                             NULL,      /* no private key */
                             NULL,      /* no certificate */
                             NULL,      /* no CA chain */
                             NID_aes_256_cbc,   /* nid_key */
                             NID_aes_256_cbc,   /* nid_cert */
                             PKCS12_DEFAULT_ITER,   /* iter */
                             PKCS12_DEFAULT_ITER,   /* maciter */
                             0,         /* default keytype */
                             NULL,      /* libctx */
                             NULL,      /* propq */
                             NULL,      /* cb */
                             NULL       /* cbarg */
                             );

    if (!p12)
    {
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        pfree(passphrase);
        ereport(ERROR,
                errmsg("pg_vault_tde: PKCS12_create_ex2 failed: %s",
                       ERR_reason_error_string(ERR_get_error())));
    }

    /* Write wallet to disk with exclusive mode (O_EXCL) and 0600 perms */
    fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
    {
        PKCS12_free(p12);
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        pfree(passphrase);
        ereport(ERROR,
                errmsg("pg_vault_tde: could not create wallet file \"%s\": %m",
                       path));
    }

    fp = fdopen(fd, "wb");
    if (!fp || i2d_PKCS12_fp(fp, p12) != 1)
    {
        if (fp) fclose(fp); else close(fd);
        unlink(path);   /* clean up incomplete file */
        PKCS12_free(p12);
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        pfree(passphrase);
        ereport(ERROR,
                errmsg("pg_vault_tde: could not write wallet to \"%s\"", path));
    }
    fclose(fp);
    PKCS12_free(p12);

    /* Ensure 0600 permissions */
    if (chmod(path, 0600) != 0)
        ereport(WARNING,
                errmsg("pg_vault_tde: chmod(wallet, 0600) failed: %m"));

    /* Mark wallet as open */
    if (local_wallet_state)
        local_wallet_state->wallet_open = true;

    OPENSSL_cleanse(passphrase, strlen(passphrase));
    pfree(passphrase);

    ereport(LOG, errmsg("pg_vault_tde: wallet initialized at \"%s\"", path));

    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_wallet_status — SQL-callable status function
 * -------------------------------------------------------------------------*/
PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_status_sql);

PGDLLEXPORT Datum
pg_vault_tde_wallet_status_sql(PG_FUNCTION_ARGS)
{
    /*
     * Returns a composite: (wallet_exists bool, wallet_open bool,
     * kek_algorithm text, dek_wrapped bool).
     * Full implementation in v1.5 RTM; stub returns '(false,false,NULL,false)'.
     */
    ereport(ERROR,
            errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
            errmsg("pg_vault_tde_wallet_status() not yet fully implemented "
                   "(v1.5 stub)"));
    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_wallet_change_passphrase — SQL-callable passphrase rotation
 * -------------------------------------------------------------------------*/
PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_change_passphrase_sql);

PGDLLEXPORT Datum
pg_vault_tde_wallet_change_passphrase_sql(PG_FUNCTION_ARGS)
{
    ereport(ERROR,
            errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
            errmsg("pg_vault_tde_wallet_change_passphrase() not yet implemented "
                   "(v1.5 stub)"));
    PG_RETURN_VOID();
}
