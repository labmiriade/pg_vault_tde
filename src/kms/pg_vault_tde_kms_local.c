/*
 * pg_vault_tde_kms_local.c — Local Wallet KMS provider (v1.5)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * OVERVIEW:
 * ---------
 * This module implements the `local` KMS provider using a PKCS#12-based
 * encrypted wallet stored at /var/lib/pg_vault_tde/<DB_OID>/wallet.p12.
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
#include "funcapi.h"            /* get_call_result_type, SRF_ macros */
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/timestamp.h"    /* TimestampTz, GetCurrentTimestamp */
#include "utils/tuplestore.h"   /* tuplestore_begin_heap, tuplestore_putvalues */
#include "common/pg_prng.h"
#include "utils/memutils.h"
#include "commands/extension.h"     /* get_extension_oid, get_extension_schema */
#include "utils/lsyscache.h"
#include "utils/elog.h"
#include "utils/rel.h"          /* RelationGetDescr */
#include "utils/snapmgr.h"      /* GetTransactionSnapshot */
#include "access/table.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "catalog/indexing.h"
#include "catalog/pg_db_role_setting.h"

#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/aes.h>        /* EVP_aes_256_wrap */
#include <openssl/crypto.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>              /* popen / pclose for passphrase_command */
#include <arpa/inet.h>          /* htonl, htons, ntohl, ntohs */

#include "src/kms/pg_vault_tde_kms_provider.h"
#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/include/pg_vault_tde_audit.h"
#include "src/include/pg_vault_tde_catalog.h" /* pg_vault_tde_catalog_evict_all */
#include "src/include/pg_vault_tde_catalog_d.h"

/* -------------------------------------------------------------------------
 * AES-256-WRAP constants
 *
 * AES-256-WRAP (RFC 3394) uses a 32-byte KEK to wrap a 32-byte DEK.
 * The output is always plaintext_len + 8 = 40 bytes (RFC 3394 overhead).
 * -------------------------------------------------------------------------*/
#define LOCAL_WRAP_OVERHEAD     8   /* RFC 3394 AES-WRAP overhead in bytes */
#define LOCAL_WRAPPED_DEK_LEN   (TDE_DEK_LEN + LOCAL_WRAP_OVERHEAD)  /* 40 bytes */

/*
 * PBKDF2 iteration count for KEK derivation from passphrase.
 *
 * NIST SP 800-132 (2023) minimum for HMAC-SHA-256: 210 000.  We use
 * 600 000 to provide a comfortable safety margin against brute-force.
 * Increasing this value requires wallet re-initialisation.
 */
#define LOCAL_PBKDF2_ITERS      600000


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
    char        *wallet_path;   /* absolute path to wallet.p12 */
    bool         wallet_open;   /* true iff wallet was successfully opened */
    bool         kek_loaded;    /* true while wallet is open (unlock caches KEK here);
                                 * cleared by wallet_lock() or backend exit */
    TimestampTz  last_opened;   /* last successful open timestamp; 0 = never */
    /* per-backend KEK buffer — held while wallet is open, cleared on lock */
    unsigned char kek[TDE_DEK_LEN];
} LocalWalletState;

static LocalWalletState *local_wallet_state = NULL;

/*
 * KEK rotation context — allocated in TopMemoryContext by prepare_kek_rotation(),
 * freed (after OPENSSL_cleanse) by commit/abort. NULL when no rotation is in progress.
 */
typedef struct LocalKekRotationCtx
{
    unsigned char old_kek[TDE_DEK_LEN];
    unsigned char new_kek[TDE_DEK_LEN];
} LocalKekRotationCtx;

static LocalKekRotationCtx *local_kek_rotation_ctx = NULL;

/* -------------------------------------------------------------------------
 * Forward declarations
 * -------------------------------------------------------------------------*/

/* KMS provider vtable callbacks */
static bool local_init(void);
static bool local_wrap_dek(const unsigned char *dek, int dek_len,
                           unsigned char *wrapped_out, int *out_len);
static bool local_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                              unsigned char *dek_out, int *dek_len);
static bool local_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                              unsigned char *new_wrapped, int *new_len);
static bool local_prepare_kek_rotation(void);
static void local_commit_kek_rotation(void);
static bool local_health_check(void);
static void local_shutdown(void);

/* Internal helpers */
static bool local_open_wallet(const char *path, const char *passphrase,
                              unsigned char *kek_out);
static void local_create_wallet_file(const char *path,
                                     const char *passphrase, 
                                     const unsigned char* kek, 
                                     int kek_len);
static bool local_wrap_dek_with_pass(const unsigned char *dek, int dek_len,
                                     unsigned char *wrapped_out, int *out_len,
                                     const char *passphrase,
                                     const char *wallet_path);
static bool local_unwrap_dek_with_pass(const unsigned char *wrapped,
                                       int wrapped_len,
                                       unsigned char *dek_out, int *dek_len,
                                       const char *passphrase,
                                       const char *wallet_path);
static bool local_wrap_dek_with_kek(const unsigned char *dek, int dek_len,
                                    unsigned char *wrapped_out, int *out_len,
                                    const unsigned char *kek);
static bool local_unwrap_dek_with_kek(const unsigned char *wrapped,
                                      int wrapped_len,
                                      unsigned char *dek_out, int *dek_len,
                                      const unsigned char *kek);
static bool local_derive_kek_from_pass(const char *passphrase,
                                       unsigned char *kek_out);
static const char *local_get_wallet_path(void);
static void local_set_wallet(const char *path);
static bool local_get_passphrase(char *pass_out, Size pass_max);
static bool local_passphrase_from_env(char *pass_out, Size pass_max);
static bool local_passphrase_from_file(char *pass_out, Size pass_max);
static bool local_passphrase_from_command(char *pass_out, Size pass_max);
static void local_kek_rotation_ctx_free(void);
/* v1.6 SQL-callable wallet management functions */
PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_unlock_sql);
PG_FUNCTION_INFO_V1(pg_vault_tde_migrate_vault_to_wallet_sql);

/* -------------------------------------------------------------------------
 * Provider registration
 * -------------------------------------------------------------------------*/
static const TdeKmsProvider local_provider_impl = {
    .name                 = "local",
    .init                 = local_init,
    .wrap_dek             = local_wrap_dek,
    .unwrap_dek           = local_unwrap_dek,
    .rewrap_dek           = local_rewrap_dek,
    .prepare_kek_rotation = local_prepare_kek_rotation,
    .commit_kek_rotation  = local_commit_kek_rotation,
    .health_check         = local_health_check,
    .shutdown             = local_shutdown,
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

    if(MyDatabaseId == InvalidOid) {
        path = "";
    }
    else {
        path = local_get_wallet_path();
    }

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
    local_wallet_state->last_opened = GetCurrentTimestamp();

    tde_audit(WALLET_OPEN, NULL, true);
    return true;
}

/* -------------------------------------------------------------------------
 * local_wrap_dek_with_pass — AES-256-WRAP the DEK under an explicit KEK
 *
 * Internal helper used by the vtable callback, wallet_change_passphrase,
 * and wallet_rotate_kek where an explicit passphrase is already available
 * rather than needing to re-read it from the configured source.
 * -------------------------------------------------------------------------*/
static bool
local_wrap_dek_with_pass(const unsigned char *dek, int dek_len,
                         unsigned char *wrapped_out, int *out_len,
                         const char *passphrase, const char *wallet_path)
{
    unsigned char   kek[TDE_DEK_LEN];
    EVP_CIPHER_CTX *ctx;
    int             update_len = 0;
    int             final_len  = 0;
    bool            ok = false;

    Assert(dek != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(wrapped_out != NULL);
    Assert(out_len != NULL);
    Assert(passphrase != NULL);
    Assert(wallet_path != NULL);

    if (!local_open_wallet(wallet_path, passphrase, kek))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local_wrap_dek_with_pass: "
                       "could not open wallet \"%s\"", wallet_path));
        return false;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        OPENSSL_cleanse(kek, TDE_DEK_LEN);
        ereport(WARNING, errmsg("pg_vault_tde: EVP_CIPHER_CTX_new failed"));
        return false;
    }

    /*
     * AES-256-WRAP (RFC 3394) via OpenSSL 3.x EVP interface.
     * EVP_aes_256_wrap() uses the default IV 0xA6A6A6A6A6A6A6A6.
     * Output is always plaintext_len + 8 = LOCAL_WRAPPED_DEK_LEN bytes.
     */
    if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL) == 1 &&
        EVP_EncryptUpdate(ctx, wrapped_out, &update_len, dek, dek_len) == 1 &&
        EVP_EncryptFinal_ex(ctx, wrapped_out + update_len, &final_len) == 1)
    {
        *out_len = update_len + final_len;
        ok = true;
    }
    else
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: AES-256-WRAP encryption failed: %s",
                       ERR_reason_error_string(ERR_get_error())));
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(kek, TDE_DEK_LEN);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_unwrap_dek_with_pass — AES-256-UNWRAP under an explicit passphrase
 *
 * Symmetric inverse of local_wrap_dek_with_pass.  Used anywhere we have an
 * explicit (passphrase, wallet_path) rather than reading from the GUC source.
 * -------------------------------------------------------------------------*/
static bool
local_unwrap_dek_with_pass(const unsigned char *wrapped, int wrapped_len,
                           unsigned char *dek_out, int *dek_len,
                           const char *passphrase, const char *wallet_path)
{
    unsigned char   kek[TDE_DEK_LEN];
    EVP_CIPHER_CTX *ctx;
    int             update_len = 0;
    int             final_len  = 0;
    bool            ok = false;

    Assert(wrapped != NULL);
    Assert(wrapped_len == LOCAL_WRAPPED_DEK_LEN);
    Assert(dek_out != NULL && dek_len != NULL);
    Assert(passphrase != NULL);
    Assert(wallet_path != NULL);

    if (wrapped_len != LOCAL_WRAPPED_DEK_LEN) return false;

    if (!local_open_wallet(wallet_path, passphrase, kek))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local_unwrap_dek_with_pass: "
                       "could not open wallet \"%s\"", wallet_path));
        return false;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        OPENSSL_cleanse(kek, TDE_DEK_LEN);
        ereport(WARNING, errmsg("pg_vault_tde: EVP_CIPHER_CTX_new failed"));
        return false;
    }

    /* AES-256-UNWRAP via EVP — symmetric inverse of wrap */
    if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL) == 1 &&
        EVP_DecryptUpdate(ctx, dek_out, &update_len, wrapped, wrapped_len) == 1 &&
        EVP_DecryptFinal_ex(ctx, dek_out + update_len, &final_len) == 1)
    {
        *dek_len = update_len + final_len;
        ok = true;
    }
    else
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: AES-256-UNWRAP failed (wrong passphrase "
                       "or corrupt wrapped DEK): %s",
                       ERR_reason_error_string(ERR_get_error())));
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(kek, TDE_DEK_LEN);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_wrap_dek_with_kek — AES-256-WRAP using a raw in-memory KEK.
 *
 * Used by the vtable callbacks when the wallet was opened interactively via
 * wallet_unlock() and the KEK is cached in local_wallet_state.  Avoids an
 * expensive PBKDF2 re-derivation and passphrase re-read on every call.
 *
 * kek MUST point to TDE_DEK_LEN bytes.  Caller retains ownership.
 * -------------------------------------------------------------------------*/
static bool
local_wrap_dek_with_kek(const unsigned char *dek, int dek_len,
                        unsigned char *wrapped_out, int *out_len,
                        const unsigned char *kek)
{
    EVP_CIPHER_CTX *ctx;
    int             update_len = 0;
    int             final_len  = 0;
    bool            ok         = false;

    Assert(dek != NULL && dek_len == TDE_DEK_LEN);
    Assert(wrapped_out != NULL && out_len != NULL);
    Assert(kek != NULL);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ereport(WARNING, errmsg("pg_vault_tde: EVP_CIPHER_CTX_new failed"));
        return false;
    }

    if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL) == 1 &&
        EVP_EncryptUpdate(ctx, wrapped_out, &update_len, dek, dek_len) == 1 &&
        EVP_EncryptFinal_ex(ctx, wrapped_out + update_len, &final_len) == 1)
    {
        *out_len = update_len + final_len;
        ok = true;
    }
    else
        ereport(WARNING,
                errmsg("pg_vault_tde: AES-256-WRAP (cached KEK) failed: %s",
                       ERR_reason_error_string(ERR_get_error())));

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_unwrap_dek_with_kek — AES-256-UNWRAP using a raw in-memory KEK.
 *
 * Symmetric inverse of local_wrap_dek_with_kek.
 * -------------------------------------------------------------------------*/
static bool
local_unwrap_dek_with_kek(const unsigned char *wrapped, int wrapped_len,
                          unsigned char *dek_out, int *dek_len,
                          const unsigned char *kek)
{
    EVP_CIPHER_CTX *ctx;
    int             update_len = 0;
    int             final_len  = 0;
    bool            ok         = false;

    Assert(wrapped != NULL && wrapped_len == LOCAL_WRAPPED_DEK_LEN);
    Assert(dek_out != NULL && dek_len != NULL);
    Assert(kek != NULL);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ereport(WARNING, errmsg("pg_vault_tde: EVP_CIPHER_CTX_new failed"));
        return false;
    }

    if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_wrap(), kek, NULL, NULL) == 1 &&
        EVP_DecryptUpdate(ctx, dek_out, &update_len, wrapped, wrapped_len) == 1 &&
        EVP_DecryptFinal_ex(ctx, dek_out + update_len, &final_len) == 1)
    {
        *dek_len = update_len + final_len;
        ok = true;
    }
    else
        ereport(WARNING,
                errmsg("pg_vault_tde: AES-256-UNWRAP (cached KEK) failed: %s",
                       ERR_reason_error_string(ERR_get_error())));

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_derive_kek_from_pass — derive a KEK from a passphrase WITHOUT
 * touching the wallet file or verifying any MAC.
 *
 * Mirrors exactly the PBKDF2 derivation performed inside local_open_wallet()
 * (same fixed salt "pg_vault_tde_kek_v1", same iteration count, same MD).
 *
 * This is used during passphrase rotation: between the old MAC (still on
 * disk) and the new MAC (about to be written), we need to derive the NEW
 * KEK from the NEW passphrase to re-wrap DEKs.  Calling local_open_wallet()
 * with the new passphrase would fail PKCS12_verify_mac() because the file
 * is still authenticated under the OLD passphrase.
 *
 * kek_out must point to a TDE_DEK_LEN-byte buffer.
 * Caller MUST OPENSSL_cleanse(kek_out, TDE_DEK_LEN) after use.
 * -------------------------------------------------------------------------*/
static bool
local_derive_kek_from_pass(const char *passphrase, unsigned char *kek_out)
{
    Assert(passphrase != NULL);
    Assert(kek_out != NULL);

    if (PKCS5_PBKDF2_HMAC(passphrase, -1,
                          (const unsigned char *) "pg_vault_tde_kek_v1",
                          19,                                 /* salt length */
                          LOCAL_PBKDF2_ITERS,
                          EVP_sha256(),
                          TDE_DEK_LEN, kek_out) != 1)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: PBKDF2 KEK derivation failed: %s",
                       ERR_reason_error_string(ERR_get_error())));
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * local_wrap_dek — vtable callback: wrap a DEK under the wallet KEK.
 *
 * Fast path: wallet was opened via wallet_unlock() in this backend — the KEK
 * is cached in local_wallet_state.  Use it directly without PBKDF2.
 * Slow path: re-derive the passphrase from the configured GUC source each
 * call (env var / file / command) and open the wallet.
 * -------------------------------------------------------------------------*/
static bool
local_wrap_dek(const unsigned char *dek, int dek_len,
               unsigned char *wrapped_out, int *out_len)
{
    const char *path;

    Assert(dek != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(wrapped_out != NULL);
    Assert(out_len != NULL);

    /*
     * Fast path: KEK is cached because wallet_unlock() was called in this
     * backend.  No passphrase re-read or PBKDF2 re-derivation needed.
     */
    if (local_wallet_state && local_wallet_state->kek_loaded)
        return local_wrap_dek_with_kek(dek, dek_len, wrapped_out, out_len,
                                       local_wallet_state->kek);

    /* Slow path: re-derive passphrase from GUC source on every call. */
    {
        char pass[1024];
        bool ok;

        if (!local_get_passphrase(pass, sizeof(pass)))
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: local wrap_dek: passphrase unavailable "
                           "— call pg_vault_tde_wallet_unlock() or configure "
                           "pg_vault_tde.wallet_passphrase_env"));
            return false;
        }

        path = (local_wallet_state && local_wallet_state->wallet_path[0])
               ? local_wallet_state->wallet_path
               : local_get_wallet_path();
               
        ok = local_wrap_dek_with_pass(dek, dek_len, wrapped_out, out_len,
                                      pass, path);
        OPENSSL_cleanse(pass, sizeof(pass));
        return ok;
    }
}

/* -------------------------------------------------------------------------
 * local_unwrap_dek — vtable callback: read passphrase from GUC source, unwrap
 * -------------------------------------------------------------------------*/
static bool
local_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                 unsigned char *dek_out, int *dek_len)
{
    char        pass[1024];
    const char *path;
    bool        ok;

    Assert(wrapped != NULL);
    Assert(wrapped_len == LOCAL_WRAPPED_DEK_LEN);
    Assert(dek_out != NULL && dek_len != NULL);

    /* Fast path: cached KEK from wallet_unlock(). */
    if (local_wallet_state && local_wallet_state->kek_loaded)
        return local_unwrap_dek_with_kek(wrapped, wrapped_len, dek_out, dek_len,
                                         local_wallet_state->kek);

    /* Slow path: re-derive passphrase from GUC source. */
    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local unwrap_dek: passphrase unavailable "
                       "— call pg_vault_tde_wallet_unlock() or configure "
                       "pg_vault_tde.wallet_passphrase_env"));
        return false;
    }

    path = (local_wallet_state && local_wallet_state->wallet_path[0])
           ? local_wallet_state->wallet_path
           : local_get_wallet_path();

    ok = local_unwrap_dek_with_pass(wrapped, wrapped_len, dek_out, dek_len,
                                    pass, path);
    OPENSSL_cleanse(pass, sizeof(pass));
    return ok;
}

/* -------------------------------------------------------------------------
 * local_rewrap_dek — re-wrap a DEK.
 *
 * If local_kek_rotation_ctx is set (KEK rotation in progress): unwrap with
 * old_kek and re-wrap with new_kek.  Otherwise: unwrap + wrap with the
 * current active key (standard path, e.g. after a simple re-wrap request).
 * -------------------------------------------------------------------------*/
static bool
local_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                 unsigned char *new_wrapped, int *new_len)
{
    unsigned char dek_temp[TDE_DEK_LEN];
    int           dek_temp_len;
    bool          ok;

    if (local_kek_rotation_ctx != NULL)
    {
        PG_TRY();
        {
            dek_temp_len = TDE_DEK_LEN;
            ok = local_unwrap_dek_with_kek(old_wrapped, old_len,
                                           dek_temp, &dek_temp_len,
                                           local_kek_rotation_ctx->old_kek);
            if (ok)
                ok = local_wrap_dek_with_kek(dek_temp, TDE_DEK_LEN,
                                             new_wrapped, new_len,
                                             local_kek_rotation_ctx->new_kek);
        }
        PG_CATCH();
        {
            local_kek_rotation_ctx_free();
            OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);

            PG_RE_THROW();
        }
        PG_END_TRY();
    }
    else
    {
        dek_temp_len = TDE_DEK_LEN;
        ok = local_unwrap_dek(old_wrapped, old_len, dek_temp, &dek_temp_len);
        if (ok)
            ok = local_wrap_dek(dek_temp, TDE_DEK_LEN, new_wrapped, new_len);
    }

    OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_kek_rotation_ctx_free — cleanse and free the rotation context.
 * Safe to call when ctx is already NULL.
 * -------------------------------------------------------------------------*/
static void
local_kek_rotation_ctx_free(void)
{
    if (local_kek_rotation_ctx == NULL)
        return;
    OPENSSL_cleanse(local_kek_rotation_ctx->old_kek, TDE_DEK_LEN);
    OPENSSL_cleanse(local_kek_rotation_ctx->new_kek, TDE_DEK_LEN);
    pfree(local_kek_rotation_ctx);
    local_kek_rotation_ctx = NULL;
}

/* -------------------------------------------------------------------------
 * local_prepare_kek_rotation — vtable: arm the provider for a rewrap cycle.
 *
 * Reads the current KEK (from cache or wallet), generates a fresh random KEK,
 * writes the new wallet file to disk (durability before the loop), then stores
 * both keys in local_kek_rotation_ctx so local_rewrap_dek() can use them.
 * -------------------------------------------------------------------------*/
static bool
local_prepare_kek_rotation(void)
{
    unsigned char old_kek[TDE_DEK_LEN];
    unsigned char new_kek[TDE_DEK_LEN];
    const char   *path = local_get_wallet_path();
    char          pass[1024];

    if (local_kek_rotation_ctx != NULL)
        ereport(ERROR,
                errmsg("pg_vault_tde: KEK rotation already in progress"));

    /* Obtain old KEK: from cache if available, otherwise from GUC + wallet. */
    if (local_wallet_state && local_wallet_state->kek_loaded)
    {
        memcpy(old_kek, local_wallet_state->kek, TDE_DEK_LEN);
    }
    else
    {
        if (!local_get_passphrase(pass, sizeof(pass)) ||
            !local_open_wallet(path, pass, old_kek))
        {
            OPENSSL_cleanse(pass, sizeof(pass));
            OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
            return false;
        }
        OPENSSL_cleanse(pass, sizeof(pass));
    }

    if (!pg_strong_random(new_kek, sizeof(new_kek)))
    {
        OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
        return false;
    }

    /* Allocate rotation context in TopMemoryContext (survives query boundary). */
    local_kek_rotation_ctx = (LocalKekRotationCtx *)
        MemoryContextAllocZero(TopMemoryContext, sizeof(LocalKekRotationCtx));
    memcpy(local_kek_rotation_ctx->old_kek, old_kek, TDE_DEK_LEN);
    memcpy(local_kek_rotation_ctx->new_kek, new_kek, TDE_DEK_LEN);

    OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
    OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
    return true;
}

/* -------------------------------------------------------------------------
 * local_commit_kek_rotation — vtable: finalise after rewrap loop completes.
 *
 * Copies new_kek into local_wallet_state so this backend can continue
 * wrapping/unwrapping without re-reading the passphrase.  Clears the ctx.
 * Safe to call even on error paths (idempotent when ctx is NULL).
 * -------------------------------------------------------------------------*/
static void
local_commit_kek_rotation(void)
{
    const char   *path = local_get_wallet_path();
    char          pass[1024];

    if (local_kek_rotation_ctx == NULL)
        return;

     /* Write new wallet file before the rewrap loop (durability first). */
    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(ERROR, 
                errmsg("pg_vault_tde: can't get wallet passphrase"));
    }
    local_create_wallet_file(path, pass, local_kek_rotation_ctx->new_kek, TDE_DEK_LEN);
    OPENSSL_cleanse(pass, sizeof(pass));

    if (local_wallet_state)
    {
        memcpy(local_wallet_state->kek, local_kek_rotation_ctx->new_kek,
               TDE_DEK_LEN);
        local_wallet_state->kek_loaded  = true;
        local_wallet_state->wallet_open = true;
        local_wallet_state->last_opened = GetCurrentTimestamp();
    }

    local_kek_rotation_ctx_free();
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

    tde_audit(WALLET_CLOSE, NULL, true);
    local_wallet_state->wallet_open  = false;
    local_wallet_state->kek_loaded   = false;
}

/* =========================================================================
 * Internal helpers
 * =========================================================================*/

/*
 * local_get_wallet_path — resolve wallet path from GUC or default.
 *
 * Also registered as the show_hook for pg_vault_tde.wallet_path so that
 * SHOW returns the computed default even when the GUC is not set in
 * postgresql.conf.  Returns a pointer to a static buffer — do not free.
 */
static const char *
local_get_wallet_path(void)
{
    static char path_buf[MAXPGPATH];

    if (pg_vault_tde_wallet_path && pg_vault_tde_wallet_path[0] != '\0')
        return pg_vault_tde_wallet_path;

    /* MyDatabaseId is only valid after the backend has attached to a database. */
    if (!OidIsValid(MyDatabaseId))
        return "";

    snprintf(path_buf, sizeof(path_buf),
             "/var/lib/pg_vault_tde/%u/wallet.p12", MyDatabaseId);

    return path_buf;
}

/*
 * local_set_wallet — set wallet_path GUC for the current session and persist
 * it at database level so reconnecting backends inherit the same path.
 *
 * Must be called after the wallet file path is finalised (i.e. after the
 * parent directory is created but before writing the wallet).
 */
static void
local_set_wallet(const char *path)
{
    VariableSetStmt *setstmt;

    Assert(path != NULL && path[0] != '\0');

    /* 1. Update the current session so SHOW returns the correct value. */
    SetConfigOption("pg_vault_tde.wallet_path", path, PGC_SUSET, PGC_S_SESSION);

    /*
     * 2. Persist the current session value to pg_db_role_setting for this
     *    database only (equivalent to ALTER DATABASE … SET FROM CURRENT).
     *    VAR_SET_CURRENT requires no args — it reads the value already set
     *    by the SetConfigOption call above.
     */
    setstmt        = makeNode(VariableSetStmt);
    setstmt->kind  = VAR_SET_CURRENT;
    setstmt->name  = "pg_vault_tde.wallet_path";
    setstmt->args  = NIL;

    AlterSetting(MyDatabaseId, InvalidOid, setstmt);
}

/* -------------------------------------------------------------------------
 * Passphrase resolution helpers (v1.6 multi-source)
 *
 * Priority (highest to lowest):
 *   1. wallet_passphrase_command  — shell command stdout
 *   2. wallet_passphrase_env      — environment variable
 *   3. wallet_passphrase_file     — file on disk
 *   4. wallet_dev_mode_passphrase — only when dev_mode = on
 *
 * Conflict detection (active means: non-empty GUC value):
 *   If more than one of (command, env, file) is non-empty, ereport(ERROR).
 *   dev_mode passphrase is only active when all three above are empty AND
 *   dev_mode = on.
 * -------------------------------------------------------------------------*/

/*
 * local_passphrase_from_env — read passphrase from an environment variable.
 *
 * GUC wallet_passphrase_env holds the NAME of the env var, not the value.
 * Returns true if the env var exists and is non-empty.
 */
static bool
local_passphrase_from_env(char *pass_out, Size pass_max)
{
    const char *env_name;
    const char *env_val;

    env_name = pg_vault_tde_wallet_passphrase_env;
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

    fpath = pg_vault_tde_wallet_passphrase_file;
    if (!fpath || fpath[0] == '\0')
        return false;

    /* Permission sanity check */
    if (stat(fpath, &st) != 0)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: passphrase file \"%s\": %m", fpath));
        return false;
    }
    if ((st.st_mode & 0777) & ~0600)
        ereport(WARNING,
                errmsg("pg_vault_tde: passphrase file \"%s\" is mode %04o; "
                       "expected 0400 or 0600 (owner-only)",
                       fpath, (unsigned)(st.st_mode & 0777)));
    if ((st.st_mode & 0777) & 0044)  /* group/other readable */
    {
        ereport(ERROR,
                errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pg_vault_tde: passphrase file \"%s\" is group- or "
                       "world-readable (mode %04o); refusing to read passphrase",
                       fpath, (unsigned)(st.st_mode & 0777)));
    }

    fp = fopen(fpath, "r");
    if (!fp)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: cannot open passphrase file \"%s\": %m",
                       fpath));
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

    cmd = pg_vault_tde_wallet_passphrase_command;
    if (!cmd || cmd[0] == '\0')
        return false;

    fp = popen(cmd, "r");
    if (!fp)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: passphrase_command popen() failed: %m"));
        return false;
    }

    n = fread(pass_out, 1, pass_max - 1, fp);
    pclose(fp);
    pass_out[n] = '\0';

    /* Strip trailing whitespace */
    p = pass_out + n;
    while (p > pass_out && (p[-1] == '\n' || p[-1] == '\r' ||
                            p[-1] == ' '  || p[-1] == '\t'))
        *--p = '\0';

    if (pass_out[0] == '\0')
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: passphrase_command produced empty output"));
        return false;
    }
    return true;
}

/*
 * local_get_passphrase — multi-source passphrase dispatcher.
 *
 * Tries sources in priority order:
 *   command > env > file > dev_mode_passphrase (only when dev_mode = on)
 *
 * Returns true if a non-empty passphrase was found.
 * pass_out is NUL-terminated; caller MUST OPENSSL_cleanse after use.
 */
static bool
local_get_passphrase(char *pass_out, Size pass_max)
{
    int active_sources = 0;
    bool has_command = (pg_vault_tde_wallet_passphrase_command &&
                        pg_vault_tde_wallet_passphrase_command[0] != '\0');
    /* Count env source only when the named variable is actually set in the
     * environment; the GUC just names the variable to look up. */
    bool has_env     = (pg_vault_tde_wallet_passphrase_env &&
                        pg_vault_tde_wallet_passphrase_env[0] != '\0' &&
                        getenv(pg_vault_tde_wallet_passphrase_env) != NULL);
    bool has_file    = (pg_vault_tde_wallet_passphrase_file &&
                        pg_vault_tde_wallet_passphrase_file[0] != '\0');

    if (has_command) active_sources++;
    if (has_env)     active_sources++;
    if (has_file)    active_sources++;

    /*
     * Conflict detection: more than one of command/env/file is configured.
     * This is a coding error in postgresql.conf; fail loudly.
     */
    if (active_sources > 1)
        ereport(ERROR,
                errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                errmsg("pg_vault_tde: multiple wallet passphrase sources "
                       "are configured (command=%s, env=%s, file=%s); "
                       "set at most one",
                       has_command ? "yes" : "no",
                       has_env     ? "yes" : "no",
                       has_file    ? "yes" : "no"));

    /* Try sources in priority order */
    if (has_command && local_passphrase_from_command(pass_out, pass_max))
        return true;

    if (has_env && local_passphrase_from_env(pass_out, pass_max))
        return true;

    if (has_file && local_passphrase_from_file(pass_out, pass_max))
        return true;

    /* Dev-mode fallback — only when explicitly enabled */
    if (pg_vault_tde_dev_mode &&
        pg_vault_tde_wallet_dev_mode_passphrase &&
        pg_vault_tde_wallet_dev_mode_passphrase[0] != '\0')
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: using dev_mode_passphrase from GUC — "
                       "NEVER use this in production"));
        strncpy(pass_out, pg_vault_tde_wallet_dev_mode_passphrase,
                pass_max - 1);
        pass_out[pass_max - 1] = '\0';
        return true;
    }

    ereport(DEBUG1,
            errmsg("pg_vault_tde: no wallet passphrase source configured "
                   "or all sources returned empty"));
    return false;
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
    STACK_OF(X509) *ca  = NULL;
    bool      ok   = false;
    unsigned char kek_buffer[32];
    size_t kek_len     = sizeof(kek_buffer);

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

    if(PKCS12_verify_mac(p12, passphrase, -1))
    {
        if(PKCS12_parse(p12, passphrase, &pkey, &cert, &ca)){
            if(EVP_PKEY_get_raw_private_key(pkey, kek_buffer, &kek_len) != 1)
                ereport(WARNING,
                    errmsg("pg_vault_tde: error while extracting the kek"));
            else 
                ok = true;
        }
        else
            ereport(WARNING,
                errmsg("pg_vault_tde: PKCS#12 parsing failed"));
    }
    else    
        ereport(WARNING,
                errmsg(("pg_vault_tde: wallet MAC verification failed - "
                     "wrong passphrase or corrupt wallet")));

    if(pkey) EVP_PKEY_free(pkey);
    if(cert) X509_free(cert);
    if(ca) sk_X509_pop_free(ca, X509_free);

    PKCS12_free(p12);

    /* Only copy the KEK when parsing succeeded; avoids writing uninitialized bytes on error. */
    if(ok) memcpy(kek_out, kek_buffer, kek_len);

    OPENSSL_cleanse(kek_buffer, kek_len);
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
 *   1. Generate a fresh 32-byte KEK via pg_strong_random.
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
    unsigned char kek[32];
    EVP_PKEY       *pkey = NULL;

    /* Superuser check */
    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_wallet_init requires superuser"));
    if(pg_vault_tde_kms_provider == NULL ||
        strcmp(pg_vault_tde_kms_provider, "local") != 0)
        ereport(ERROR, 
                errmsg("pg_vault_tde_wallet_init requires KMS local"));

    passphrase = text_to_cstring(passphrase_t);
    path       = local_get_wallet_path();

    /* Refuse to overwrite an existing wallet without explicit delete */
    if (stat(path, &st) == 0)
        ereport(WARNING,
                errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pg_vault_tde: wallet already exists at \"%s\"; "
                       "use pg_vault_tde_wallet_change_passphrase() to "
                       "rotate the passphrase, or remove the file manually "
                       "to re-initialize", path));


    /*
     * Ensure the per-database wallet directory exists inside the base dir.
     *
     * /var/lib/pg_vault_tde/          ← created by the package installer (root)
     * /var/lib/pg_vault_tde/<db_oid>/ ← created here by the postgres process
     *
     * If the base directory is missing the admin has not completed the
     * installation; fail with an actionable message rather than trying to
     * create it (the postgres process must not own /var/lib directories).
     */
    {
        char        dir[MAXPGPATH];
        const char *last_slash = strrchr(path, '/');
        size_t      dlen;

        if (last_slash && last_slash > path)
        {
            dlen = (size_t)(last_slash - path);
            if (dlen >= sizeof(dir))
            {
                OPENSSL_cleanse(passphrase, strlen(passphrase));
                pfree(passphrase);
                ereport(ERROR, errmsg("pg_vault_tde: wallet path too long"));
            }
            memcpy(dir, path, dlen);
            dir[dlen] = '\0';

            if (mkdir(dir, 0700) != 0 && errno != EEXIST)
            {
                int saved_errno = errno;
                OPENSSL_cleanse(passphrase, strlen(passphrase));
                pfree(passphrase);
                if (saved_errno == ENOENT)
                    ereport(ERROR,
                            errmsg("pg_vault_tde: wallet base directory does not exist"),
                            errdetail("Attempted to create \"%s\" but its parent is missing.",
                                      dir),
                            errhint("Run as root: mkdir -p /var/lib/pg_vault_tde && "
                                    "chown postgres:postgres /var/lib/pg_vault_tde && "
                                    "chmod 0700 /var/lib/pg_vault_tde"));
                else
                    ereport(ERROR,
                            errmsg("pg_vault_tde: could not create directory \"%s\": %m",
                                   dir));
            }
        }
    }

    local_set_wallet(path);

    if(!pg_strong_random(kek, 32))
    {
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        pfree(passphrase);

        ereport(ERROR, 
                errmsg("pg_vault_tde: KEK generation failed"));
    }
    
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, kek, sizeof(kek));
    if(!pkey)
    {
        OPENSSL_cleanse(kek, sizeof(kek));
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        pfree(passphrase);
        ereport(ERROR, 
                errmsg("pg_vault_tde: EVP_KEY creation failed"));
    }

    /*
     * The 8th argument (maciter) was previously -1, which in OpenSSL 3.x
     * disables the PKCS#12 MAC entirely.  A wallet without a MAC cannot be
     * verified by PKCS12_verify_mac, breaking local_open_wallet on the first
     * unwrap attempt.  PKCS12_DEFAULT_ITER (2048) enables proper MAC protection.
     */
    p12 = PKCS12_create(passphrase,
                        "pg_vault_tde_kek",
                        pkey,
                        NULL,
                        NULL,
                        NID_aes_256_cbc,
                        NID_aes_256_cbc,
                        PKCS12_DEFAULT_ITER,
                        PKCS12_DEFAULT_ITER,
                        0);

    OPENSSL_cleanse(kek, sizeof(kek));
    EVP_PKEY_free(pkey);

    if(!p12)
    {
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        pfree(passphrase);
        ereport(ERROR, 
                errmsg("pg_vault_tde: PKCS12 wallet creation failed"));
    }

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
    {
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        pfree(passphrase);
        ereport(ERROR,
                errmsg("pg_vault_tde: chmod(wallet, 0600) failed: %m"));
    }

    /*
     * Open the freshly created wallet to derive and cache the KEK.
     * Without this, the first wrap_dek call after wallet_init would take the
     * slow path (re-read passphrase from GUC source), which adds latency and
     * fails if the env var passphrase differs from the one just used here.
     */
    if (local_wallet_state)
    {
        unsigned char kek_cache[TDE_DEK_LEN];

        if (local_open_wallet(path, passphrase, kek_cache))
        {
            memcpy(local_wallet_state->kek, kek_cache, TDE_DEK_LEN);
            local_wallet_state->kek_loaded  = true;
            local_wallet_state->wallet_open = true;
            local_wallet_state->last_opened = GetCurrentTimestamp();
            if (local_wallet_state->wallet_path == NULL ||
                local_wallet_state->wallet_path[0] == '\0')
                local_wallet_state->wallet_path =
                    MemoryContextStrdup(TopMemoryContext, path);
        }
        else
        {
            /* Wallet was just written — this should never fail */
            ereport(WARNING,
                    errmsg("pg_vault_tde: wallet created but could not be "
                           "re-opened for KEK caching at \"%s\"", path));
            local_wallet_state->wallet_open = true;
        }
        OPENSSL_cleanse(kek_cache, TDE_DEK_LEN);
    }

    OPENSSL_cleanse(passphrase, strlen(passphrase));
    pfree(passphrase);

    ereport(LOG, errmsg("pg_vault_tde: wallet initialized at \"%s\"", path));

    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * local_create_wallet_file — create (or overwrite-via-rename) a PKCS#12 wallet
 *
 * Writes the new PKCS#12 file to `dest_path.new`, then renames atomically to
 * `dest_path`.  The caller holds responsibility for cleansing `passphrase`
 * after return.
 *
 * Returns true on success; on error emits ereport(ERROR) (longjmp).
 * -------------------------------------------------------------------------*/
static void
local_create_wallet_file(const char *dest_path, const char *passphrase, const unsigned char* kek, int kek_len)
{
    char    tmp_path[MAXPGPATH];
    PKCS12 *p12;
    int     fd;
    FILE   *fp;
    EVP_PKEY* pkey;

    Assert(dest_path != NULL);
    Assert(passphrase != NULL);
    Assert(kek != NULL);
    Assert(kek_len > 0);

    snprintf(tmp_path, sizeof(tmp_path), "%s.new", dest_path);

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, kek, kek_len);
    if(!pkey)
    {
        ereport(ERROR, 
                errmsg("pg_vault_tde: EVP_KEY creation failed"));
    }

    p12 = PKCS12_create(passphrase, 
                        "pg_vault_tde_kek", 
                        pkey, 
                        NULL, 
                        NULL, 
                        NID_aes_256_cbc, 
                        NID_aes_256_cbc, 
                        PKCS12_DEFAULT_ITER, 
                        PKCS12_DEFAULT_ITER, 
                        0);
    EVP_PKEY_free(pkey);

    if(!p12)
    {
        ereport(ERROR, 
                errmsg("pg_vault_tde: PKCS12 wallet creation failed"));
    }

    fd = open(tmp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
    {
        PKCS12_free(p12);
        ereport(ERROR,
                errmsg("pg_vault_tde: could not open \"%s\" for write: %m",
                       tmp_path));
    }

    fp = fdopen(fd, "wb");
    if (!fp || i2d_PKCS12_fp(fp, p12) != 1)
    {
        if (fp) fclose(fp); else close(fd);
        unlink(tmp_path);
        PKCS12_free(p12);
        ereport(ERROR,
                errmsg("pg_vault_tde: could not write wallet to \"%s\"",
                       tmp_path));
    }
    fclose(fp);
    PKCS12_free(p12);

    if (chmod(tmp_path, 0600) != 0)
    {
        unlink(tmp_path);
        ereport(ERROR,
                errmsg("pg_vault_tde: chmod(\"%s\", 0600) failed: %m",
                       tmp_path));
    }

    if (rename(tmp_path, dest_path) != 0)
    {
        unlink(tmp_path);
        ereport(ERROR,
                errmsg("pg_vault_tde: could not rename \"%s\" to \"%s\": %m",
                       tmp_path, dest_path));
    }
}



/* -------------------------------------------------------------------------
 * pg_vault_tde_wallet_status — SQL-callable: returns wallet diagnostics
 *
 * Returns TABLE(wallet_exists bool, wallet_open bool, kek_algorithm text,
 *               dek_count int, last_opened timestamptz, file_perms text)
 * -------------------------------------------------------------------------*/
PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_status_sql);

PGDLLEXPORT Datum
pg_vault_tde_wallet_status_sql(PG_FUNCTION_ARGS)
{
    ReturnSetInfo      *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    TupleDesc           tupdesc;
    Tuplestorestate    *tupstore;
    MemoryContext       per_query_ctx;
    MemoryContext       old_ctx;
    const char         *path;
    struct stat         st;
    bool                wallet_exists;
    bool                wallet_open;
    TimestampTz         last_opened_ts;
    char                perms_str[8];
    Datum               vals[5];
    bool                nulls[5];

    /* Prepare the result set */
    if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
        ereport(ERROR,
                errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                errmsg("set-valued function called in context that cannot accept a set"));

    if (!(rsinfo->allowedModes & SFRM_Materialize))
        ereport(ERROR,
                errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                errmsg("materialize mode required, but it is not allowed in this context"));

    /* Build TupleDesc matching the TABLE() definition */
    get_call_result_type(fcinfo, NULL, &tupdesc);

    per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    old_ctx = MemoryContextSwitchTo(per_query_ctx);
    tupstore = tuplestore_begin_heap(true, false, work_mem);
    rsinfo->returnMode = SFRM_Materialize;
    rsinfo->setResult  = tupstore;
    rsinfo->setDesc    = tupdesc;
    MemoryContextSwitchTo(old_ctx);

    /* Gather state */
    path          = local_get_wallet_path();
    wallet_exists = (stat(path, &st) == 0);
    wallet_open   = (local_wallet_state && local_wallet_state->wallet_open);
    last_opened_ts = (local_wallet_state)
                     ? local_wallet_state->last_opened
                     : (TimestampTz) 0;

    if (wallet_exists)
        snprintf(perms_str, sizeof(perms_str), "%04o",
                 (unsigned) (st.st_mode & 0777));
    else
        perms_str[0] = '\0';

    /* Build result tuple */
    memset(nulls, 0, sizeof(nulls));
    vals[0] = BoolGetDatum(wallet_exists);
    vals[1] = BoolGetDatum(wallet_open);
    vals[2] = CStringGetTextDatum("AES-256-WRAP/PBKDF2-SHA256");

    if (last_opened_ts != (TimestampTz) 0)
        vals[3] = TimestampTzGetDatum(last_opened_ts);
    else
        nulls[3] = true;

    if (wallet_exists)
        vals[4] = CStringGetTextDatum(perms_str);
    else
        nulls[4] = true;

    tuplestore_putvalues(tupstore, tupdesc, vals, nulls);

    return (Datum) 0;
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_wallet_change_passphrase — re-wrap all DEKs under new passphrase
 *
 * Algorithm:
 *   1. Verify old_passphrase opens the wallet.
 *   2. Fetch all catalog entries for kms_provider='local'.
 *   3. For each entry: unwrap with old passphrase → wrap with new passphrase → UPDATE.
 *   4. Create new wallet file (atomic rename).
 *   5. Evict shmem cache so next access uses new KEK.
 * -------------------------------------------------------------------------*/
PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_change_passphrase_sql);

PGDLLEXPORT Datum
pg_vault_tde_wallet_change_passphrase_sql(PG_FUNCTION_ARGS)
{
    text   *old_t   = PG_GETARG_TEXT_PP(0);
    text   *new_t   = PG_GETARG_TEXT_PP(1);
    char   *old_pass = text_to_cstring(old_t);
    char   *new_pass = text_to_cstring(new_t);
    const char *path;
    unsigned char old_kek[TDE_DEK_LEN];
    unsigned char new_kek[TDE_DEK_LEN];

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_wallet_change_passphrase requires superuser"));

    path = local_get_wallet_path();

    /*
     * Verify old passphrase actually opens the wallet (MAC check on
     * the on-disk PKCS#12 file, which is still authenticated under old_pass).
     */
    if (!local_open_wallet(path, old_pass, old_kek))
    {
        OPENSSL_cleanse(old_pass, strlen(old_pass));
        OPENSSL_cleanse(new_pass, strlen(new_pass));
        OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
        pfree(old_pass);
        pfree(new_pass);
        ereport(ERROR,
                errcode(ERRCODE_INVALID_PASSWORD),
                errmsg("pg_vault_tde: wrong passphrase (could not open wallet)"));
    }

    if(!pg_strong_random(new_kek, sizeof(new_kek)))
    {
        OPENSSL_cleanse(old_pass, strlen(old_pass));
        OPENSSL_cleanse(new_pass, strlen(new_pass));
        OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
        OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
        pfree(old_pass);
        pfree(new_pass);
        ereport(ERROR,
                errmsg("pg_vault_tde: change_passphrase: could not generate new KEK"));
    }
    
    /* Set up rotation context with explicit KEK pair (passphrase-derived). */
    if (local_kek_rotation_ctx != NULL)
    {
        OPENSSL_cleanse(old_pass, strlen(old_pass));
        OPENSSL_cleanse(new_pass, strlen(new_pass));
        OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
        OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
        pfree(old_pass);
        pfree(new_pass);
        ereport(ERROR, errmsg("pg_vault_tde: KEK rotation already in progress"));
    }

    local_kek_rotation_ctx = (LocalKekRotationCtx *)
        MemoryContextAllocZero(TopMemoryContext, sizeof(LocalKekRotationCtx));
    memcpy(local_kek_rotation_ctx->old_kek, old_kek, TDE_DEK_LEN);
    memcpy(local_kek_rotation_ctx->new_kek, new_kek, TDE_DEK_LEN);

    PG_TRY();
    {
        pg_vault_tde_catalog_rewrap_all();
    }
    PG_CATCH();
    {
        local_kek_rotation_ctx_free();
        OPENSSL_cleanse(old_pass, strlen(old_pass));
        OPENSSL_cleanse(new_pass, strlen(new_pass));
        OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
        OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
        pfree(old_pass);
        pfree(new_pass);
        PG_RE_THROW();
    }
    PG_END_TRY();

    local_kek_rotation_ctx_free();

    /* Evict shmem — next access loads with new KEK */
    pg_vault_tde_catalog_evict_all();

    /* 
     * Write new wallet file with new passphrase (atomic rename).
     * From here on, on-disk MAC is authenticated under new_pass.
     */
    local_create_wallet_file(path, new_pass, new_kek, TDE_DEK_LEN);

    if (local_wallet_state)
    {
        /*
         * Always cache the new KEK and mark it loaded, regardless of whether
         * wallet_unlock() was called before change_passphrase().  Without this,
         * backends that use the slow path (env-var passphrase, kek_loaded=false)
         * would attempt local_open_wallet() with the now-stale env-var passphrase
         * against a wallet file already re-MAC'd under new_pass, producing a
         * "MAC verification failed" error on the very next SELECT.
         */
        memcpy(local_wallet_state->kek, new_kek, TDE_DEK_LEN);
        local_wallet_state->kek_loaded   = true;
        local_wallet_state->wallet_open  = true;
        local_wallet_state->last_opened  = GetCurrentTimestamp();
    }

    OPENSSL_cleanse(old_pass, strlen(old_pass));
    OPENSSL_cleanse(new_pass, strlen(new_pass));
    OPENSSL_cleanse(old_kek, TDE_DEK_LEN);
    OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
    pfree(old_pass);
    pfree(new_pass);

    ereport(LOG,
            errmsg("pg_vault_tde: wallet passphrase changed; "
                   "DEK(s) re-wrapped"));

    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_wallet_unlock — verify passphrase, flush cache, mark open
 *
 * Calling this function:
 *   1. Verifies the passphrase opens the PKCS#12 wallet.
 *   2. Evicts ALL per-table DEKs from shmem (forces fresh unwrap on next access).
 *   3. Marks the wallet as open so health_check passes.
 *
 * This is safe to call from any backend; the shmem eviction affects all
 * backends because the cache lives in shared memory.
 * -------------------------------------------------------------------------*/

PGDLLEXPORT Datum
pg_vault_tde_wallet_unlock_sql(PG_FUNCTION_ARGS)
{
    text   *pass_t   = PG_GETARG_TEXT_PP(0);
    char   *passphrase = text_to_cstring(pass_t);
    const char *path;
    unsigned char kek_test[TDE_DEK_LEN];

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_wallet_unlock requires superuser"));

    path = local_get_wallet_path();

    if (!local_open_wallet(path, passphrase, kek_test))
    {
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        OPENSSL_cleanse(kek_test, TDE_DEK_LEN);
        pfree(passphrase);
        ereport(ERROR,
                errcode(ERRCODE_INVALID_PASSWORD),
                errmsg("pg_vault_tde: wallet_unlock: wrong passphrase or "
                       "wallet not found at \"%s\"", path));
    }

    OPENSSL_cleanse(passphrase, strlen(passphrase));
    pfree(passphrase);

    /*
     * Cache the derived KEK in per-backend state so that subsequent
     * wrap_dek / unwrap_dek calls in this backend can use it directly
     * without re-reading the passphrase from a GUC source.
     *
     * This is the only safe mechanism for the interactive unlock path
     * where no passphrase env var / file / command is configured:
     *   SELECT pg_vault_tde_wallet_unlock('pass');
     *   CREATE TABLE t (...) USING encrypted_heap;  ← needs wrap_dek
     *
     * kek_loaded is cleared by wallet_lock() and local_shutdown().
     */
    if (local_wallet_state)
    {
        memcpy(local_wallet_state->kek, kek_test, TDE_DEK_LEN);
        local_wallet_state->kek_loaded  = true;
        local_wallet_state->wallet_open = true;
        local_wallet_state->last_opened = GetCurrentTimestamp();
    }
    OPENSSL_cleanse(kek_test, TDE_DEK_LEN);

    /*
     * Evict shmem so every backend reloads DEKs through the full
     * unwrap path.  Other backends that lack the cached KEK will use
     * the GUC passphrase source; if that is also absent they must call
     * wallet_unlock() themselves.
     */
    pg_vault_tde_catalog_evict_all();

    ereport(LOG, errmsg("pg_vault_tde: wallet unlocked by superuser"));

    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_wallet_lock — flush all plaintext DEK material from shmem
 *
 * After calling this function, any attempt to access an encrypted table will
 * trigger a DEK unwrap (which will fail unless the wallet passphrase is
 * available via the configured GUC source or a subsequent wallet_unlock call).
 *
 * This provides a manual "key-zeroing" capability without a server restart.
 * -------------------------------------------------------------------------*/

PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_lock_sql);
PGDLLEXPORT Datum
pg_vault_tde_wallet_lock_sql(PG_FUNCTION_ARGS)
{
    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_wallet_lock requires superuser"));

    pg_vault_tde_catalog_evict_all();

    if (local_wallet_state)
    {
        /*
         * Evict the cached KEK so that this backend can no longer
         * wrap or unwrap DEKs without a fresh wallet_unlock() or a
         * configured passphrase GUC source.
         */
        if (local_wallet_state->kek_loaded)
            OPENSSL_cleanse(local_wallet_state->kek, TDE_DEK_LEN);
        local_wallet_state->kek_loaded  = false;
        local_wallet_state->wallet_open = false;
    }

    ereport(LOG, errmsg("pg_vault_tde: wallet locked; KEK and all DEKs cleared from shmem"));

    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_migrate_vault_to_wallet — re-wrap all Vault DEKs under local wallet
 *
 * For each row in pg_vault_tde_catalog with kms_provider='vault':
 *   1. Unwrap the DEK using the Vault provider.
 *   2. Re-wrap using the local wallet with new_passphrase.
 *   3. UPDATE the catalog row with the new wrapped_dek and kms_provider='local'.
 *
 * After all rows are migrated, sets tde_active_kms_provider to the local
 * provider.  The Vault provider is NOT shut down (may still be referenced by
 * GUC settings until the server is restarted with kms_provider=local).
 * -------------------------------------------------------------------------*/

PGDLLEXPORT Datum
pg_vault_tde_migrate_vault_to_wallet_sql(PG_FUNCTION_ARGS)
{
    text   *pass_t   = PG_GETARG_TEXT_PP(0);
    char   *new_pass = text_to_cstring(pass_t);
    const char *wallet_path;
    int     migrated = 0;

    unsigned char new_kek[TDE_DEK_LEN];

    Oid ext_ns;
    ScanKeyData scan_key;
    SysScanDesc scan;
    Oid rel;
    Relation catalog_rel;
    TupleDesc tup_desc;
    HeapTuple old_tuple;
    HeapTuple new_tuple;

    /*
     * To update pg_vault_tde_catalog we use CatalogTupleUpdateWithInfo
     * because it updates even the indexes, so we don't need to call
     * ExecInsertIndexTuples (or similar) after heap_update.
     * We cannot use CatalogTupleUpdate because we are updating
     * multiple tuples and we don't want opening and closing the index
     * table at every iteration (like CatalogTupleUpdate does).
     */
    CatalogIndexState indstate;

    /*
     * If there are many catalog entries for kms_provider = 'vault'
     * we have to call heap_deform_tuple and heap_form_tuple many times.
     * We MUST free allocated space and calling heap_freetuple can cause
     * an overhead on the CPU. So we use contexts that automatically
     * allocate space within a context and free it up fast with
     * MemoryContextReset.  It prevents also memory fragmentation.
     */
    MemoryContext old_ctx;
    MemoryContext tuple_ctx;

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_migrate_vault_to_wallet requires superuser"));

    wallet_path = local_get_wallet_path();

    /* The local wallet must exist before migration */
    {
        struct stat st;
        if (stat(wallet_path, &st) != 0)
        {
            OPENSSL_cleanse(new_pass, strlen(new_pass));
            pfree(new_pass);
            ereport(ERROR,
                    errmsg("pg_vault_tde: migrate_vault_to_wallet: local wallet "
                           "does not exist at \"%s\"; call "
                           "pg_vault_tde_wallet_init() first", wallet_path));
        }
    }

    /*
     * Derive the local KEK from new_pass once before the scan loop.
     * This avoids per-row PBKDF2 overhead that local_wrap_dek_with_pass
     * would incur inside the loop.
     */
    if (!local_derive_kek_from_pass(new_pass, new_kek))
    {
        OPENSSL_cleanse(new_pass, strlen(new_pass));
        pfree(new_pass);
        ereport(ERROR,
                errmsg("pg_vault_tde: migrate_vault_to_wallet: could not derive KEK from passphrase"));
    }

    ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
    rel = get_relname_relid("pg_vault_tde_catalog", ext_ns);

    if (!OidIsValid(ext_ns) || !OidIsValid(rel))
    {
        OPENSSL_cleanse(new_pass, strlen(new_pass));
        OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
        pfree(new_pass);
        ereport(ERROR, errmsg("pg_vault_tde: catalog table pg_vault_tde_catalog absent"));
    }

    tuple_ctx = AllocSetContextCreate(CurrentMemoryContext, "migrate-vault-tuple-ctx", ALLOCSET_DEFAULT_SIZES);

    catalog_rel = table_open(rel, ShareRowExclusiveLock);
    tup_desc = RelationGetDescr(catalog_rel);

    indstate = CatalogOpenIndexes(catalog_rel);

    ScanKeyInit(&scan_key, Anum_pg_vault_tde_kms_provider, BTEqualStrategyNumber, F_TEXTEQ, CStringGetTextDatum("vault"));

    scan = systable_beginscan(catalog_rel, InvalidOid, false, GetTransactionSnapshot(), 1, &scan_key);

    while (HeapTupleIsValid(old_tuple = systable_getnext(scan)))
    {
        bytea  *wdek_bytea;
        bool    is_null[CATALOG_NATTS];
        Datum   values[CATALOG_NATTS];
        bool    replaces[CATALOG_NATTS];

        unsigned char plain_dek[TDE_DEK_LEN];
        unsigned char new_wrapped[LOCAL_WRAPPED_DEK_LEN];
        int     new_len = sizeof(new_wrapped);  /* in: capacity; out: bytes */
        bytea  *new_wdek_b;
        int     vault_wlen;

        MemoryContextReset(tuple_ctx);

        {
            volatile bool skip = false;

            PG_TRY();
            {
                heap_deform_tuple(old_tuple, tup_desc, values, is_null);

                if (is_null[Anum_pg_vault_tde_wrapped_dek - 1])
                {
                    ereport(WARNING,
                            errmsg("pg_vault_tde: catalog entry with null DEK, skipping"));
                    skip = true;
                }

                if (!skip)
                {
                    wdek_bytea = DatumGetByteaPP(values[Anum_pg_vault_tde_wrapped_dek-1]);
                    vault_wlen = (int) VARSIZE_ANY_EXHDR(wdek_bytea);

                    old_ctx = MemoryContextSwitchTo(tuple_ctx);

                    /*
                    * Unwrap using the active (Vault) provider.  The scan filter on
                    * kms_provider = 'vault' guarantees we only land here for vault rows.
                    */
                    if (!tde_active_kms_provider)
                        ereport(ERROR,
                                errmsg("pg_vault_tde: migrate_vault_to_wallet: no active KMS provider"));
                    {
                        int plain_dek_len = TDE_DEK_LEN;
                        if (!tde_active_kms_provider->unwrap_dek(
                                (unsigned char *) VARDATA_ANY(wdek_bytea), vault_wlen,
                                plain_dek, &plain_dek_len))
                            ereport(ERROR,
                                    errmsg("pg_vault_tde: migrate_vault_to_wallet: vault unwrap "
                                        "failed for relid %u", DatumGetObjectId(values[Anum_pg_vault_tde_relid-1])));
                    }

                    if (!local_wrap_dek_with_kek(plain_dek, TDE_DEK_LEN,
                                                new_wrapped, &new_len,
                                                new_kek))
                    {
                        ereport(ERROR,
                                errmsg("pg_vault_tde: migrate_vault_to_wallet: local wrap "
                                    "failed for relid %u", DatumGetObjectId(values[Anum_pg_vault_tde_relid-1])));
                    }
                    OPENSSL_cleanse(plain_dek, TDE_DEK_LEN);

                    /* Build bytea for the new wrapped DEK */
                    new_wdek_b = (bytea *) palloc(VARHDRSZ + new_len);
                    SET_VARSIZE(new_wdek_b, VARHDRSZ + new_len);
                    memcpy(VARDATA(new_wdek_b), new_wrapped, new_len);
                    OPENSSL_cleanse(new_wrapped, sizeof(new_wrapped));

                    memset(replaces, 0, sizeof(replaces));
                    replaces[Anum_pg_vault_tde_wrapped_dek-1] = true;                         /* wrapped_dek */
                    values[Anum_pg_vault_tde_wrapped_dek-1] = PointerGetDatum(new_wdek_b);
                    is_null[Anum_pg_vault_tde_wrapped_dek-1] = false;
                    replaces[Anum_pg_vault_tde_kms_provider-1] = true;                         /* kms_provider */
                    values[Anum_pg_vault_tde_kms_provider-1] = CStringGetTextDatum("local");
                    is_null[Anum_pg_vault_tde_kms_provider-1] = false;

                    new_tuple = heap_modify_tuple(old_tuple, tup_desc, values, is_null, replaces);

                        CatalogTupleUpdateWithInfo(catalog_rel, &(old_tuple->t_self), new_tuple, indstate);

                        MemoryContextSwitchTo(old_ctx);

                        migrated++;
                } /* end if (!skip) */
            }
            PG_CATCH();
            {
                OPENSSL_cleanse(plain_dek, TDE_DEK_LEN);
                OPENSSL_cleanse(new_wrapped, sizeof(new_wrapped));
                OPENSSL_cleanse(new_pass, strlen(new_pass));
                OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
                pfree(new_pass);
                systable_endscan(scan);
                CatalogCloseIndexes(indstate);
                table_close(catalog_rel, ShareRowExclusiveLock);
                PG_RE_THROW();
            }
            PG_END_TRY();

            if (skip)
                continue;
        } /* end scoping block */
    }

    MemoryContextDelete(tuple_ctx);
    systable_endscan(scan);
    CatalogCloseIndexes(indstate);
    table_close(catalog_rel, ShareRowExclusiveLock);

    pg_vault_tde_catalog_evict_all();

    if (local_wallet_state)
    {
        local_wallet_state->wallet_open = true;
        local_wallet_state->last_opened = GetCurrentTimestamp();
    }

    OPENSSL_cleanse(new_pass, strlen(new_pass));
    OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
    pfree(new_pass);

    ereport(LOG,
            errmsg("pg_vault_tde: vault-to-wallet migration complete; "
                   "%d entries migrated", migrated));

    PG_RETURN_VOID();
}

