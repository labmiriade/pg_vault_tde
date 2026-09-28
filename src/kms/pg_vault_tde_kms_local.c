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
 * SECURITY CONSTRAINTS (from ROADMAP.md):
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
#include "access/xact.h"        /* RegisterXactCallback */
#include "storage/fd.h"         /* durable_rename */
#include "catalog/indexing.h"
#include "catalog/pg_db_role_setting.h"

#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/aes.h>        /* EVP_aes_256_wrap */
#include <openssl/crypto.h>

#include <sys/stat.h>
#include <sys/file.h>           /* flock */
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
#include "src/include/pg_vault_tde_catalog.h" /* pg_vault_tde_catalog_evict_db */
#include "src/include/pg_vault_tde_catalog_d.h"

/* -------------------------------------------------------------------------
 * AES-256-WRAP constants
 *
 * AES-256-WRAP (RFC 3394) uses a 32-byte KEK to wrap a 32-byte DEK.
 * The output is always plaintext_len + 8 = 40 bytes (RFC 3394 overhead).
 * -------------------------------------------------------------------------*/
#define LOCAL_WRAP_OVERHEAD     8   /* RFC 3394 AES-WRAP overhead in bytes */
#define LOCAL_WRAPPED_DEK_LEN   (TDE_DEK_LEN + LOCAL_WRAP_OVERHEAD)  /* 40 bytes */


/* -------------------------------------------------------------------------
 * KEK versions (PSQLE-185)
 *
 * A KEK rotation used to overwrite the wallet's only KEK before its
 * transaction committed, so a rotation that rolled back, failed later in its
 * statement or died in a crash left the catalog wrapped under a key that
 * existed nowhere.  The wallet now keeps every KEK version: a rotation adds
 * one, written durably before any DEK is re-wrapped, and nothing is removed.
 * Whatever the transaction does, every row still unwraps with a key the
 * wallet has — the same model as Vault Transit key versions and the PKCS#11
 * provider's "<label>.v<N>" objects.
 *
 * On disk: one PKCS#12 key bag per version, friendlyName
 * "pg_vault_tde_kek.v<N>", the current (highest) version first.  A wallet
 * written before 1.7.2 has a single bag named "pg_vault_tde_kek", read as
 * version 1.  PKCS12_parse() returns the first key, so a reader that knows
 * nothing about versions still gets the current KEK.
 *
 * The wrapped DEK is unchanged — 40 bytes of RFC 3394 AES key wrap, no version
 * tag.  Unwrap tries the versions newest first and the key wrap's own
 * integrity check rejects a wrong KEK; after a committed rotation every row is
 * under the current version, so that is a single attempt.
 * -------------------------------------------------------------------------*/
#define LOCAL_KEK_BAG_NAME      "pg_vault_tde_kek"
#define LOCAL_KEK_MAX_VERSIONS  256

typedef struct LocalKekRing
{
    int           n;                                        /* versions held */
    uint32        version[LOCAL_KEK_MAX_VERSIONS];          /* [0] is current */
    unsigned char kek[LOCAL_KEK_MAX_VERSIONS][TDE_DEK_LEN];
} LocalKekRing;


/*
 * Per-backend wallet state.
 *
 * Stored in TopMemoryContext (process lifetime).  The KEK is zeroed
 * immediately after DEK unwrap; only boolean flags are retained.
 *
 * The wallet path is deliberately NOT cached here: it is re-resolved from the
 * effective GUC through local_get_wallet_path() at every use, so an
 * ALTER DATABASE SET pg_vault_tde.wallet_path applied after the provider was
 * selected is honoured instead of being shadowed by a stale snapshot.
 *
 * kek[] is wiped after every unwrap call — it MUST NOT persist in memory.
 */
typedef struct LocalWalletState
{
    bool         wallet_open;   /* true iff wallet was successfully opened */
    bool         kek_loaded;    /* true while wallet is open (unlock caches KEK here);
                                 * cleared by wallet_lock() or backend exit */
    TimestampTz  last_opened;   /* last successful open timestamp; 0 = never */
    /* every KEK version, cached by wallet_unlock(); cleared on lock */
    LocalKekRing *ring;
} LocalWalletState;

static LocalWalletState *local_wallet_state = NULL;

/*
 * local_state — return the per-backend wallet state, allocating it on first
 * use in TopMemoryContext so it survives query boundaries.
 *
 * Every site that *stores* into the state must go through this: since the
 * provider is initialised lazily (tde_kms_provider()), a session whose first
 * KMS-touching action is an SQL wallet function — wallet_unlock(),
 * wallet_init(), change_passphrase(), rotate_kek(), migrate() — reaches that
 * function before local_init() has ever run.  Read-only sites keep testing
 * local_wallet_state directly: a read must never allocate.
 */
static LocalWalletState *
local_state(void)
{
    if (local_wallet_state == NULL)
    {
        MemoryContext old_ctx = MemoryContextSwitchTo(TopMemoryContext);

        local_wallet_state = palloc0(sizeof(LocalWalletState));
        MemoryContextSwitchTo(old_ctx);
    }

    return local_wallet_state;
}

static LocalKekRing *
local_ring_new(MemoryContext cxt)
{
    return (LocalKekRing *) MemoryContextAllocZero(cxt, sizeof(LocalKekRing));
}

static void
local_ring_free(LocalKekRing *ring)
{
    if (ring == NULL)
        return;
    OPENSSL_cleanse(ring, sizeof(LocalKekRing));
    pfree(ring);
}

/* Keep every KEK version in this backend, as wallet_unlock() does. */
static void
local_cache_ring(const LocalKekRing *ring)
{
    LocalWalletState *st = local_state();

    if (st->ring == NULL)
        st->ring = local_ring_new(TopMemoryContext);
    memcpy(st->ring, ring, sizeof(LocalKekRing));
    st->kek_loaded  = true;
    st->wallet_open = true;
    st->last_opened = GetCurrentTimestamp();
}

static void
local_drop_cached_ring(void)
{
    if (local_wallet_state == NULL)
        return;
    if (local_wallet_state->ring != NULL)
        OPENSSL_cleanse(local_wallet_state->ring, sizeof(LocalKekRing));
    local_wallet_state->kek_loaded = false;
}

/*
 * next = a fresh random KEK as the new current version, then every version of
 * cur.  Returns false only if no random KEK could be generated.
 */
static bool
local_ring_add_version(const LocalKekRing *cur, LocalKekRing *next)
{
    if (cur->n >= LOCAL_KEK_MAX_VERSIONS)
        ereport(ERROR,
                errmsg("pg_vault_tde: the wallet already holds %d KEK versions, "
                       "the most it can keep", LOCAL_KEK_MAX_VERSIONS),
                errhint("Rotation and wallet_change_passphrase() are refused "
                        "from here on; nothing was changed.  Removing old "
                        "versions is planned for 1.8."));

    memset(next, 0, sizeof(LocalKekRing));
    if (!pg_strong_random(next->kek[0], TDE_DEK_LEN))
        return false;
    next->version[0] = (cur->n > 0 ? cur->version[0] : 0) + 1;
    memcpy(&next->version[1], cur->version, (size_t) cur->n * sizeof(uint32));
    memcpy(next->kek[1], cur->kek, (size_t) cur->n * TDE_DEK_LEN);
    next->n = cur->n + 1;
    return true;
}

/* "pg_vault_tde_kek" (wallets before 1.7.2) is version 1. */
static bool
local_kek_version_from_name(const char *name, uint32 *version)
{
    unsigned int v;
    char         tail;

    if (strcmp(name, LOCAL_KEK_BAG_NAME) == 0)
    {
        *version = 1;
        return true;
    }
    if (sscanf(name, LOCAL_KEK_BAG_NAME ".v%u%c", &v, &tail) == 1 && v > 0)
    {
        *version = v;
        return true;
    }
    return false;
}

/*
 * Serialise every read-modify-write of the wallet file.  Two rotations — two
 * sessions of one database, or two databases sharing a wallet — could
 * otherwise read the same versions and each write back a file missing the
 * other's new one, and the rows re-wrapped under the lost version with it.
 * OpenTransientFile(): fd.c closes the file at transaction abort, which
 * releases the lock even when an ERROR skips local_wallet_unlock_file().
 */
static int
local_wallet_lock_file(const char *wallet_path)
{
    char lock_path[MAXPGPATH];
    int  fd;

    snprintf(lock_path, sizeof(lock_path), "%s.lock", wallet_path);
    fd = OpenTransientFile(lock_path, O_RDWR | O_CREAT | PG_BINARY);
    if (fd < 0)
        ereport(ERROR,
                errcode_for_file_access(),
                errmsg("pg_vault_tde: could not open \"%s\": %m", lock_path));

    while (flock(fd, LOCK_EX | LOCK_NB) != 0)
    {
        if (errno != EWOULDBLOCK && errno != EINTR)
        {
            int save_errno = errno;

            CloseTransientFile(fd);
            errno = save_errno;
            ereport(ERROR,
                    errcode_for_file_access(),
                    errmsg("pg_vault_tde: could not lock \"%s\": %m", lock_path));
        }
        CHECK_FOR_INTERRUPTS();
        pg_usleep(10000L);
    }
    return fd;
}

static void
local_wallet_unlock_file(int fd)
{
    (void) flock(fd, LOCK_UN);
    CloseTransientFile(fd);
}

/*
 * KEK rotation context — allocated in TopMemoryContext by prepare_kek_rotation(),
 * freed (after OPENSSL_cleanse) by commit/abort. NULL when no rotation is in progress.
 */
typedef struct LocalKekRotationCtx
{
    LocalKekRing ring;      /* ring.kek[0] is the new KEK; all of it unwraps */
} LocalKekRotationCtx;

static LocalKekRotationCtx *local_kek_rotation_ctx = NULL;
static bool local_kek_rotation_callback_registered = false;

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
static bool local_open_wallet_ring(const char *path, const char *passphrase,
                                   LocalKekRing *out);
static void local_write_wallet_ring(const char *dest_path, const char *passphrase,
                                    const LocalKekRing *ring);
static bool local_unwrap_dek_with_ring(const unsigned char *wrapped,
                                       int wrapped_len, unsigned char *dek_out,
                                       int *dek_len, const LocalKekRing *ring);
static bool local_open_wallet(const char *path, const char *passphrase,
                              unsigned char *kek_out);
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
#define TDE_DEFAULT_WALLET_FMT "/var/lib/pg_vault_tde/%u/wallet.p12"

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

/*
 * pg_vault_tde_kms_local_wallet_path — GUC show_hook for
 * pg_vault_tde.wallet_path.
 *
 * Without it SHOW returns an empty string whenever the GUC is not explicitly
 * set, hiding the per-database default the provider actually uses.  Signature
 * must stay GucShowHook-compatible: const char *(*)(void).
 */
const char *
pg_vault_tde_kms_local_wallet_path(void)
{
    return local_get_wallet_path();
}

/*
 * pg_vault_tde_kms_local_reset — drop cached key material and the open flag.
 *
 * Called from tde_kms_provider_invalidate() when any GUC that feeds the
 * provider changes: a KEK derived from the previous wallet path / passphrase
 * source must not survive into the new configuration.  No-op before the
 * provider has ever been initialised in this backend.
 */
void
pg_vault_tde_kms_local_reset(void)
{
    if (local_wallet_state == NULL)
        return;

    local_drop_cached_ring();
    local_wallet_state->wallet_open = false;
}



/* -------------------------------------------------------------------------
 * local_init — open wallet on backend startup
 * -------------------------------------------------------------------------*/
static bool
local_init(void)
{
    char          pass[1024];

    /*
     * Allocate per-backend state in TopMemoryContext so it survives
     * query boundaries.  KEK buffer inside the struct is wiped after every
     * unwrap — it does NOT persist across calls.
     *
     * Must be idempotent: tde_kms_provider_invalidate() can schedule another
     * init() in the same backend (e.g. after a SET of a wallet GUC, or the
     * SetConfigOption that pg_vault_tde_wallet_init performs), and
     * re-allocating here would leak the old state and discard a cached KEK.
     */
    (void) local_state();

    /*
     * A KEK is already cached (wallet_unlock / wallet_init ran in this
     * backend): the wallet is open by definition, nothing to re-derive.
     */
    if (local_wallet_state->kek_loaded)
        return true;

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

    /*
     * Retrieve the passphrase from the configured source.  init() now runs at
     * first KMS use rather than at GUC assign time, so reaching this branch
     * means no passphrase source is effectively configured for this database
     * — not merely that the GUCs had not been applied yet.
     */
    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: no wallet passphrase source configured "
                       "— wallet not opened; encryption-at-rest is "
                       "unavailable until it is"),
                errdetail("Passphrase sources: wallet_passphrase_command=\"%s\", "
                          "wallet_passphrase_env=\"%s\", "
                          "wallet_passphrase_file=\"%s\".",
                          pg_vault_tde_wallet_passphrase_command
                              ? pg_vault_tde_wallet_passphrase_command : "",
                          pg_vault_tde_wallet_passphrase_env
                              ? pg_vault_tde_wallet_passphrase_env : "",
                          pg_vault_tde_wallet_passphrase_file
                              ? pg_vault_tde_wallet_passphrase_file : ""),
                errhint("Set one of them, or call "
                        "pg_vault_tde_wallet_unlock('<passphrase>')."));
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

        if (!local_open_wallet(local_get_wallet_path(), pass, kek_temp))
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
    LocalKekRing *ring;
    bool          ok;

    Assert(wrapped != NULL);
    Assert(wrapped_len == LOCAL_WRAPPED_DEK_LEN);
    Assert(dek_out != NULL && dek_len != NULL);
    Assert(passphrase != NULL);
    Assert(wallet_path != NULL);

    if (wrapped_len != LOCAL_WRAPPED_DEK_LEN) return false;

    ring = local_ring_new(CurrentMemoryContext);
    if (!local_open_wallet_ring(wallet_path, passphrase, ring))
    {
        local_ring_free(ring);
        ereport(WARNING,
                errmsg("pg_vault_tde: local_unwrap_dek_with_pass: "
                       "could not open wallet \"%s\"", wallet_path));
        return false;
    }

    ok = local_unwrap_dek_with_ring(wrapped, wrapped_len, dek_out, dek_len, ring);
    if (!ok)
        ereport(WARNING,
                errmsg("pg_vault_tde: AES-256-UNWRAP failed with all %d KEK "
                       "version(s) of the wallet (wrong passphrase or corrupt "
                       "wrapped DEK)", ring->n));
    local_ring_free(ring);
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
 * Symmetric inverse of local_wrap_dek_with_kek.  Silent on failure: with
 * several KEK versions a mismatch is expected, and the caller reports once.
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
    {
        OPENSSL_cleanse(dek_out, TDE_DEK_LEN);
        ERR_clear_error();
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Every version, newest first; the key wrap's integrity check picks the one. */
static bool
local_unwrap_dek_with_ring(const unsigned char *wrapped, int wrapped_len,
                           unsigned char *dek_out, int *dek_len,
                           const LocalKekRing *ring)
{
    int i;

    for (i = 0; i < ring->n; i++)
        if (local_unwrap_dek_with_kek(wrapped, wrapped_len, dek_out, dek_len,
                                      ring->kek[i]))
            return true;
    return false;
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
                                       local_wallet_state->ring->kek[0]);

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

        path = local_get_wallet_path();

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

    /* Fast path: KEK versions cached by wallet_unlock(). */
    if (local_wallet_state && local_wallet_state->kek_loaded)
    {
        LocalKekRing *ring;

        if (local_unwrap_dek_with_ring(wrapped, wrapped_len, dek_out, dek_len,
                                       local_wallet_state->ring))
            return true;

        /*
         * None of the versions this session holds opens it: the wallet gained
         * one since wallet_unlock() — another session rotated the KEK or
         * changed the passphrase.  Reload the wallet when a passphrase source
         * can; otherwise only a new wallet_unlock() can.
         */
        if (!local_get_passphrase(pass, sizeof(pass)))
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: local unwrap_dek: no KEK version "
                           "cached by wallet_unlock() in this session opens "
                           "this DEK"),
                    errhint("If another session rotated the KEK or changed the "
                            "passphrase, call pg_vault_tde_wallet_unlock() "
                            "again."));
            return false;
        }
        ring = local_ring_new(CurrentMemoryContext);
        ok = local_open_wallet_ring(local_get_wallet_path(), pass, ring) &&
             local_unwrap_dek_with_ring(wrapped, wrapped_len, dek_out, dek_len,
                                        ring);
        OPENSSL_cleanse(pass, sizeof(pass));
        if (ok)
            local_cache_ring(ring);
        else
            ereport(WARNING,
                    errmsg("pg_vault_tde: AES-256-UNWRAP failed with every KEK "
                           "version of the wallet"));
        local_ring_free(ring);
        return ok;
    }

    /* Slow path: re-derive passphrase from GUC source. */
    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: local unwrap_dek: passphrase unavailable "
                       "— call pg_vault_tde_wallet_unlock() or configure "
                       "pg_vault_tde.wallet_passphrase_env"));
        return false;
    }

    path = local_get_wallet_path();

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
        const LocalKekRing *ring = &local_kek_rotation_ctx->ring;

        dek_temp_len = TDE_DEK_LEN;
        ok = local_unwrap_dek_with_ring(old_wrapped, old_len,
                                        dek_temp, &dek_temp_len, ring);
        if (!ok)
            ereport(WARNING,
                    errmsg("pg_vault_tde: KEK rotation: a DEK unwraps with none "
                           "of the wallet's %d KEK version(s)", ring->n));
        else
            ok = local_wrap_dek_with_kek(dek_temp, TDE_DEK_LEN,
                                         new_wrapped, new_len, ring->kek[0]);
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
    OPENSSL_cleanse(local_kek_rotation_ctx, sizeof(LocalKekRotationCtx));
    pfree(local_kek_rotation_ctx);
    local_kek_rotation_ctx = NULL;
}

/* The keys go at the end of the transaction, whatever ends it. */
static void
local_kek_rotation_xact_callback(XactEvent event, void *arg)
{
    if (event == XACT_EVENT_COMMIT || event == XACT_EVENT_ABORT ||
        event == XACT_EVENT_PARALLEL_COMMIT || event == XACT_EVENT_PARALLEL_ABORT)
        local_kek_rotation_ctx_free();
}

/*
 * Arm a re-wrap: every row unwraps with some version of `ring` and is wrapped
 * again under ring->kek[0].  A context left by a rotation that failed is
 * replaced — nothing else can be using it.
 */
static void
local_kek_rotation_ctx_set(const LocalKekRing *ring)
{
    local_kek_rotation_ctx_free();

    if (!local_kek_rotation_callback_registered)
    {
        RegisterXactCallback(local_kek_rotation_xact_callback, NULL);
        local_kek_rotation_callback_registered = true;
    }

    local_kek_rotation_ctx = (LocalKekRotationCtx *)
        MemoryContextAllocZero(TopMemoryContext, sizeof(LocalKekRotationCtx));
    memcpy(&local_kek_rotation_ctx->ring, ring, sizeof(LocalKekRing));
}

/* -------------------------------------------------------------------------
 * local_prepare_kek_rotation — vtable: add a KEK version and arm the re-wrap.
 *
 * The new version goes into the wallet file, durably and ahead of every older
 * one, BEFORE pg_vault_tde_catalog_rewrap_all() touches a row.  From then on
 * each row unwraps with a version the file holds whatever the transaction
 * does: commit, roll back, fail later in its statement, or crash.
 *
 * Needs the passphrase from a configured source, because the file is
 * re-encrypted under it; a KEK cached by wallet_unlock() is not enough.
 * -------------------------------------------------------------------------*/
static bool
local_prepare_kek_rotation(void)
{
    const char   *path = local_get_wallet_path();
    char          pass[1024];
    LocalKekRing *cur;
    LocalKekRing *next;
    bool          ok;

    if (!local_get_passphrase(pass, sizeof(pass)))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: KEK rotation needs the wallet passphrase "
                       "from wallet_passphrase_command, wallet_passphrase_env "
                       "or wallet_passphrase_file"));
        return false;
    }

    cur  = local_ring_new(CurrentMemoryContext);
    next = local_ring_new(CurrentMemoryContext);

    PG_TRY();
    {
        int lock_fd = local_wallet_lock_file(path);

        if (local_open_wallet_ring(path, pass, cur) &&
            local_ring_add_version(cur, next))
        {
            local_write_wallet_ring(path, pass, next);
            local_kek_rotation_ctx_set(next);
            if (local_wallet_state && local_wallet_state->kek_loaded)
                local_cache_ring(next);
        }
        else
            next->n = 0;
        local_wallet_unlock_file(lock_fd);
    }
    PG_FINALLY();
    {
        OPENSSL_cleanse(pass, sizeof(pass));
    }
    PG_END_TRY();

    if (next->n > 0)
        ereport(LOG,
                errmsg("pg_vault_tde: KEK version %u added to the wallet; "
                       "re-wrapping the DEKs", next->version[0]));

    ok = (next->n > 0);
    local_ring_free(cur);
    local_ring_free(next);
    return ok;
}

/* -------------------------------------------------------------------------
 * local_commit_kek_rotation — vtable: the re-wrap is done.
 *
 * Nothing left to make durable: the wallet was written in prepare.  The
 * context is released here, and at the end of the transaction otherwise.
 * -------------------------------------------------------------------------*/
static void
local_commit_kek_rotation(void)
{
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

    path = local_get_wallet_path();
    if (!path || !path[0])
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

    /* Wipe the KEK versions cached by wallet_unlock(), if any. */
    local_drop_cached_ring();

    tde_audit(WALLET_CLOSE, NULL, true);
    local_wallet_state->wallet_open  = false;
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
             TDE_DEFAULT_WALLET_FMT, MyDatabaseId);

    return path_buf;
}

/*
 * pg_vault_tde_local_wallet_is_overridden — is the wallet not this database's
 * own default file?
 *
 * Note this cannot be answered by testing whether pg_vault_tde.wallet_path is
 * set: pg_vault_tde_wallet_init() persists the resolved path with ALTER
 * DATABASE ... SET FROM CURRENT (local_set_wallet), so after an ordinary setup
 * the GUC is always populated — with the per-database default.  Comparing
 * against that default is what actually distinguishes "somewhere else, and
 * possibly shared" from "this database's own file".
 */
bool
pg_vault_tde_local_wallet_is_overridden(void)
{
    char dflt[MAXPGPATH];

    /* No database attached: nothing to compare against. */
    if (!OidIsValid(MyDatabaseId))
        return false;

    snprintf(dflt, sizeof(dflt), TDE_DEFAULT_WALLET_FMT, MyDatabaseId);

    return strcmp(local_get_wallet_path(), dflt) != 0;
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
    int         fd;

    fpath = pg_vault_tde_wallet_passphrase_file;
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
        ereport(WARNING,
                errmsg("pg_vault_tde: cannot open passphrase file \"%s\": %m",
                       fpath));
        return false;
    }

    /* Permission sanity check, against the descriptor actually opened */
    if (fstat(fd, &st) != 0)
    {
        close(fd);
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
        close(fd);              /* ereport(ERROR) longjmps out of here */
        ereport(ERROR,
                errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pg_vault_tde: passphrase file \"%s\" is group- or "
                       "world-readable (mode %04o); refusing to read passphrase",
                       fpath, (unsigned)(st.st_mode & 0777)));
    }

    fp = fdopen(fd, "r");
    if (!fp)
    {
        close(fd);
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
/*
 * local_open_wallet_ring — every KEK version in the wallet, current first.
 *
 * Walks the PKCS#12 bags itself: PKCS12_parse() stops at the first key.
 */
static bool
local_open_wallet_ring(const char *path, const char *passphrase,
                       LocalKekRing *out)
{
    FILE            *fp;
    PKCS12          *p12;
    STACK_OF(PKCS7) *asafes;
    int              i, j;

    Assert(path != NULL);
    Assert(passphrase != NULL);
    Assert(out != NULL);

    memset(out, 0, sizeof(LocalKekRing));

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

    if (!PKCS12_verify_mac(p12, passphrase, -1))
    {
        PKCS12_free(p12);
        ereport(WARNING,
                errmsg("pg_vault_tde: wallet MAC verification failed - "
                       "wrong passphrase or corrupt wallet"));
        return false;
    }

    asafes = PKCS12_unpack_authsafes(p12);
    PKCS12_free(p12);
    if (!asafes)
    {
        ereport(WARNING, errmsg("pg_vault_tde: PKCS#12 parsing failed"));
        return false;
    }

    for (i = 0; i < sk_PKCS7_num(asafes); i++)
    {
        PKCS7                    *p7 = sk_PKCS7_value(asafes, i);
        STACK_OF(PKCS12_SAFEBAG) *bags = NULL;

        if (PKCS7_type_is_data(p7))
            bags = PKCS12_unpack_p7data(p7);
        else if (PKCS7_type_is_encrypted(p7))
            bags = PKCS12_unpack_p7encdata(p7, passphrase, -1);
        if (!bags)
            continue;

        for (j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++)
        {
            PKCS12_SAFEBAG            *bag = sk_PKCS12_SAFEBAG_value(bags, j);
            PKCS8_PRIV_KEY_INFO       *shrouded = NULL;
            const PKCS8_PRIV_KEY_INFO *p8 = NULL;
            EVP_PKEY                  *pkey;
            char                      *name;
            uint32                     version;
            size_t                     klen = TDE_DEK_LEN;

            if (PKCS12_SAFEBAG_get_nid(bag) == NID_pkcs8ShroudedKeyBag)
                p8 = shrouded = PKCS12_decrypt_skey(bag, passphrase, -1);
            else if (PKCS12_SAFEBAG_get_nid(bag) == NID_keyBag)
                p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
            if (!p8)
                continue;

            pkey = EVP_PKCS82PKEY(p8);
            if (shrouded)
                PKCS8_PRIV_KEY_INFO_free(shrouded);
            name = PKCS12_get_friendlyname(bag);

            if (pkey && name && out->n < LOCAL_KEK_MAX_VERSIONS &&
                local_kek_version_from_name(name, &version) &&
                EVP_PKEY_get_raw_private_key(pkey, out->kek[out->n], &klen) == 1 &&
                klen == TDE_DEK_LEN)
            {
                out->version[out->n] = version;
                out->n++;
            }
            if (name)
                OPENSSL_free(name);
            if (pkey)
                EVP_PKEY_free(pkey);
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }
    sk_PKCS7_pop_free(asafes, PKCS7_free);

    if (out->n == 0)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wallet \"%s\" holds no KEK", path));
        return false;
    }

    /* Newest first, whatever order the file had. */
    for (i = 1; i < out->n; i++)
        for (j = i; j > 0 && out->version[j] > out->version[j - 1]; j--)
        {
            uint32        v = out->version[j];
            unsigned char k[TDE_DEK_LEN];

            out->version[j]     = out->version[j - 1];
            out->version[j - 1] = v;
            memcpy(k, out->kek[j], TDE_DEK_LEN);
            memcpy(out->kek[j], out->kek[j - 1], TDE_DEK_LEN);
            memcpy(out->kek[j - 1], k, TDE_DEK_LEN);
            OPENSSL_cleanse(k, TDE_DEK_LEN);
        }

    return true;
}

/* The current KEK only — for the callers that need nothing else. */
static bool
local_open_wallet(const char *path, const char *passphrase,
                  unsigned char *kek_out)
{
    LocalKekRing *ring = local_ring_new(CurrentMemoryContext);
    bool          ok   = local_open_wallet_ring(path, passphrase, ring);

    if (ok)
        memcpy(kek_out, ring->kek[0], TDE_DEK_LEN);
    local_ring_free(ring);
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
    {
        LocalKekRing *ring = local_ring_new(CurrentMemoryContext);

        if (local_open_wallet_ring(path, passphrase, ring))
            local_cache_ring(ring);
        else
        {
            /* Wallet was just written — this should never fail */
            ereport(WARNING,
                    errmsg("pg_vault_tde: wallet created but could not be "
                           "re-opened for KEK caching at \"%s\"", path));
            local_state()->wallet_open = true;
        }
        local_ring_free(ring);
    }

    OPENSSL_cleanse(passphrase, strlen(passphrase));
    pfree(passphrase);

    ereport(LOG, errmsg("pg_vault_tde: wallet initialized at \"%s\"", path));

    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * local_write_wallet_ring — write every KEK version, current first
 *
 * To `dest_path.new`, then durable_rename(): the file and its directory are
 * fsync'd, so a crash leaves either the old wallet or the new one, never a
 * half-written one and never a rename that did not reach the disk.
 * ereports ERROR on failure.
 * -------------------------------------------------------------------------*/
static void
local_write_wallet_ring(const char *dest_path, const char *passphrase,
                        const LocalKekRing *ring)
{
    char                      tmp_path[MAXPGPATH];
    STACK_OF(PKCS12_SAFEBAG) *bags  = NULL;
    STACK_OF(PKCS7)          *safes = NULL;
    PKCS12                   *p12   = NULL;
    int                       fd;
    FILE                     *fp;
    int                       i;
    bool                      built = false;

    Assert(dest_path != NULL);
    Assert(passphrase != NULL);
    Assert(ring != NULL && ring->n > 0);

    snprintf(tmp_path, sizeof(tmp_path), "%s.new", dest_path);

    for (i = 0; i < ring->n; i++)
    {
        char            name[64];
        EVP_PKEY       *pkey;
        PKCS12_SAFEBAG *bag;

        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                            ring->kek[i], TDE_DEK_LEN);
        if (!pkey)
            break;
        bag = PKCS12_add_key(&bags, pkey, 0, PKCS12_DEFAULT_ITER,
                             NID_aes_256_cbc, passphrase);
        EVP_PKEY_free(pkey);
        snprintf(name, sizeof(name), LOCAL_KEK_BAG_NAME ".v%u", ring->version[i]);
        if (!bag || !PKCS12_add_friendlyname(bag, name, -1))
            break;
    }
    if (i == ring->n &&
        PKCS12_add_safe(&safes, bags, -1, 0, NULL) &&
        (p12 = PKCS12_add_safes(safes, 0)) != NULL &&
        PKCS12_set_mac(p12, passphrase, -1, NULL, 0, PKCS12_DEFAULT_ITER, NULL))
        built = true;

    if (bags)
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    if (safes)
        sk_PKCS7_pop_free(safes, PKCS7_free);
    if (!built)
    {
        if (p12)
            PKCS12_free(p12);
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
    if (!fp || i2d_PKCS12_fp(fp, p12) != 1 || fclose(fp) != 0)
    {
        if (!fp)
            close(fd);
        unlink(tmp_path);
        PKCS12_free(p12);
        ereport(ERROR,
                errmsg("pg_vault_tde: could not write wallet to \"%s\"",
                       tmp_path));
    }
    PKCS12_free(p12);

    if (chmod(tmp_path, 0600) != 0)
    {
        unlink(tmp_path);
        ereport(ERROR,
                errmsg("pg_vault_tde: chmod(\"%s\", 0600) failed: %m",
                       tmp_path));
    }

    if (durable_rename(tmp_path, dest_path, LOG) != 0)
    {
        unlink(tmp_path);
        ereport(ERROR,
                errmsg("pg_vault_tde: could not install the wallet \"%s\"",
                       dest_path));
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

    /*
     * Resolve the provider first.  Since init() is lazy, a session whose first
     * action is this function would otherwise report wallet_open = false
     * simply because nothing had opened the wallet yet — a monitoring answer
     * about the session, not about the wallet.  Going through the accessor
     * gives auto-open its chance, so the reported state is the real one.
     */
    (void) tde_kms_provider();

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
 * pg_vault_tde_wallet_change_passphrase — new passphrase, new KEK version
 *
 * Algorithm:
 *   1. Open every KEK version with old_passphrase.
 *   2. Add a new version and write the wallet under new_passphrase — durably,
 *      with every old version still in it, BEFORE any row changes.
 *   3. Re-wrap every DEK under the new version.
 *   4. Evict the shmem cache so the next access unwraps again.
 *
 * Step 2 is what makes a failure harmless: whatever happens to the
 * transaction afterwards, every row unwraps with a version the wallet holds.
 * The new passphrase is in effect from step 2 on, even if the call then fails.
 * -------------------------------------------------------------------------*/
PG_FUNCTION_INFO_V1(pg_vault_tde_wallet_change_passphrase_sql);

PGDLLEXPORT Datum
pg_vault_tde_wallet_change_passphrase_sql(PG_FUNCTION_ARGS)
{
    text         *old_t    = PG_GETARG_TEXT_PP(0);
    text         *new_t    = PG_GETARG_TEXT_PP(1);
    char         *old_pass = text_to_cstring(old_t);
    char         *new_pass = text_to_cstring(new_t);
    const char   *path;
    LocalKekRing *cur;
    LocalKekRing *next;

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_wallet_change_passphrase requires superuser"));

    path = local_get_wallet_path();
    cur  = local_ring_new(CurrentMemoryContext);
    next = local_ring_new(CurrentMemoryContext);

    PG_TRY();
    {
        int lock_fd = local_wallet_lock_file(path);

        /* The MAC check authenticates old_pass against the file on disk. */
        if (!local_open_wallet_ring(path, old_pass, cur))
            ereport(ERROR,
                    errcode(ERRCODE_INVALID_PASSWORD),
                    errmsg("pg_vault_tde: wrong passphrase (could not open wallet)"));

        if (!local_ring_add_version(cur, next))
            ereport(ERROR,
                    errmsg("pg_vault_tde: change_passphrase: could not generate new KEK"));

        local_write_wallet_ring(path, new_pass, next);
        local_wallet_unlock_file(lock_fd);

        local_kek_rotation_ctx_set(next);
        pg_vault_tde_catalog_rewrap_all();
        local_kek_rotation_ctx_free();
    }
    PG_FINALLY();
    {
        OPENSSL_cleanse(old_pass, strlen(old_pass));
        OPENSSL_cleanse(new_pass, strlen(new_pass));
    }
    PG_END_TRY();

    /* Evict shmem — next access loads with new KEK */
    pg_vault_tde_catalog_evict_db();

    /*
     * Always cache the KEK versions, whether or not wallet_unlock() ran first:
     * a backend on the slow path would otherwise re-read the now-stale
     * passphrase source against a wallet already re-MAC'd under new_pass, and
     * fail its very next SELECT with "MAC verification failed".
     */
    local_cache_ring(next);

    local_ring_free(cur);
    local_ring_free(next);
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
    LocalKekRing *ring;

    if (!superuser())
        ereport(ERROR,
                errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                errmsg("pg_vault_tde_wallet_unlock requires superuser"));

    path = local_get_wallet_path();
    ring = local_ring_new(CurrentMemoryContext);

    if (!local_open_wallet_ring(path, passphrase, ring))
    {
        OPENSSL_cleanse(passphrase, strlen(passphrase));
        local_ring_free(ring);
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
    local_cache_ring(ring);
    local_ring_free(ring);

    /*
     * Evict shmem so every backend reloads DEKs through the full
     * unwrap path.  Other backends that lack the cached KEK will use
     * the GUC passphrase source; if that is also absent they must call
     * wallet_unlock() themselves.
     */
    pg_vault_tde_catalog_evict_db();

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

    pg_vault_tde_catalog_evict_db();

    if (local_wallet_state)
    {
        /*
         * Evict the cached KEK so that this backend can no longer
         * wrap or unwrap DEKs without a fresh wallet_unlock() or a
         * configured passphrase GUC source.
         */
        local_drop_cached_ring();
        local_wallet_state->wallet_open = false;
    }

    ereport(LOG, errmsg("pg_vault_tde: wallet locked; KEK and this database's DEKs cleared from shmem"));

    PG_RETURN_VOID();
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_migrate_vault_to_wallet — re-wrap all Vault DEKs under local wallet
 *
 * new_passphrase must open the wallet pg_vault_tde_wallet_init() created; its
 * current KEK is the key everything is wrapped under.  For each row in
 * pg_vault_tde_catalog with kms_provider='vault':
 *   1. Unwrap the DEK using the Vault provider.
 *   2. Re-wrap it under the wallet's current KEK.
 *   3. UPDATE the catalog row with the new wrapped_dek and kms_provider='local'.
 *
 * Then the database switches to the local provider — this session at once,
 * new sessions through a database-level setting — since the Vault provider
 * cannot unwrap what was just written.  The plaintext DEKs do not change, so
 * the shmem cache is left alone: every session keeps reading the tables it
 * has cached, including those connected before the migration.
 *
 * Until PSQLE-188 the DEKs were wrapped under a KEK derived from the
 * passphrase, which the wallet does not hold, so no migrated table read again.
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
     * The wallet's own current KEK, once, before the scan loop.  Opening the
     * file is also what proves new_pass is the wallet's passphrase: the MAC
     * check fails otherwise, and nothing has been touched yet.
     */
    {
        LocalKekRing *ring = local_ring_new(CurrentMemoryContext);

        if (!local_open_wallet_ring(wallet_path, new_pass, ring))
        {
            local_ring_free(ring);
            OPENSSL_cleanse(new_pass, strlen(new_pass));
            pfree(new_pass);
            ereport(ERROR,
                    errcode(ERRCODE_INVALID_PASSWORD),
                    errmsg("pg_vault_tde: migrate_vault_to_wallet: the passphrase "
                           "does not open the local wallet at \"%s\"", wallet_path),
                    errhint("Pass the passphrase given to pg_vault_tde_wallet_init()."));
        }
        memcpy(new_kek, ring->kek[0], TDE_DEK_LEN);
        local_ring_free(ring);
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

    /*
     * NULL, not GetTransactionSnapshot(): systable_beginscan() then picks the
     * catalog snapshot itself.  A transaction snapshot is neither registered
     * nor active, so HeapTupleSatisfiesVisibility asserts
     * (regd_count > 0 || active_count > 0) on an assert-enabled server and,
     * worse, nothing pins it for the life of the scan.  Core passes NULL for
     * every catalog scan; see make ci-cassert.
     */
    scan = systable_beginscan(catalog_rel, InvalidOid, false, NULL, 1, &scan_key);

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
                    if (!tde_kms_provider())
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

    /*
     * No pg_vault_tde_catalog_evict_db(): the DEKs are the same, only their
     * wrapping moved, and evicting would send every session back to the
     * Vault provider, which cannot unwrap the new wrapping.
     *
     * Switch this database to the local provider — this session now, and
     * the ones that connect later through the database-level setting, the
     * same mechanism local_set_wallet() uses for wallet_path.
     */
    {
        VariableSetStmt *setstmt;

        SetConfigOption("pg_vault_tde.kms_provider", "local",
                        PGC_SUSET, PGC_S_SESSION);

        setstmt        = makeNode(VariableSetStmt);
        setstmt->kind  = VAR_SET_CURRENT;
        setstmt->name  = "pg_vault_tde.kms_provider";
        setstmt->args  = NIL;
        AlterSetting(MyDatabaseId, InvalidOid, setstmt);
    }

    {
        LocalWalletState *st = local_state();

        st->wallet_open = true;
        st->last_opened = GetCurrentTimestamp();
    }

    OPENSSL_cleanse(new_pass, strlen(new_pass));
    OPENSSL_cleanse(new_kek, TDE_DEK_LEN);
    pfree(new_pass);

    ereport(LOG,
            errmsg("pg_vault_tde: vault-to-wallet migration complete; "
                   "%d entries migrated", migrated));
    ereport(NOTICE,
            errmsg("pg_vault_tde: this database now uses the local wallet "
                   "(kms_provider = 'local')"),
            errdetail("Sessions connected before the migration keep the Vault "
                      "provider until they reconnect; they still read the "
                      "tables whose keys are cached."));

    PG_RETURN_VOID();
}

