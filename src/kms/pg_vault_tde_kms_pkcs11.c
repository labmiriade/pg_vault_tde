/*
 * pg_vault_tde_kms_pkcs11.c — PKCS#11 / HSM KMS provider (v1.7)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * OVERVIEW:
 * ---------
 * This module implements the `pkcs11` KMS provider.  It dlopen()s the
 * HSM vendor's PKCS#11 module (GUC pg_vault_tde.pkcs11_library) and
 * wraps/unwraps per-table DEKs with C_WrapKey/C_UnwrapKey against an
 * AES-256 KEK that lives on the token and never leaves the HSM.
 *
 * KEY HIERARCHY:
 *   HSM token (user PIN via env var) → KEK (CKO_SECRET_KEY, CKA_EXTRACTABLE=FALSE)
 *     └── C_WrapKey (CKM_AES_KEY_WRAP, RFC 3394) → per-table DEK
 *                   └── encrypts → tuple data (AES-256-GCM, per tuple)
 *
 *   Each KEK generation is an immutable token object labelled
 *   "<pkcs11_key_label>.v<N>"; rotation never renames or destroys a key
 *   (see the KEK ROTATION note above pkcs11_prepare_kek_rotation).  Every
 *   wrapped_dek blob is prefixed with the version tag of the KEK that
 *   produced it, so unwrapping never depends on which version is
 *   "current" at the time.
 *
 * SECURITY CONSTRAINTS (same rules as the local wallet provider):
 *   1. The PIN comes ONLY from an environment variable — never from
 *      postgresql.conf.  GUC pg_vault_tde.pkcs11_pin_env holds the env
 *      var NAME.  The PIN transits a stack buffer and is OPENSSL_cleanse'd
 *      immediately after C_Login.
 *   2. The KEK is created on-token with CKA_EXTRACTABLE=FALSE and can never
 *      be read out; only the DEK transits backend memory (cleansed after use).
 *   3. FORK SAFETY (PKCS#11 §6.6): a forked child inherits an unusable copy
 *      of the parent's Cryptoki state.  Therefore C_Initialize is NEVER
 *      called in the postmaster; each backend attaches lazily on first use,
 *      and a getpid() guard discards state inherited across fork() without
 *      calling into the module.
 *   4. The vendor module is never dlclose()d: many modules keep atexit
 *      handlers / background threads and crash on unload.
 *
 * OWNERSHIP: @SecurityKMS
 */

#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/memutils.h"

#include <openssl/crypto.h>     /* OPENSSL_cleanse */

#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include "src/include/pg_vault_tde_cryptoki.h"
#include "src/kms/pg_vault_tde_kms_provider.h"
#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/include/pg_vault_tde_audit.h"

/* -------------------------------------------------------------------------
 * Constants
 *
 * CKM_AES_KEY_WRAP (RFC 3394) wraps the 32-byte DEK into 40 bytes.
 * CKM_AES_KEY_WRAP_PAD (RFC 5649 fallback) also yields 40 bytes for a
 * 32-byte input.  Both fit comfortably in the callers' 512-byte buffers.
 *
 * Every wrapped_dek blob is prefixed with a 4-byte big-endian KEK version
 * tag identifying which "<key_label>.v<N>" token key produced it (see the
 * KEK ROTATION note below).  This keeps the version self-describing inside
 * the opaque bytea the catalog already stores, with no schema change.
 * -------------------------------------------------------------------------*/
#define PKCS11_KEK_VERSION_LEN  4    /* wrapped_dek: 4-byte BE KEK version tag */
#define PKCS11_WRAP_OVERHEAD    8
#define PKCS11_WRAPPED_DEK_LEN  (PKCS11_KEK_VERSION_LEN + TDE_DEK_LEN + PKCS11_WRAP_OVERHEAD) /* 44 */
#define PKCS11_PIN_MAX          256
#define PKCS11_TOKEN_LABEL_LEN  32   /* CK_TOKEN_INFO.label: space-padded */
#define PKCS11_LABEL_MAX        256  /* object CKA_LABEL working buffers */

/* -------------------------------------------------------------------------
 * Per-backend state
 *
 * A single file-scope instance; no key material is retained here — only
 * module/session handles.  init_pid implements the fork guard: when the
 * current pid differs, every Cryptoki handle below is stale garbage
 * inherited across fork() and is discarded without touching the module.
 * -------------------------------------------------------------------------*/
typedef struct Pkcs11State
{
    void                 *dl_handle;    /* dlopen handle — never dlclose'd */
    CK_FUNCTION_LIST_PTR  fn;           /* module function list */
    pid_t                 init_pid;     /* pid that ran C_Initialize */
    bool                  initialized;  /* C_Initialize done in THIS pid */
    CK_SLOT_ID            slot_id;      /* resolved slot */
    CK_SESSION_HANDLE     session;      /* logged-in session */
    CK_OBJECT_HANDLE      kek_handle;   /* current (highest-version) KEK object */
    uint32                kek_version;  /* its version number ("<label>.v<N>") */
    CK_MECHANISM_TYPE     wrap_mech;    /* CKM_AES_KEY_WRAP or _PAD */
    /* KEK rotation context (armed by prepare_kek_rotation) */
    bool                  rotation_active;
    CK_OBJECT_HANDLE      new_kek_handle;
    uint32                new_kek_version;
} Pkcs11State;

static Pkcs11State pkcs11_state = {
    .session = CK_INVALID_HANDLE,
    .kek_handle = CK_INVALID_HANDLE,
    .new_kek_handle = CK_INVALID_HANDLE,
};


/*-------------------------------------------------------------------------
 * Cross-backend shared state — KEK-version beacon (v1.7+)
 *
 * Unlike Pkcs11State above (per-backend, per-process), this struct lives in
 * shared memory and is visible to every backend in the cluster.  It solves
 * a gap the per-backend cache cannot: after pkcs11_commit_kek_rotation()
 * runs in ONE backend, every OTHER already-connected backend still has its
 * own Pkcs11State.kek_handle/kek_version pinned to the pre-rotation KEK —
 * nothing tells them a new version exists until they reconnect or hit an
 * unrelated session error.
 *
 * The fix is NOT to share the KEK's CK_OBJECT_HANDLE itself: per the PKCS#11
 * specification, an object/session handle is only meaningful within the
 * Cryptoki session that resolved it — a second process reusing another
 * process's raw handle value is not portable (some HSMs happen to keep
 * stable handles across sessions; the spec does not require it, and at
 * least one major HSM vendor has shipped and later fixed exactly this class
 * of bug). Only a plain version NUMBER is shared here; every backend keeps
 * resolving its OWN CK_OBJECT_HANDLE in its OWN session via the existing
 * label-based lookup (pkcs11_find_key_by_label), exactly as it always did.
 *
 * Read/write discipline:
 *   - Written ONLY from pkcs11_commit_kek_rotation() and the one-time
 *     pg_vault_tde_pkcs11_keygen_sql() provisioning path — i.e. only once a
 *     KEK generation is durable AND (for rotation) every existing row has
 *     already been re-wrapped under it.  Never written from
 *     pkcs11_prepare_kek_rotation(): doing so would leak an armed-but-not-
 *     yet-committed rotation to the whole cluster the instant the new key
 *     is generated on the token, before pg_vault_tde_catalog_rewrap_all()
 *     has migrated a single row.
 *   - Read from pkcs11_refresh_kek_if_stale(), called opportunistically
 *     from pkcs11_attach()'s already-attached fast path on every provider
 *     operation, so staleness is bounded by "this backend's next wrap,
 *     unwrap, or rewrap call" — not wall-clock time.
 *   - Writes are monotonic-max (never move the beacon backwards), so a
 *     concurrent keygen/rotate race can only advance it, never regress it.
 * -------------------------------------------------------------------------*/

typedef struct Pkcs11SharedState
{
    LWLock lock;
    uint32 current_kek_version;
} Pkcs11SharedState;

static Pkcs11SharedState *pkcs11_shared = NULL;

/*
 * pg_vault_tde_kms_pkcs11_shmem_request — reserve shmem space for the KEK
 * version beacon.  Called from the shmem_request_hook chain, BEFORE shmem
 * is allocated (see pg_vault_tde.c:pg_vault_tde_shmem_request).
 */
void
pg_vault_tde_kms_pkcs11_shmem_request(void)
{
    RequestAddinShmemSpace(sizeof(Pkcs11SharedState));
}

/*
 * pg_vault_tde_kms_pkcs11_shmem_init — map the KEK version beacon and set up
 * its dynamic-tranche LWLock.  Called from the shmem_startup_hook chain,
 * AFTER shmem is allocated (see pg_vault_tde.c:pg_vault_tde_shmem_startup) —
 * same pattern as pg_vault_tde_kms_shmem_init() for pg_vault_tde_kms_cache.
 */
void
pg_vault_tde_kms_pkcs11_shmem_init(void)
{
    bool found;
    int  tranche_id;

    pkcs11_shared = ShmemInitStruct("pg_vault_tde_pkcs11_shared",
                                    sizeof(Pkcs11SharedState), &found);
    if (!found)
    {
        tranche_id = LWLockNewTrancheId();
        LWLockInitialize(&pkcs11_shared->lock, tranche_id);
        pkcs11_shared->current_kek_version = 0;
    }
    else
        tranche_id = pkcs11_shared->lock.tranche;

    LWLockRegisterTranche(tranche_id, "pg_vault_tde_pkcs11");
}

/*
 * Last CK_RV reported by a wrap/unwrap primitive.  Lets the vtable
 * callbacks retry through a fresh session only when the failure was a
 * session/device loss (see pkcs11_session_lost) rather than a semantic
 * error that would just fail again.
 */
static CK_RV pkcs11_last_rv = CKR_OK;

/* -------------------------------------------------------------------------
 * Forward declarations
 * -------------------------------------------------------------------------*/

/* KMS provider vtable callbacks */
static bool pkcs11_init(void);
static bool pkcs11_wrap_dek(const unsigned char *dek, int dek_len,
                            unsigned char *wrapped_out, int *out_len);
static bool pkcs11_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                              unsigned char *dek_out, int *dek_len);
static bool pkcs11_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                              unsigned char *new_wrapped, int *new_len);
static bool pkcs11_prepare_kek_rotation(void);
static void pkcs11_commit_kek_rotation(void);
static bool pkcs11_health_check(void);
static void pkcs11_shutdown(void);

/* Internal helpers */
static const char *pkcs11_strerror(CK_RV rv);
static bool pkcs11_session_lost(CK_RV rv);
static bool pkcs11_validate_gucs(void);
static bool pkcs11_load_module(void);
static bool pkcs11_find_slot(CK_SLOT_ID *slot_out);
static bool pkcs11_label_matches(const CK_UTF8CHAR *padded, const char *cstr);
static bool pkcs11_find_key_by_label(const char *label,
                                     CK_OBJECT_HANDLE *handle_out);
static bool pkcs11_select_mechanism(void);
static bool pkcs11_attach(bool need_kek);
static bool pkcs11_ensure_session(void);
static void pkcs11_invalidate_session(void);
static void pkcs11_refresh_kek_if_stale(const char *key_label);
static bool pkcs11_generate_kek(const char *label,
                                CK_OBJECT_HANDLE *handle_out);
static void pkcs11_kek_label_for_version(const char *base_label,
                                         uint32 version,
                                         char *out, size_t out_size);
static bool pkcs11_find_current_version(const char *base_label,
                                        uint32 *version_out,
                                        CK_OBJECT_HANDLE *handle_out);
static bool pkcs11_resolve_kek_handle_for_version(uint32 version,
                                                  CK_OBJECT_HANDLE *handle_out);
static void pkcs11_encode_version(unsigned char *buf, uint32 version);
static uint32 pkcs11_decode_version(const unsigned char *buf);
static bool pkcs11_wrap_with_key(CK_OBJECT_HANDLE wrapping_key,
                                 const unsigned char *dek, int dek_len,
                                 unsigned char *wrapped_out, int *out_len);
static bool pkcs11_unwrap_with_key(CK_OBJECT_HANDLE unwrapping_key,
                                   const unsigned char *wrapped,
                                   int wrapped_len,
                                   unsigned char *dek_out, int *dek_len);

/* -------------------------------------------------------------------------
 * Provider registration
 * -------------------------------------------------------------------------*/
static const TdeKmsProvider pkcs11_provider_impl = {
    .name                 = "pkcs11",
    .init                 = pkcs11_init,
    .wrap_dek             = pkcs11_wrap_dek,
    .unwrap_dek           = pkcs11_unwrap_dek,
    .rewrap_dek           = pkcs11_rewrap_dek,
    .prepare_kek_rotation = pkcs11_prepare_kek_rotation,
    .commit_kek_rotation  = pkcs11_commit_kek_rotation,
    .health_check         = pkcs11_health_check,
    .shutdown             = pkcs11_shutdown,
};

const TdeKmsProvider *
pg_vault_tde_kms_pkcs11_provider(void)
{
    return &pkcs11_provider_impl;
}

/* -------------------------------------------------------------------------
 * pkcs11_strerror — human-readable name for the common CK_RV codes
 *
 * Returns a pointer to a static string; the fallback formats the raw value
 * into a static buffer (backends are single-threaded, so this is safe).
 * -------------------------------------------------------------------------*/
static const char *
pkcs11_strerror(CK_RV rv)
{
    static char unknown[32];

    switch (rv)
    {
        case CKR_OK:                            return "CKR_OK";
        case CKR_HOST_MEMORY:                   return "CKR_HOST_MEMORY";
        case CKR_SLOT_ID_INVALID:               return "CKR_SLOT_ID_INVALID";
        case CKR_GENERAL_ERROR:                 return "CKR_GENERAL_ERROR";
        case CKR_FUNCTION_FAILED:               return "CKR_FUNCTION_FAILED";
        case CKR_ARGUMENTS_BAD:                 return "CKR_ARGUMENTS_BAD";
        case CKR_ATTRIBUTE_VALUE_INVALID:       return "CKR_ATTRIBUTE_VALUE_INVALID";
        case CKR_DEVICE_ERROR:                  return "CKR_DEVICE_ERROR";
        case CKR_DEVICE_MEMORY:                 return "CKR_DEVICE_MEMORY";
        case CKR_DEVICE_REMOVED:                return "CKR_DEVICE_REMOVED";
        case CKR_FUNCTION_NOT_SUPPORTED:        return "CKR_FUNCTION_NOT_SUPPORTED";
        case CKR_KEY_HANDLE_INVALID:            return "CKR_KEY_HANDLE_INVALID";
        case CKR_KEY_SIZE_RANGE:                return "CKR_KEY_SIZE_RANGE";
        case CKR_KEY_NOT_WRAPPABLE:             return "CKR_KEY_NOT_WRAPPABLE";
        case CKR_KEY_UNEXTRACTABLE:             return "CKR_KEY_UNEXTRACTABLE";
        case CKR_MECHANISM_INVALID:             return "CKR_MECHANISM_INVALID";
        case CKR_MECHANISM_PARAM_INVALID:       return "CKR_MECHANISM_PARAM_INVALID";
        case CKR_OBJECT_HANDLE_INVALID:         return "CKR_OBJECT_HANDLE_INVALID";
        case CKR_OPERATION_NOT_INITIALIZED:     return "CKR_OPERATION_NOT_INITIALIZED";
        case CKR_PIN_INCORRECT:                 return "CKR_PIN_INCORRECT";
        case CKR_PIN_EXPIRED:                   return "CKR_PIN_EXPIRED";
        case CKR_PIN_LOCKED:                    return "CKR_PIN_LOCKED";
        case CKR_SESSION_CLOSED:                return "CKR_SESSION_CLOSED";
        case CKR_SESSION_HANDLE_INVALID:        return "CKR_SESSION_HANDLE_INVALID";
        case CKR_SESSION_READ_ONLY:             return "CKR_SESSION_READ_ONLY";
        case CKR_TOKEN_NOT_PRESENT:             return "CKR_TOKEN_NOT_PRESENT";
        case CKR_TOKEN_NOT_RECOGNIZED:          return "CKR_TOKEN_NOT_RECOGNIZED";
        case CKR_USER_ALREADY_LOGGED_IN:        return "CKR_USER_ALREADY_LOGGED_IN";
        case CKR_USER_NOT_LOGGED_IN:            return "CKR_USER_NOT_LOGGED_IN";
        case CKR_USER_PIN_NOT_INITIALIZED:      return "CKR_USER_PIN_NOT_INITIALIZED";
        case CKR_WRAPPED_KEY_INVALID:           return "CKR_WRAPPED_KEY_INVALID";
        case CKR_WRAPPED_KEY_LEN_RANGE:         return "CKR_WRAPPED_KEY_LEN_RANGE";
        case CKR_WRAPPING_KEY_HANDLE_INVALID:   return "CKR_WRAPPING_KEY_HANDLE_INVALID";
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
        case CKR_CRYPTOKI_NOT_INITIALIZED:      return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:  return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        case CKR_TEMPLATE_INCOMPLETE:           return "CKR_TEMPLATE_INCOMPLETE";
        case CKR_TEMPLATE_INCONSISTENT:         return "CKR_TEMPLATE_INCONSISTENT";
        default:
            snprintf(unknown, sizeof(unknown), "CKR 0x%08lx",
                     (unsigned long) rv);
            return unknown;
    }
}

/*
 * pkcs11_session_lost — CK_RV values that mean "this session/device state is
 * gone; re-establishing the session may fix it".  Used for the retry-once
 * logic in the wrap/unwrap callbacks.
 */
static bool
pkcs11_session_lost(CK_RV rv)
{
    return rv == CKR_SESSION_HANDLE_INVALID ||
           rv == CKR_SESSION_CLOSED ||
           rv == CKR_DEVICE_ERROR ||
           rv == CKR_DEVICE_REMOVED ||
           rv == CKR_TOKEN_NOT_PRESENT ||
           rv == CKR_USER_NOT_LOGGED_IN ||
           rv == CKR_CRYPTOKI_NOT_INITIALIZED;
}

/* -------------------------------------------------------------------------
 * pkcs11_validate_gucs — cheap configuration sanity checks
 *
 * Called from init() in every process (including the postmaster, where no
 * Cryptoki call is ever made).  Only inspects GUC values and the module
 * file on disk.
 * -------------------------------------------------------------------------*/
static bool
pkcs11_validate_gucs(void)
{
    struct stat st;

    if (pg_vault_tde_pkcs11_library == NULL ||
        pg_vault_tde_pkcs11_library[0] == '\0')
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: pg_vault_tde.pkcs11_library is not set"),
                errhint("Set it to the absolute path of the HSM vendor's "
                        "PKCS#11 module, e.g. /usr/lib/softhsm/libsofthsm2.so."));
        return false;
    }

    if (stat(pg_vault_tde_pkcs11_library, &st) != 0)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: cannot access PKCS#11 module \"%s\": %m",
                       pg_vault_tde_pkcs11_library));
        return false;
    }

    if ((pg_vault_tde_pkcs11_token_label == NULL ||
         pg_vault_tde_pkcs11_token_label[0] == '\0') &&
        pg_vault_tde_pkcs11_slot_id < 0)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: neither pg_vault_tde.pkcs11_token_label "
                       "nor pg_vault_tde.pkcs11_slot_id is set"),
                errhint("Set pkcs11_token_label (preferred) to select the "
                        "token holding the KEK."));
        return false;
    }

    return true;
}

/* -------------------------------------------------------------------------
 * pkcs11_load_module — dlopen the vendor module and fetch its vtable
 *
 * Runs at most once per backend: the handle is cached and never dlclose'd.
 * -------------------------------------------------------------------------*/
static bool
pkcs11_load_module(void)
{
    CK_C_GetFunctionList get_fn_list;
    CK_RV       rv;

    if (pkcs11_state.fn != NULL)
        return true;

    if (pkcs11_state.dl_handle == NULL)
    {
        pkcs11_state.dl_handle = dlopen(pg_vault_tde_pkcs11_library,
                                        RTLD_NOW | RTLD_LOCAL);
        if (pkcs11_state.dl_handle == NULL)
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: could not load PKCS#11 module \"%s\": %s",
                           pg_vault_tde_pkcs11_library, dlerror()));
            return false;
        }
    }

    get_fn_list = (CK_C_GetFunctionList)
        dlsym(pkcs11_state.dl_handle, "C_GetFunctionList");
    if (get_fn_list == NULL)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: \"%s\" does not export C_GetFunctionList: %s",
                       pg_vault_tde_pkcs11_library, dlerror()));
        return false;
    }

    rv = get_fn_list(&pkcs11_state.fn);
    if (rv != CKR_OK || pkcs11_state.fn == NULL)
    {
        pkcs11_state.fn = NULL;
        ereport(WARNING,
                errmsg("pg_vault_tde: C_GetFunctionList failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }

    return true;
}

/*
 * pkcs11_label_matches — compare a C string against a fixed-width,
 * space-padded PKCS#11 label field (CK_TOKEN_INFO.label, 32 bytes, no NUL).
 */
static bool
pkcs11_label_matches(const CK_UTF8CHAR *padded, const char *cstr)
{
    size_t      len = strlen(cstr);
    size_t      i;

    if (len > PKCS11_TOKEN_LABEL_LEN)
        return false;
    if (memcmp(padded, cstr, len) != 0)
        return false;
    for (i = len; i < PKCS11_TOKEN_LABEL_LEN; i++)
    {
        if (padded[i] != ' ')
            return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * pkcs11_find_slot — resolve the slot from token label (preferred) or slot id
 * -------------------------------------------------------------------------*/
static bool
pkcs11_find_slot(CK_SLOT_ID *slot_out)
{
    CK_FUNCTION_LIST_PTR fn = pkcs11_state.fn;
    CK_ULONG    count = 0;
    CK_SLOT_ID *slots;
    CK_ULONG    i;
    CK_RV       rv;
    bool        found = false;

    /* Explicit slot id path (token label unset) */
    if (pg_vault_tde_pkcs11_token_label == NULL ||
        pg_vault_tde_pkcs11_token_label[0] == '\0')
    {
        *slot_out = (CK_SLOT_ID) pg_vault_tde_pkcs11_slot_id;
        return true;
    }

    rv = fn->C_GetSlotList(CK_TRUE, NULL, &count);
    if (rv != CKR_OK)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: C_GetSlotList failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }
    if (count == 0)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: no PKCS#11 token present in any slot"));
        return false;
    }

    slots = (CK_SLOT_ID *) palloc(count * sizeof(CK_SLOT_ID));
    rv = fn->C_GetSlotList(CK_TRUE, slots, &count);
    if (rv != CKR_OK)
    {
        pfree(slots);
        ereport(WARNING,
                errmsg("pg_vault_tde: C_GetSlotList failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }

    for (i = 0; i < count; i++)
    {
        CK_TOKEN_INFO info;

        rv = fn->C_GetTokenInfo(slots[i], &info);
        if (rv != CKR_OK)
            continue;
        if (pkcs11_label_matches(info.label, pg_vault_tde_pkcs11_token_label))
        {
            *slot_out = slots[i];
            found = true;
            break;
        }
    }
    pfree(slots);

    if (!found)
        ereport(WARNING,
                errmsg("pg_vault_tde: no token with label \"%s\" found",
                       pg_vault_tde_pkcs11_token_label),
                errhint("Check pg_vault_tde.pkcs11_token_label and that the "
                        "token is initialized."));
    return found;
}

/* -------------------------------------------------------------------------
 * pkcs11_find_key_by_label — locate an AES secret key object by CKA_LABEL
 *
 * Returns false (without WARNING) when no object matches — callers decide
 * how to report.  Warns when the label is ambiguous and picks the first.
 * -------------------------------------------------------------------------*/
static bool
pkcs11_find_key_by_label(const char *label, CK_OBJECT_HANDLE *handle_out)
{
    CK_FUNCTION_LIST_PTR fn = pkcs11_state.fn;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_LABEL, (void *) label, (CK_ULONG) strlen(label)},
    };
    CK_OBJECT_HANDLE handles[2];
    CK_ULONG    nfound = 0;
    CK_RV       rv;

    rv = fn->C_FindObjectsInit(pkcs11_state.session, tmpl, lengthof(tmpl));
    if (rv != CKR_OK)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: C_FindObjectsInit failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }

    rv = fn->C_FindObjects(pkcs11_state.session, handles, lengthof(handles),
                           &nfound);
    (void) fn->C_FindObjectsFinal(pkcs11_state.session);
    if (rv != CKR_OK)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: C_FindObjects failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }

    if (nfound == 0)
        return false;

    if (nfound > 1)
        ereport(WARNING,
                errmsg("pg_vault_tde: multiple keys labelled \"%s\" on the "
                       "token, using the first one", label),
                errhint("PKCS#11 labels are not unique; keep exactly one KEK "
                        "under this label."));

    *handle_out = handles[0];
    return true;
}

/* -------------------------------------------------------------------------
 * pkcs11_select_mechanism — probe CKM_AES_KEY_WRAP, fall back to _PAD
 * -------------------------------------------------------------------------*/
static bool
pkcs11_select_mechanism(void)
{
    CK_FUNCTION_LIST_PTR fn = pkcs11_state.fn;
    CK_MECHANISM_INFO info;
    CK_RV       rv;

    rv = fn->C_GetMechanismInfo(pkcs11_state.slot_id, CKM_AES_KEY_WRAP, &info);
    if (rv == CKR_OK)
    {
        pkcs11_state.wrap_mech = CKM_AES_KEY_WRAP;
        return true;
    }

    rv = fn->C_GetMechanismInfo(pkcs11_state.slot_id, CKM_AES_KEY_WRAP_PAD,
                                &info);
    if (rv == CKR_OK)
    {
        pkcs11_state.wrap_mech = CKM_AES_KEY_WRAP_PAD;
        ereport(LOG,
                errmsg("pg_vault_tde: token lacks CKM_AES_KEY_WRAP, using "
                       "CKM_AES_KEY_WRAP_PAD"));
        return true;
    }

    ereport(WARNING,
            errmsg("pg_vault_tde: token supports neither CKM_AES_KEY_WRAP "
                   "nor CKM_AES_KEY_WRAP_PAD"),
            errhint("The pkcs11 provider requires an AES key-wrap mechanism."));
    return false;
}

/*
 * pkcs11_invalidate_session — forget session-level handles after a device
 * error or fork.  Deliberately does NOT call into the module: the handles
 * may be inherited garbage (fork) or already dead (device removed).
 */
static void
pkcs11_invalidate_session(void)
{
    pkcs11_state.initialized = false;
    pkcs11_state.session = CK_INVALID_HANDLE;
    pkcs11_state.kek_handle = CK_INVALID_HANDLE;
    pkcs11_state.new_kek_handle = CK_INVALID_HANDLE;
    pkcs11_state.rotation_active = false;
}

/* -------------------------------------------------------------------------
 * pkcs11_attach — attach to the HSM (idempotent, fork-safe)
 *
 * Called at the top of every provider operation.  Fast path: state already
 * valid in this pid.  Slow path: (re)load module, C_Initialize, resolve
 * slot, open session, login with the PIN from the environment, pick the
 * wrap mechanism.
 *
 * need_kek: when true (every provider operation) the KEK is also resolved
 * by CKA_LABEL, with crash recovery for an interrupted rotation commit.
 * pg_vault_tde_pkcs11_keygen() attaches with need_kek=false because its
 * whole purpose is to create the KEK that is not there yet.
 * -------------------------------------------------------------------------*/
static bool
pkcs11_attach(bool need_kek)
{
    const char *key_label = pg_vault_tde_pkcs11_key_label;

    /* Fork guard: discard state inherited from another process. */
    if (pkcs11_state.initialized && pkcs11_state.init_pid != getpid())
        pkcs11_invalidate_session();

    if (!pkcs11_state.initialized ||
        pkcs11_state.session == CK_INVALID_HANDLE)
    {
        CK_FUNCTION_LIST_PTR fn;
        CK_C_INITIALIZE_ARGS init_args;
        const char *pin_env_name;
        const char *pin_env_value;
        char        pin[PKCS11_PIN_MAX];
        size_t      pin_len;
        CK_RV       rv;

        /* Cryptoki must never be initialized in the postmaster (fork rules) */
        if (MyDatabaseId == InvalidOid)
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: pkcs11 provider cannot attach to "
                           "the HSM outside a backend"));
            return false;
        }

        if (!pkcs11_validate_gucs())
            return false;
        if (!pkcs11_load_module())
            return false;

        fn = pkcs11_state.fn;

        memset(&init_args, 0, sizeof(init_args));
        init_args.flags = CKF_OS_LOCKING_OK;

        rv = fn->C_Initialize(&init_args);
        if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: C_Initialize failed: %s",
                           pkcs11_strerror(rv)));
            return false;
        }

        if (!pkcs11_find_slot(&pkcs11_state.slot_id))
            return false;

        /*
         * A read/write session: wrap/unwrap only need R/O, but keygen and
         * KEK rotation create token objects, and reusing one session keeps
         * the login state in one place.
         */
        rv = fn->C_OpenSession(pkcs11_state.slot_id,
                               CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL, NULL, &pkcs11_state.session);
        if (rv != CKR_OK)
        {
            pkcs11_state.session = CK_INVALID_HANDLE;
            ereport(WARNING,
                    errmsg("pg_vault_tde: C_OpenSession failed: %s",
                           pkcs11_strerror(rv)));
            return false;
        }

        /* PIN from environment — the GUC holds the env var NAME, never the PIN */
        pin_env_name = (pg_vault_tde_pkcs11_pin_env &&
                        pg_vault_tde_pkcs11_pin_env[0] != '\0')
            ? pg_vault_tde_pkcs11_pin_env : "PG_TDE_PKCS11_PIN";

        pin_env_value = getenv(pin_env_name);

        if (pin_env_value == NULL || pin_env_value[0] == '\0')
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: PKCS#11 PIN env var \"%s\" not set",
                           pin_env_name),
                    errhint("Export the token user PIN in the server "
                            "environment before starting PostgreSQL."));
            tde_audit(KMS_AUTH_FAILURE, NULL, false);
            fn->C_CloseSession(pkcs11_state.session);
            pkcs11_state.session = CK_INVALID_HANDLE;      
            return false;
        }

        pin_len = strlen(pin_env_value);
        if (pin_len >= sizeof(pin))
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: PKCS#11 PIN longer than %d bytes",
                           PKCS11_PIN_MAX - 1));
            tde_audit(KMS_AUTH_FAILURE, NULL, false);
            fn->C_CloseSession(pkcs11_state.session);
            pkcs11_state.session = CK_INVALID_HANDLE;                   
            return false;
        }
        memcpy(pin, pin_env_value, pin_len + 1);

        rv = fn->C_Login(pkcs11_state.session, CKU_USER,
                         (CK_UTF8CHAR *) pin, (CK_ULONG) pin_len);
        OPENSSL_cleanse(pin, sizeof(pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: C_Login failed: %s",
                           pkcs11_strerror(rv)));
            tde_audit(KMS_AUTH_FAILURE, NULL, false);
            fn->C_CloseSession(pkcs11_state.session);
            pkcs11_state.session = CK_INVALID_HANDLE;                   
            return false;
        }

        if (!pkcs11_select_mechanism()){
            ereport(WARNING,
                    errmsg("pg_vault_tde: pkcs11 select mechanism failed"));            
            fn->C_CloseSession(pkcs11_state.session);
            pkcs11_state.session = CK_INVALID_HANDLE;                
            return false;
        }    

        pkcs11_state.initialized = true;
        pkcs11_state.init_pid = getpid();

        tde_audit(KMS_AUTH_SUCCESS, NULL, true);
        ereport(DEBUG1,
                errmsg("pg_vault_tde: pkcs11 session established (slot %lu)",
                       (unsigned long) pkcs11_state.slot_id));
    }

    if (!need_kek)
        return true;

    if (pkcs11_state.kek_handle != CK_INVALID_HANDLE)
    {
        /* Already resolved in this backend — pick up a committed rotation
         * lazily, on this call, instead of staying pinned to a stale KEK. */
        pkcs11_refresh_kek_if_stale(key_label);
        return true;
    }

    if (key_label == NULL || key_label[0] == '\0')
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: pg_vault_tde.pkcs11_key_label is not set"));
        return false;
    }

    if (!pkcs11_find_current_version(key_label, &pkcs11_state.kek_version,
                                     &pkcs11_state.kek_handle))
    {
        pkcs11_state.kek_handle = CK_INVALID_HANDLE;
        ereport(WARNING,
                errmsg("pg_vault_tde: no KEK found under \"%s.v*\" on token",
                       key_label),
                errhint("Run pg_vault_tde_pkcs11_keygen() once, or create an "
                        "AES-256 key labelled \"%s.v1\" with CKA_WRAP/"
                        "CKA_UNWRAP with the HSM tooling.", key_label));
        return false;
    }

    return true;
}

/*
 * pkcs11_ensure_session — the provider operations' entry point: full attach
 * including KEK resolution.
 */
static bool
pkcs11_ensure_session(void)
{
    return pkcs11_attach(true);
}

/* -------------------------------------------------------------------------
 * pkcs11_wrap_with_key — C_WrapKey the DEK under the given token key
 *
 * The DEK is imported as a transient SESSION object (CKA_TOKEN=FALSE) so
 * C_WrapKey can reference it; the object is destroyed on every exit path.
 * -------------------------------------------------------------------------*/
static bool
pkcs11_wrap_with_key(CK_OBJECT_HANDLE wrapping_key,
                     const unsigned char *dek, int dek_len,
                     unsigned char *wrapped_out, int *out_len)
{
    CK_FUNCTION_LIST_PTR fn = pkcs11_state.fn;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_BBOOL    ck_false = CK_FALSE;
    CK_BBOOL    ck_true = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &ck_false, sizeof(ck_false)},
        {CKA_SENSITIVE, &ck_false, sizeof(ck_false)},
        {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
        {CKA_VALUE, (void *) dek, (CK_ULONG) dek_len},
    };
    CK_MECHANISM mech = {0, NULL, 0};
    CK_OBJECT_HANDLE dek_obj = CK_INVALID_HANDLE;
    CK_ULONG    wrapped_len;
    CK_RV       rv;
    bool        ok = false;

    mech.mechanism = pkcs11_state.wrap_mech;

    rv = fn->C_CreateObject(pkcs11_state.session, tmpl, lengthof(tmpl),
                            &dek_obj);
    if (rv != CKR_OK)
    {
        pkcs11_last_rv = rv;
        ereport(WARNING,
                errmsg("pg_vault_tde: C_CreateObject for DEK failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }

    wrapped_len = (CK_ULONG) *out_len;   /* in: capacity, out: bytes written */
    rv = fn->C_WrapKey(pkcs11_state.session, &mech, wrapping_key, dek_obj,
                       wrapped_out, &wrapped_len);
    if (rv != CKR_OK)
    {
        pkcs11_last_rv = rv;
        ereport(WARNING,
                errmsg("pg_vault_tde: C_WrapKey failed: %s",
                       pkcs11_strerror(rv)));
        goto cleanup;
    }

    *out_len = (int) wrapped_len;
    ok = true;

cleanup:
    (void) fn->C_DestroyObject(pkcs11_state.session, dek_obj);
    return ok;
}

/* -------------------------------------------------------------------------
 * pkcs11_unwrap_with_key — C_UnwrapKey and extract the plaintext DEK
 *
 * The unwrapped key materializes as a transient session object marked
 * extractable/non-sensitive so its CKA_VALUE can be read back into the
 * caller's buffer; the object is destroyed and the intermediate attribute
 * buffer cleansed on every exit path.
 * -------------------------------------------------------------------------*/
static bool
pkcs11_unwrap_with_key(CK_OBJECT_HANDLE unwrapping_key,
                       const unsigned char *wrapped, int wrapped_len,
                       unsigned char *dek_out, int *dek_len)
{
    CK_FUNCTION_LIST_PTR fn = pkcs11_state.fn;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_BBOOL    ck_false = CK_FALSE;
    CK_BBOOL    ck_true = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &ck_false, sizeof(ck_false)},
        {CKA_SENSITIVE, &ck_false, sizeof(ck_false)},
        {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
    };
    CK_MECHANISM mech = {0, NULL, 0};
    CK_OBJECT_HANDLE dek_obj = CK_INVALID_HANDLE;
    unsigned char value[TDE_DEK_LEN];
    CK_ATTRIBUTE value_attr = {CKA_VALUE, value, sizeof(value)};
    CK_RV       rv;
    bool        ok = false;

    mech.mechanism = pkcs11_state.wrap_mech;

    rv = fn->C_UnwrapKey(pkcs11_state.session, &mech, unwrapping_key,
                         (CK_BYTE *) wrapped, (CK_ULONG) wrapped_len,
                         tmpl, lengthof(tmpl), &dek_obj);
    if (rv != CKR_OK)
    {
        pkcs11_last_rv = rv;
        ereport(WARNING,
                errmsg("pg_vault_tde: C_UnwrapKey failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }

    rv = fn->C_GetAttributeValue(pkcs11_state.session, dek_obj,
                                 &value_attr, 1);
    if (rv != CKR_OK)
    {
        pkcs11_last_rv = rv;
        ereport(WARNING,
                errmsg("pg_vault_tde: C_GetAttributeValue(CKA_VALUE) failed: %s",
                       pkcs11_strerror(rv)));
        goto cleanup;
    }

    if (value_attr.ulValueLen != TDE_DEK_LEN)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: unwrapped DEK has unexpected length %lu "
                       "(expected %d)",
                       (unsigned long) value_attr.ulValueLen, TDE_DEK_LEN));
        goto cleanup;
    }

    memcpy(dek_out, value, TDE_DEK_LEN);
    *dek_len = TDE_DEK_LEN;
    ok = true;

cleanup:
    OPENSSL_cleanse(value, sizeof(value));
    (void) fn->C_DestroyObject(pkcs11_state.session, dek_obj);
    return ok;
}

/*
 * pkcs11_kek_label_for_version — build the immutable "<base_label>.v<N>"
 * label for a given KEK generation.
 */
static void
pkcs11_kek_label_for_version(const char *base_label, uint32 version,
                             char *out, size_t out_size)
{
    snprintf(out, out_size, "%s.v%u", base_label, version);
}

/*
 * pkcs11_encode_version / pkcs11_decode_version — 4-byte big-endian KEK
 * version tag prefixed to every wrapped_dek blob.  Manual pack/unpack to
 * avoid any endian.h portability assumption.
 */
static void
pkcs11_encode_version(unsigned char *buf, uint32 version)
{
    buf[0] = (unsigned char) (version >> 24);
    buf[1] = (unsigned char) (version >> 16);
    buf[2] = (unsigned char) (version >> 8);
    buf[3] = (unsigned char) version;
}

static uint32
pkcs11_decode_version(const unsigned char *buf)
{
    return ((uint32) buf[0] << 24) | ((uint32) buf[1] << 16) |
           ((uint32) buf[2] << 8) | (uint32) buf[3];
}

/* -------------------------------------------------------------------------
 * pkcs11_generate_kek — create an AES-256 wrap/unwrap key on the token
 *
 * The key is a persistent token object (CKA_TOKEN=TRUE) that can never be
 * read out (CKA_SENSITIVE=TRUE, CKA_EXTRACTABLE=FALSE) and requires a
 * logged-in session to use (CKA_PRIVATE=TRUE).
 * -------------------------------------------------------------------------*/
static bool
pkcs11_generate_kek(const char *label, CK_OBJECT_HANDLE *handle_out)
{
    CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL, 0};
    CK_ULONG    value_len = TDE_DEK_LEN;
    CK_BBOOL    ck_true = CK_TRUE;
    CK_BBOOL    ck_false = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
        {CKA_WRAP, &ck_true, sizeof(ck_true)},
        {CKA_UNWRAP, &ck_true, sizeof(ck_true)},
        {CKA_VALUE_LEN, &value_len, sizeof(value_len)},
        {CKA_LABEL, (void *) label, (CK_ULONG) strlen(label)},
    };
    CK_RV       rv;

    rv = pkcs11_state.fn->C_GenerateKey(pkcs11_state.session, &mech,
                                        tmpl, lengthof(tmpl), handle_out);
    if (rv != CKR_OK)
    {
        pkcs11_last_rv = rv;
        ereport(WARNING,
                errmsg("pg_vault_tde: C_GenerateKey failed: %s",
                       pkcs11_strerror(rv)));
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * pkcs11_find_current_version — highest "<base_label>.v<N>" on the token
 *
 * KEK generations are never renamed or destroyed (see the KEK ROTATION
 * note above pkcs11_prepare_kek_rotation): "current" is simply whichever
 * version number is highest among the immutable per-generation keys found
 * on the token.  PKCS#11 templates only match CKA_LABEL exactly, so this
 * enumerates the token's AES secret keys and compares labels by prefix.
 * -------------------------------------------------------------------------*/
static bool
pkcs11_find_current_version(const char *base_label, uint32 *version_out,
                            CK_OBJECT_HANDLE *handle_out)
{
    CK_FUNCTION_LIST_PTR fn = pkcs11_state.fn;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };
    char        prefix[PKCS11_LABEL_MAX];
    size_t      prefix_len;
    CK_OBJECT_HANDLE best = CK_INVALID_HANDLE;
    uint32      best_version = 0;
    CK_RV       rv;

    snprintf(prefix, sizeof(prefix), "%s.v", base_label);
    prefix_len = strlen(prefix);

    rv = fn->C_FindObjectsInit(pkcs11_state.session, tmpl, lengthof(tmpl));
    if (rv != CKR_OK)
        return false;

    for (;;)
    {
        CK_OBJECT_HANDLE batch[16];
        CK_ULONG    nfound = 0;
        CK_ULONG    i;

        rv = fn->C_FindObjects(pkcs11_state.session, batch, lengthof(batch),
                               &nfound);
        if (rv != CKR_OK || nfound == 0)
            break;

        for (i = 0; i < nfound; i++)
        {
            char        label[PKCS11_LABEL_MAX];
            CK_ATTRIBUTE label_attr = {CKA_LABEL, label, sizeof(label) - 1};
            unsigned long version;
            char       *endptr;

            if (fn->C_GetAttributeValue(pkcs11_state.session, batch[i],
                                        &label_attr, 1) != CKR_OK)
                continue;
            if (label_attr.ulValueLen == CK_UNAVAILABLE_INFORMATION ||
                label_attr.ulValueLen >= sizeof(label))
                continue;
            label[label_attr.ulValueLen] = '\0';

            if (strncmp(label, prefix, prefix_len) != 0)
                continue;

            version = strtoul(label + prefix_len, &endptr, 10);
            if (*endptr != '\0' || version == 0)
                continue;          /* not a bare "<prefix><digits>" label */

            if (best == CK_INVALID_HANDLE || version > best_version)
            {
                best = batch[i];
                best_version = (uint32) version;
            }
        }

        if (nfound < lengthof(batch))
            break;
    }
    (void) fn->C_FindObjectsFinal(pkcs11_state.session);

    if (best == CK_INVALID_HANDLE)
        return false;

    *handle_out = best;
    *version_out = best_version;
    return true;
}

/*
 * pkcs11_resolve_kek_handle_for_version — find the token key object for a
 * specific KEK version, tagged inside a wrapped_dek blob.
 *
 * Fast path: matches the cached current or (if a rotation is armed) the
 * cached new KEK handle.  Falls back to an explicit label lookup — needed
 * whenever the row predates the cached handles, e.g. right after restart
 * before pkcs11_find_current_version() has populated the cache, or when
 * unwrapping a row from an older generation than the one currently active.
 */
static bool
pkcs11_resolve_kek_handle_for_version(uint32 version,
                                      CK_OBJECT_HANDLE *handle_out)
{
    char        label[PKCS11_LABEL_MAX];

    if (pkcs11_state.kek_handle != CK_INVALID_HANDLE &&
        version == pkcs11_state.kek_version)
    {
        *handle_out = pkcs11_state.kek_handle;
        return true;
    }

    if (pkcs11_state.rotation_active &&
        pkcs11_state.new_kek_handle != CK_INVALID_HANDLE &&
        version == pkcs11_state.new_kek_version)
    {
        *handle_out = pkcs11_state.new_kek_handle;
        return true;
    }

    pkcs11_kek_label_for_version(pg_vault_tde_pkcs11_key_label, version,
                                 label, sizeof(label));
    if (pkcs11_find_key_by_label(label, handle_out))
        return true;

    ereport(WARNING,
            errmsg("pg_vault_tde: KEK version %u (\"%s\") not found on token",
                   version, label));
    return false;
}

/* -------------------------------------------------------------------------
 * Vtable callbacks
 * -------------------------------------------------------------------------*/

/*
 * pkcs11_init — configuration validation + best-effort eager attach
 *
 * In the postmaster (config load / shmem startup) this only validates the
 * GUCs: C_Initialize must never run before fork().  In a backend it also
 * attempts to establish the session so misconfiguration surfaces at connect
 * time; failure is a WARNING, not an ERROR — every operation retries via
 * pkcs11_ensure_session() (same degraded-mode semantics as the local
 * wallet provider).
 */
static bool
pkcs11_init(void)
{
    if (!pkcs11_validate_gucs())
        return false;

    if (MyDatabaseId == InvalidOid)
    {
        ereport(LOG,
                errmsg("pg_vault_tde: pkcs11 provider registered, HSM attach "
                       "deferred to backend first use"));
        return true;
    }

    return pkcs11_ensure_session();
}

/*
 * pkcs11_wrap_dek — wrap a DEK under the current KEK.
 *
 * *out_len is bidirectional: capacity in, bytes written out (see
 * kms.instructions.md).  The first PKCS11_KEK_VERSION_LEN bytes of the
 * output are the current KEK's version tag; the RFC 3394 blob follows.
 * Retries once through a fresh session when the module reports the
 * session/device state lost.
 */
static bool
pkcs11_wrap_dek(const unsigned char *dek, int dek_len,
                unsigned char *wrapped_out, int *out_len)
{
    int         capacity = *out_len;
    int         wrap_len;

    Assert(dek_len == TDE_DEK_LEN);

    if (capacity < PKCS11_WRAPPED_DEK_LEN)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wrapped-DEK buffer too small (%d bytes, "
                       "need %d)", capacity, PKCS11_WRAPPED_DEK_LEN));
        return false;
    }

    if (!pkcs11_ensure_session())
        return false;

    wrap_len = capacity - PKCS11_KEK_VERSION_LEN;
    if (pkcs11_wrap_with_key(pkcs11_state.kek_handle, dek, dek_len,
                             wrapped_out + PKCS11_KEK_VERSION_LEN, &wrap_len))
    {
        pkcs11_encode_version(wrapped_out, pkcs11_state.kek_version);
        *out_len = wrap_len + PKCS11_KEK_VERSION_LEN;
        return true;
    }

    /*
     * One retry through a fresh session, but only when the failure was a
     * session/device loss — a semantic error would just fail again.
     */
    if (!pkcs11_session_lost(pkcs11_last_rv))
        return false;
    pkcs11_invalidate_session();
    if (!pkcs11_ensure_session())
        return false;
    wrap_len = capacity - PKCS11_KEK_VERSION_LEN;
    if (!pkcs11_wrap_with_key(pkcs11_state.kek_handle, dek, dek_len,
                             wrapped_out + PKCS11_KEK_VERSION_LEN, &wrap_len))
        return false;
    pkcs11_encode_version(wrapped_out, pkcs11_state.kek_version);
    *out_len = wrap_len + PKCS11_KEK_VERSION_LEN;
    return true;
}

/*
 * pkcs11_unwrap_dek — unwrap a DEK with the KEK version tagged in the blob.
 *
 * *dek_len is capacity on input (must be >= TDE_DEK_LEN) and is set to the
 * actual DEK length (always TDE_DEK_LEN) on success.
 */
static bool
pkcs11_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                  unsigned char *dek_out, int *dek_len)
{
    uint32      version;
    CK_OBJECT_HANDLE unwrap_key;

    if (*dek_len < TDE_DEK_LEN)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: DEK output buffer too small (%d bytes, "
                       "need %d)", *dek_len, TDE_DEK_LEN));
        return false;
    }

    if (wrapped_len <= PKCS11_KEK_VERSION_LEN)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wrapped DEK too short (%d bytes)",
                       wrapped_len));
        return false;
    }

    version = pkcs11_decode_version(wrapped);
    wrapped += PKCS11_KEK_VERSION_LEN;
    wrapped_len -= PKCS11_KEK_VERSION_LEN;

    if (!pkcs11_ensure_session())
        return false;

    if (!pkcs11_resolve_kek_handle_for_version(version, &unwrap_key))
        return false;

    if (pkcs11_unwrap_with_key(unwrap_key, wrapped, wrapped_len,
                               dek_out, dek_len))
        return true;

    /* Retry once only on session/device loss (see pkcs11_wrap_dek). */
    if (!pkcs11_session_lost(pkcs11_last_rv))
        return false;
    pkcs11_invalidate_session();
    if (!pkcs11_ensure_session())
        return false;
    if (!pkcs11_resolve_kek_handle_for_version(version, &unwrap_key))
        return false;
    return pkcs11_unwrap_with_key(unwrap_key, wrapped, wrapped_len,
                                  dek_out, dek_len);
}

/*
 * pkcs11_rewrap_dek — unwrap with the KEK version tagged in old_wrapped,
 * re-wrap with the new KEK when a rotation is armed, with the current KEK
 * otherwise.
 *
 * Same structure as local_rewrap_dek: the plaintext DEK only lives in a
 * stack buffer that is cleansed on every exit path.
 */
static bool
pkcs11_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                  unsigned char *new_wrapped, int *new_len)
{
    unsigned char dek_temp[TDE_DEK_LEN];
    int         dek_temp_len = sizeof(dek_temp);
    uint32      old_version;
    CK_OBJECT_HANDLE unwrap_key;
    CK_OBJECT_HANDLE wrap_key;
    uint32      wrap_version;
    int         wrap_capacity;
    bool        ok = false;

    if (old_len <= PKCS11_KEK_VERSION_LEN)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wrapped DEK too short (%d bytes)",
                       old_len));
        return false;
    }

    old_version = pkcs11_decode_version(old_wrapped);
    old_wrapped += PKCS11_KEK_VERSION_LEN;
    old_len -= PKCS11_KEK_VERSION_LEN;

    if (!pkcs11_ensure_session())
        return false;

    if (!pkcs11_resolve_kek_handle_for_version(old_version, &unwrap_key))
        return false;

    if (!pkcs11_unwrap_with_key(unwrap_key, old_wrapped, old_len,
                                dek_temp, &dek_temp_len)) {

        /* Retry once on session/device loss */
        if (!pkcs11_session_lost(pkcs11_last_rv))
            goto cleanup;
        /* we invalidate the session */    
        pkcs11_invalidate_session();
        /* we verify the session */ 
        if (!pkcs11_ensure_session())
            goto cleanup;
        /* we try to get the kek */
        if (!pkcs11_resolve_kek_handle_for_version(old_version, &unwrap_key))
            goto cleanup;
        /* we unwrap the key */
        if (!pkcs11_unwrap_with_key(unwrap_key, old_wrapped, old_len,
                                    dek_temp, &dek_temp_len))
            goto cleanup;            
        }
        

    if (pkcs11_state.rotation_active)
    {
        wrap_key = pkcs11_state.new_kek_handle;
        wrap_version = pkcs11_state.new_kek_version;
    }
    else
    {
        wrap_key = pkcs11_state.kek_handle;
        wrap_version = pkcs11_state.kek_version;
    }

    wrap_capacity = *new_len - PKCS11_KEK_VERSION_LEN;
    if (!pkcs11_wrap_with_key(wrap_key, dek_temp, dek_temp_len,
                              new_wrapped + PKCS11_KEK_VERSION_LEN,
                              &wrap_capacity))
    {
        if (!pkcs11_session_lost(pkcs11_last_rv))
            goto cleanup;
        pkcs11_invalidate_session();
        if (!pkcs11_ensure_session())
            goto cleanup;

        if (pkcs11_state.rotation_active)
        {
            wrap_key = pkcs11_state.new_kek_handle;
            wrap_version = pkcs11_state.new_kek_version;
        }
        else
        {
            wrap_key = pkcs11_state.kek_handle;
            wrap_version = pkcs11_state.kek_version;
        }

        wrap_capacity = *new_len - PKCS11_KEK_VERSION_LEN;
        if (!pkcs11_wrap_with_key(wrap_key, dek_temp, dek_temp_len,
                                  new_wrapped + PKCS11_KEK_VERSION_LEN,
                                  &wrap_capacity))
            goto cleanup;
    }

    pkcs11_encode_version(new_wrapped, wrap_version);
    *new_len = wrap_capacity + PKCS11_KEK_VERSION_LEN;
    ok = true;

cleanup:
    OPENSSL_cleanse(dek_temp, sizeof(dek_temp));
    return ok;
}

/*
 * KEK ROTATION — immutable, versioned KEKs
 * -----------------------------------------
 * Each KEK generation lives forever under its own immutable token label
 * "<key_label>.v<N>" (N monotonically increasing): rotation never renames
 * or destroys a key.  "Current" is simply the highest N present on the
 * token (pkcs11_find_current_version()), and every wrapped_dek blob embeds
 * the exact version that produced it (PKCS11_KEK_VERSION_LEN prefix), so
 * unwrap always finds the right key regardless of what "current" is at the
 * time — including across a crash at any point of a rotation.  There is no
 * token-side promotion step left to interrupt: commit_kek_rotation() only
 * updates in-backend cache state once pg_vault_tde_catalog_rewrap_all()
 * has re-wrapped every row (and, if that fails, PG_CATCH unwinds without
 * ever calling commit — the new key sits unused under "<label>.v<N+1>",
 * harmless, and the next rotation attempt simply reuses or supersedes it).
 */

/*
 * pkcs11_prepare_kek_rotation — arm a KEK rotation.
 *
 * Generates a fresh AES-256 KEK on the token under the next version label
 * "<key_label>.v<current+1>".  While the rotation is armed, rewrap_dek()
 * unwraps with the KEK tagged in each row and re-wraps under the new one;
 * pg_vault_tde_catalog_rewrap_all() then calls commit_kek_rotation() to
 * make the new version the cached current one.
 */
static bool
pkcs11_prepare_kek_rotation(void)
{
    const char *label = pg_vault_tde_pkcs11_key_label;
    char        new_label[PKCS11_LABEL_MAX];
    uint32      new_version;
    CK_OBJECT_HANDLE existing;

    if (!pkcs11_ensure_session())
        return false;

    new_version = pkcs11_state.kek_version + 1;
    pkcs11_kek_label_for_version(label, new_version, new_label,
                                 sizeof(new_label));

    if (pkcs11_find_key_by_label(new_label, &existing))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: a key labelled \"%s\" already exists — "
                       "KEK rotation already in progress or was interrupted",
                       new_label),
                errhint("Remove the stale key with the HSM tooling, or just "
                        "retry: a fresh rotation will pick the next free "
                        "version."));
        return false;
    }

    if (!pkcs11_generate_kek(new_label, &pkcs11_state.new_kek_handle))
    {
        pkcs11_state.new_kek_handle = CK_INVALID_HANDLE;
        return false;
    }

    pkcs11_state.new_kek_version = new_version;
    pkcs11_state.rotation_active = true;
    ereport(LOG,
            errmsg("pg_vault_tde: pkcs11 KEK rotation armed (new key \"%s\")",
                   new_label));
    return true;
}

/*
 * pkcs11_commit_kek_rotation — make the armed KEK version current.
 *
 * Purely an in-backend cache update: the new key is already durably on the
 * token (created in prepare_kek_rotation) and every rewrapped row already
 * carries its version tag, so there is nothing left to make durable here.
 */
static void
pkcs11_commit_kek_rotation(void)
{
    if (!pkcs11_state.rotation_active ||
        pkcs11_state.new_kek_handle == CK_INVALID_HANDLE)
        return;                 /* nothing armed */

    pkcs11_state.kek_handle = pkcs11_state.new_kek_handle;
    pkcs11_state.kek_version = pkcs11_state.new_kek_version;
    pkcs11_state.new_kek_handle = CK_INVALID_HANDLE;
    pkcs11_state.rotation_active = false;

    if (pkcs11_shared != NULL)
    {
        LWLockAcquire(&pkcs11_shared->lock, LW_EXCLUSIVE);
        if (pkcs11_state.kek_version > pkcs11_shared->current_kek_version)
            pkcs11_shared->current_kek_version = pkcs11_state.kek_version;
        LWLockRelease(&pkcs11_shared->lock);
    }

    tde_audit(KMS_KEK_ROTATE, NULL, true);
    ereport(LOG,
            errmsg("pg_vault_tde: pkcs11 KEK rotated to version %u",
                   pkcs11_state.kek_version));
}

/*
 * pkcs11_refresh_kek_if_stale — pick up a committed KEK rotation lazily.
 *
 * Called from pkcs11_attach()'s already-attached fast path on every
 * provider operation (wrap/unwrap/rewrap), i.e. every time this backend
 * already has a cached kek_handle and would otherwise never look again.
 *
 * Cheap in the common case: one LWLockAcquire(LW_SHARED), a uint32 read, and
 * a comparison — no Cryptoki call, no allocation. Only when the shared
 * beacon (see the Pkcs11SharedState comment above) reports a version newer
 * than this backend's own does it pay for a label-based lookup
 * (pkcs11_find_key_by_label(), ~3 Cryptoki calls: C_FindObjectsInit /
 * C_FindObjects / C_FindObjectsFinal), never the full-token enumeration
 * scan (pkcs11_find_current_version()).
 *
 * Fails open: if the lookup does not find the announced version (e.g. a
 * transient session hiccup), this backend simply keeps its current
 * kek_handle/kek_version — still valid, since KEK generations are immutable
 * and never destroyed — and retries the same check on its next call.
 * kek_handle and kek_version are always updated together, never one without
 * the other, so a partial/inconsistent pair can never be observed by the
 * rest of this backend.
 */
static void
pkcs11_refresh_kek_if_stale(const char *key_label)
{
    uint32 shared_version;
    char   label[PKCS11_LABEL_MAX];
    CK_OBJECT_HANDLE new_handle;

    if (pkcs11_shared == NULL)
        return;                              /* shmem not mapped (should not happen once attached) */

    LWLockAcquire(&pkcs11_shared->lock, LW_SHARED);
    shared_version = pkcs11_shared->current_kek_version;
    LWLockRelease(&pkcs11_shared->lock);

    if (shared_version == 0 || shared_version <= pkcs11_state.kek_version)
        return;                              /* nothing published yet, or already current */

    pkcs11_kek_label_for_version(key_label, shared_version, label, sizeof(label));
    if (pkcs11_find_key_by_label(label, &new_handle))
    {
        pkcs11_state.kek_handle = new_handle;
        pkcs11_state.kek_version = shared_version;
        ereport(LOG,
                errmsg("pg_vault_tde: pkcs11 backend picked up KEK rotation, "
                       "now using version %u", shared_version));
    }
    else
        ereport(WARNING,
                errmsg("pg_vault_tde: KEK version %u announced but not found "
                       "on token, keeping version %u", shared_version,
                       pkcs11_state.kek_version));
}

/*
 * pkcs11_health_check — cheap when the session is live, otherwise a full
 * (lazy) attach attempt.
 */
static bool
pkcs11_health_check(void)
{
    if (pkcs11_state.initialized &&
        pkcs11_state.init_pid == getpid() &&
        pkcs11_state.session != CK_INVALID_HANDLE)
    {
        CK_SESSION_INFO info;
        CK_RV       rv;

        rv = pkcs11_state.fn->C_GetSessionInfo(pkcs11_state.session, &info);
        if (rv == CKR_OK)
            return true;
        pkcs11_invalidate_session();
    }

    return pkcs11_ensure_session();
}

/*
 * pkcs11_shutdown — orderly detach.  Only touches the module from the pid
 * that initialized it (handles inherited across fork are not ours to
 * close).  The dlopen handle is deliberately retained.
 */
static void
pkcs11_shutdown(void)
{
    CK_FUNCTION_LIST_PTR fn = pkcs11_state.fn;

    if (pkcs11_state.initialized &&
        pkcs11_state.init_pid == getpid() &&
        fn != NULL)
    {
        if (pkcs11_state.session != CK_INVALID_HANDLE)
        {
            (void) fn->C_Logout(pkcs11_state.session);
            (void) fn->C_CloseSession(pkcs11_state.session);
        }
        (void) fn->C_Finalize(NULL);
    }

    pkcs11_invalidate_session();
}

/* -------------------------------------------------------------------------
 * SQL-callable functions
 * -------------------------------------------------------------------------*/

PG_FUNCTION_INFO_V1(pg_vault_tde_pkcs11_keygen_sql);

/*
 * pg_vault_tde_pkcs11_keygen() — one-time KEK provisioning.
 *
 * Generates the AES-256 KEK on the token under "<pkcs11_key_label>.v1" (the
 * first, immutable KEK generation — see the KEK ROTATION note above
 * pkcs11_prepare_kek_rotation).  Refuses to overwrite an existing KEK
 * version: HSM key provisioning is a deliberate admin act (same philosophy
 * as pg_vault_tde_wallet_init for the local wallet).  Superuser-only via
 * REVOKE in the extension script.
 */
Datum
pg_vault_tde_pkcs11_keygen_sql(PG_FUNCTION_ARGS)
{
    const char *label = pg_vault_tde_pkcs11_key_label;
    char        v1_label[PKCS11_LABEL_MAX];
    uint32      existing_version;
    CK_OBJECT_HANDLE existing;
    CK_OBJECT_HANDLE kek;

    if (tde_kms_provider() == NULL ||
        strcmp(tde_active_kms_provider->name, "pkcs11") != 0)
        ereport(ERROR,
                errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pg_vault_tde_pkcs11_keygen() requires "
                       "pg_vault_tde.kms_provider = 'pkcs11'"));

    if (label == NULL || label[0] == '\0')
        ereport(ERROR,
                errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                errmsg("pg_vault_tde.pkcs11_key_label is not set"));

    if (!pkcs11_attach(false))
        ereport(ERROR,
                errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                errmsg("pg_vault_tde: could not attach to the PKCS#11 token"),
                errhint("See the preceding WARNING messages for the cause."));

    if (pkcs11_find_current_version(label, &existing_version, &existing))
        ereport(ERROR,
                errcode(ERRCODE_DUPLICATE_OBJECT),
                errmsg("pg_vault_tde: a KEK already exists on the token "
                       "under \"%s.v%u\"", label, existing_version),
                errhint("Use pg_vault_tde_rotate_kek() to rotate the KEK, "
                        "or remove the key with the HSM tooling first."));

    pkcs11_kek_label_for_version(label, 1, v1_label, sizeof(v1_label));
    if (!pkcs11_generate_kek(v1_label, &kek))
        ereport(ERROR,
                errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                errmsg("pg_vault_tde: KEK generation on the token failed"));

    pkcs11_state.kek_handle = kek;
    pkcs11_state.kek_version = 1;

    if (pkcs11_shared != NULL)
    {
        LWLockAcquire(&pkcs11_shared->lock, LW_EXCLUSIVE);
        if (pkcs11_state.kek_version > pkcs11_shared->current_kek_version)
            pkcs11_shared->current_kek_version = pkcs11_state.kek_version;
        LWLockRelease(&pkcs11_shared->lock);
    }    

    ereport(LOG,
            errmsg("pg_vault_tde: AES-256 KEK \"%s\" generated on PKCS#11 "
                   "token", v1_label));
    PG_RETURN_VOID();
}
