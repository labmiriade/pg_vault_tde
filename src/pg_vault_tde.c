/*
 * pg_vault_tde.c — Extension entry point and hook registration.
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */
#include "postgres.h"
#include "fmgr.h"
#include "access/tableam.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/guc.h"

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_iam.h"
#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_hw_accel.h"
#include "src/include/pg_vault_tde_guc.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/*
 * GUC variables — defined here, declared extern in pg_vault_tde_guc.h so
 * other translation units (kms.c, tam.c) can read them without re-registering.
 */
char *pg_vault_tde_vault_url            = NULL;
char *pg_vault_tde_vault_namespace      = NULL;
char *pg_vault_tde_vault_token          = NULL;
char *pg_vault_tde_vault_transit_mount  = NULL;
char *pg_vault_tde_vault_key_name       = NULL;
char *pg_vault_tde_vault_ca_cert        = NULL;
int         pg_vault_tde_vault_timeout_ms     = 5000;
bool        pg_vault_tde_enabled              = true;
int         pg_vault_tde_dek_cache_ttl        = 0;     /* 0 = disabled */
char *pg_vault_tde_vault_auth_method    = NULL;
char *pg_vault_tde_vault_role_id        = NULL;
char *pg_vault_tde_vault_secret_id      = NULL;
char *pg_vault_tde_vault_role_name      = NULL; /* role NAME for secret_id destroy (v1.4) */
char *pg_vault_tde_vault_k8s_role       = NULL;
char *pg_vault_tde_vault_k8s_mount      = NULL;
char *pg_vault_tde_crypto_provider      = NULL;
bool        pg_vault_tde_bgw_enabled              = false;
int         pg_vault_tde_token_renewal_interval   = 3600;

/* Hook chain pointers — we save the previous hook so we compose correctly. */
static shmem_request_hook_type prev_shmem_request_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/*
 * tde_backend_cleanup -- on_proc_exit callback.
 *
 * Frees per-backend EVP_CIPHER_CTX objects, wipes the IV batch buffer, and
 * frees the IAM SIV contexts.  Runs for every backend exit (normal,
 * SIGTERM, etc.) via the proc_exit() callback chain.
 */
static void
tde_backend_cleanup(int code, Datum arg)
{
    tde_crypto_ctx_cleanup();
    tde_iam_siv_ctx_cleanup();
    tde_hw_accel_cleanup();
}

PG_FUNCTION_INFO_V1(pg_vault_tde_tableam_handler);
PG_FUNCTION_INFO_V1(pg_vault_tde_iam_handler);

PGDLLEXPORT Datum
pg_vault_tde_tableam_handler(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(pg_vault_tde_get_tableam_routine());
}

PGDLLEXPORT Datum
pg_vault_tde_iam_handler(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(pg_vault_tde_get_iam_routine());
}

void _PG_init(void);

/*
 * pg_vault_tde_shmem_request
 *
 * PG 15+ requires that RequestAddinShmemSpace and RequestNamedLWLockTranche
 * be called from this dedicated hook, not from _PG_init.  Calling them from
 * _PG_init in PG18 is silently ignored, leaving the allocations missing.
 */
static void
pg_vault_tde_shmem_request(void)
{
    if (prev_shmem_request_hook)
        prev_shmem_request_hook();

    pg_vault_tde_kms_shmem_request();
}

/*
 * pg_vault_tde_shmem_startup
 *
 * Maps our shared memory structs once the segment is initialised.
 * Called by the postmaster and by each backend on first attach.
 */
static void
pg_vault_tde_shmem_startup(void)
{
    if (prev_shmem_startup_hook)
        prev_shmem_startup_hook();

    pg_vault_tde_kms_shmem_init();
}

/*
 * _PG_init
 *
 * Entry point for shared_preload_libraries. Wire up hook chains only —
 * do NOT call any shmem functions here; shared memory is not yet allocated
 * at this point.
 */
void
_PG_init(void)
{
    if (!process_shared_preload_libraries_in_progress)
        ereport(ERROR,
                (errmsg("pg_vault_tde must be loaded via shared_preload_libraries")));

    /*
     * GUC parameter registration must happen in _PG_init, before any shmem
     * or hook setup.
     */

    /* Vault endpoint URL */
    DefineCustomStringVariable("pg_vault_tde.vault_url",
        "HashiCorp Vault / OpenBao URL (e.g. https://vault.example.com:8200)",
        NULL, &pg_vault_tde_vault_url, "", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Vault namespace */
    DefineCustomStringVariable("pg_vault_tde.vault_namespace",
        "Vault namespace (enterprise only, empty for community)",
        NULL, &pg_vault_tde_vault_namespace, "", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Vault token — secret, not shown in pg_settings */
    DefineCustomStringVariable("pg_vault_tde.vault_token",
        "Vault token for authentication",
        NULL, &pg_vault_tde_vault_token, "", PGC_POSTMASTER,
        GUC_SUPERUSER_ONLY | GUC_NOT_IN_SAMPLE, NULL, NULL, NULL);

    /* Transit engine mount path */
    DefineCustomStringVariable("pg_vault_tde.vault_transit_mount",
        "Vault Transit secrets engine mount path",
        NULL, &pg_vault_tde_vault_transit_mount, "transit", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Transit key name for DEK wrapping */
    DefineCustomStringVariable("pg_vault_tde.vault_key_name",
        "Vault Transit key name for DEK wrapping",
        NULL, &pg_vault_tde_vault_key_name, "pg-tde-dek", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* TLS CA certificate bundle path */
    DefineCustomStringVariable("pg_vault_tde.vault_ca_cert",
        "Path to CA certificate bundle for Vault TLS verification",
        NULL, &pg_vault_tde_vault_ca_cert, "", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Vault HTTP request timeout */
    DefineCustomIntVariable("pg_vault_tde.vault_timeout_ms",
        "Vault HTTP request timeout in milliseconds (0 = no timeout)",
        NULL, &pg_vault_tde_vault_timeout_ms, 5000, 0, 300000,
        PGC_POSTMASTER, 0, NULL, NULL, NULL);

    /* Master on/off switch — useful for benchmarking overhead */
    DefineCustomBoolVariable("pg_vault_tde.enabled",
        "Enable AES-256-GCM encryption for encrypted_heap tables",
        NULL, &pg_vault_tde_enabled, true, PGC_SUSET,
        0, NULL, NULL, NULL);

    /* DEK cache TTL in seconds (v1.1) — 0 disables time-based expiry */
    DefineCustomIntVariable("pg_vault_tde.dek_cache_ttl",
        "Per-backend DEK cache time-to-live in seconds (0 = no expiry)",
        "When > 0, each backend re-reads the DEK from shared memory "
        "after this many seconds, even if key rotation has not occurred.",
        &pg_vault_tde_dek_cache_ttl, 0, 0, 86400,
        PGC_SIGHUP, 0, NULL, NULL, NULL);

    /* Vault auth method (v1.1): token, approle, or kubernetes */
    DefineCustomStringVariable("pg_vault_tde.vault_auth_method",
        "Vault authentication method: token, approle, or kubernetes",
        NULL, &pg_vault_tde_vault_auth_method, "token", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* AppRole role_id (v1.1) */
    DefineCustomStringVariable("pg_vault_tde.vault_role_id",
        "Vault AppRole role_id for authentication",
        NULL, &pg_vault_tde_vault_role_id, "", PGC_POSTMASTER,
        GUC_SUPERUSER_ONLY | GUC_NOT_IN_SAMPLE, NULL, NULL, NULL);

    /* AppRole secret_id (v1.1) */
    DefineCustomStringVariable("pg_vault_tde.vault_secret_id",
        "Vault AppRole secret_id for authentication",
        NULL, &pg_vault_tde_vault_secret_id, "", PGC_POSTMASTER,
        GUC_SUPERUSER_ONLY | GUC_NOT_IN_SAMPLE, NULL, NULL, NULL);

    /* AppRole role name (v1.4) — used for secret_id rotation after login */
    DefineCustomStringVariable("pg_vault_tde.vault_role_name",
        "Vault AppRole role name for secret_id rotation (v1.4)",
        "When set, pg_vault_tde destroys the used secret_id after a "
        "successful AppRole login, implementing the response_wrapping "
        "single-use pattern.  Must match the role name in "
        "`vault write auth/approle/role/<name> ...`.",
        &pg_vault_tde_vault_role_name, "", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Kubernetes auth role (v1.1) */
    DefineCustomStringVariable("pg_vault_tde.vault_k8s_role",
        "Vault Kubernetes auth role name",
        NULL, &pg_vault_tde_vault_k8s_role, "", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Kubernetes auth mount path (v1.1) */
    DefineCustomStringVariable("pg_vault_tde.vault_k8s_mount",
        "Vault Kubernetes auth engine mount path",
        NULL, &pg_vault_tde_vault_k8s_mount, "kubernetes", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* OpenSSL 3.x crypto provider for hardware acceleration (v1.1) */
    DefineCustomStringVariable("pg_vault_tde.crypto_provider",
        "OpenSSL 3.x provider name for hardware crypto offload",
        "Empty (default) uses built-in AES-NI/ARM CE auto-dispatch. "
        "Set to 'qatprovider' for Intel QAT, 'fips' for FIPS mode.",
        &pg_vault_tde_crypto_provider, "", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Background worker for automatic Vault token renewal (v1.3) */
    DefineCustomBoolVariable("pg_vault_tde.bgw_enabled",
        "Enable background worker for automatic Vault token renewal",
        "When true, a background worker periodically renews the Vault "
        "token and stores it in shared memory for all backends.  "
        "Only useful with AppRole or Kubernetes auth methods.",
        &pg_vault_tde_bgw_enabled, false, PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Token renewal interval in seconds (v1.3) */
    DefineCustomIntVariable("pg_vault_tde.token_renewal_interval",
        "Vault token renewal interval in seconds (background worker)",
        "How often the background worker renews the Vault token.  "
        "Ignored if bgw_enabled is false.",
        &pg_vault_tde_token_renewal_interval, 3600, 60, 86400,
        PGC_POSTMASTER, 0, NULL, NULL, NULL);

    /* Chain hooks so other extensions coexist correctly. */
    prev_shmem_request_hook = shmem_request_hook;
    shmem_request_hook = pg_vault_tde_shmem_request;

    prev_shmem_startup_hook = shmem_startup_hook;
    shmem_startup_hook = pg_vault_tde_shmem_startup;

    /*
     * Wire the mutable tde_methods copy: copy heapam's TableAmRoutine and
     * override the 6 data-touching callbacks with AES-256-GCM wrappers.
     * Must be done AFTER hooks are chained so that shmem (DEK store) is
     * initialised before any actual crypto is attempted.
     */
    pg_vault_tde_tam_init();

    /*
     * Wire the mutable tde_btree_methods copy: copy btree's IndexAmRoutine
     * and override ambuild/aminsert/ambeginscan/amrescan with AES-256-SIV
     * encryption wrappers.  Must run after GUC registration (provider GUC
     * needed by hw_accel_siv_cipher) but before the first CREATE INDEX.
     */
    tde_iam_init();

    /*
     * Initialize hardware acceleration provider layer.
     * Must run AFTER GUC registration so crypto_provider GUC is available.
     * Loads the configured OpenSSL provider (e.g. qatprovider for Intel QAT)
     * and pre-fetches GCM/SIV ciphers.  No-op if GUC is empty.
     */
    tde_hw_accel_init();

    /* Free per-backend EVP contexts on exit to avoid OpenSSL memory leaks. */
    on_proc_exit(tde_backend_cleanup, (Datum) 0);

    /*
     * Register the Vault token renewal background worker (v1.3).
     * Must happen in _PG_init before the postmaster forks.
     * Only starts if bgw_enabled=true; the BGW itself checks auth_method.
     */
    pg_vault_tde_register_bgw();

    ereport(LOG,
            (errmsg("pg_vault_tde: hooks registered, awaiting shmem startup")));
}
