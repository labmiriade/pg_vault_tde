/*
 * pg_vault_tde.c — Extension entry point and hook registration.
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */
#include "postgres.h"
#include "fmgr.h"
#include "access/relation.h"    /* try_relation_open / relation_close */
#include "access/tableam.h"
#include "catalog/namespace.h"
#include "commands/defrem.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/builtins.h"

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_iam.h"
#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_hw_accel.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/include/pg_vault_tde_catalog.h"
#include "src/kms/pg_vault_tde_kms_provider.h"

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

/* -----------------------------------------------------------------------
 * v1.5 GUC definitions
 * ----------------------------------------------------------------------- */
char *pg_vault_tde_kms_provider           = NULL; /* "vault" | "local" */
char *pg_vault_tde_wallet_path            = NULL; /* path to wallet.p12 */
char *pg_vault_tde_wallet_passphrase_env  = NULL; /* env var NAME */
bool  pg_vault_tde_wallet_auto_open       = true;
int   pg_vault_tde_max_encrypted_relations = 1024;
bool  pg_vault_tde_toast_encryption       = true;

/*
 * tde_active_kms_provider — selected KMS backend (set in _PG_init).
 * All callers that need KMS operations go through this pointer.
 * Declared extern in pg_vault_tde_kms_provider.h.
 */
const TdeKmsProvider *tde_active_kms_provider = NULL;

/* Hook chain pointers — we save the previous hook so we compose correctly. */
static shmem_request_hook_type    prev_shmem_request_hook = NULL;
static shmem_startup_hook_type    prev_shmem_startup_hook = NULL;
static ProcessUtility_hook_type   prev_process_utility_hook = NULL;

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
 * tde_get_tableam_name_for_rel
 *
 * Returns the access method name for the given relation OID, or NULL if the
 * relation does not exist yet (i.e. during CREATE TABLE before it is
 * committed).  We use this to decide whether a new relation is using the
 * encrypted_heap AM so we can register it in the DEK catalog.
 */
static const char *
tde_get_tableam_name_for_create(CreateStmt *create_stmt)
{
    /* CREATE TABLE ... USING <am_name> */
    if (create_stmt->accessMethod != NULL)
        return create_stmt->accessMethod;
    return NULL;
}

/*
 * tde_process_utility_hook
 *
 * ProcessUtility hook that intercepts DDL statements to maintain the per-
 * table DEK catalog:
 *
 *   CREATE TABLE ... USING encrypted_heap → register in pg_vault_tde_catalog
 *   DROP TABLE ... (if relation used encrypted_heap)  → deregister from catalog
 *
 * We chain to the previous ProcessUtility hook and to standard_ProcessUtility
 * after doing our pre/post-processing.
 *
 * Security note: we do NOT prevent CREATE TABLE AS SELECT or ALTER TABLE SET
 * ACCESS METHOD from using encrypted_heap — those paths also trigger TAM
 * callbacks and the catalog is updated lazily on first DEK access.
 */
static void
tde_process_utility_hook(PlannedStmt *pstmt,
                         const char *queryString,
                         bool readOnlyTree,
                         ProcessUtilityContext context,
                         ParamListInfo params,
                         QueryEnvironment *queryEnv,
                         DestReceiver *dest,
                         QueryCompletion *qc)
{
    Node       *parsetree = pstmt->utilityStmt;
    bool        is_create_encrypted = false;
    List       *drop_encrypted_oids = NIL;  /* OIDs of encrypted tables being dropped */

    /*
     * Pre-processing: determine if this is a CREATE TABLE USING encrypted_heap.
     * We check the AM name from the parse tree before execution so we know
     * which relids will be created.
     */
    if (IsA(parsetree, CreateStmt))
    {
        CreateStmt *stmt = (CreateStmt *) parsetree;
        const char *am   = tde_get_tableam_name_for_create(stmt);

        if (am != NULL && strcmp(am, "encrypted_heap") == 0)
            is_create_encrypted = true;
    }
    else if (IsA(parsetree, DropStmt))
    {
        DropStmt *stmt = (DropStmt *) parsetree;

        /*
         * For DROP TABLE, we capture the OIDs of all encrypted_heap tables
         * BEFORE the drop executes — after the drop, the relcache entry is
         * gone and we can no longer look up the AM.
         *
         * We build drop_encrypted_oids in the current MemoryContext (which
         * will survive through the rest of this hook invocation).
         */
        if (stmt->removeType == OBJECT_TABLE)
        {
            ListCell *lc;

            foreach(lc, stmt->objects)
            {
                RangeVar *rv  = makeRangeVarFromNameList((List *) lfirst(lc));
                Oid       rid = RangeVarGetRelid(rv, NoLock, true /* missing_ok */);

                if (OidIsValid(rid))
                {
                    Relation rel = try_relation_open(rid, NoLock);
                    if (rel != NULL)
                    {
                        if (OidIsValid(rel->rd_rel->relam) &&
                            strcmp(get_am_name(rel->rd_rel->relam),
                                   "encrypted_heap") == 0)
                            drop_encrypted_oids = lappend_oid(drop_encrypted_oids, rid);
                        relation_close(rel, NoLock);
                    }
                }
            }
        }
    }

    /* Run the actual DDL statement through the hook chain */
    if (prev_process_utility_hook)
        prev_process_utility_hook(pstmt, queryString, readOnlyTree,
                                  context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree,
                                context, params, queryEnv, dest, qc);

    /*
     * Post-processing for CREATE TABLE USING encrypted_heap:
     * After the table is committed we can look it up by name and register
     * it in the catalog.
     *
     * We use SPI to INSERT into pg_vault_tde_catalog.  The vault_key_name
     * defaults to pg_vault_tde.vault_key_name GUC (or "local" for wallet
     * provider).  The wrapped_dek column is populated lazily on first access
     * by the catalog hot-path.
     */
    if (is_create_encrypted)
    {
        CreateStmt *stmt   = (CreateStmt *) parsetree;
        Oid         relid;
        char        sql[512];
        int         rc;
        Oid         public_ns;

        relid = RangeVarGetRelid(stmt->relation, NoLock, true /* missing_ok */);
        if (!OidIsValid(relid))
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: could not find newly created "
                            "encrypted_heap relation '%s' for catalog "
                            "registration",
                            stmt->relation->relname)));
            return;
        }

        /*
         * Guard: pg_vault_tde_catalog is created by the v1.5 upgrade script
         * (pg_vault_tde--1.4--1.5.sql).  On a v1.0 deployment that has not
         * yet been upgraded, the table does not exist and we skip the INSERT
         * gracefully.  Encrypted tables still work using the global DEK.
         */
        public_ns = get_namespace_oid("public", true /* missing_ok */);
        if (!OidIsValid(public_ns) ||
            !OidIsValid(get_relname_relid("pg_vault_tde_catalog", public_ns)))
        {
            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: skipping per-table DEK registration "
                            "for relid=%u (pg_vault_tde_catalog not found; "
                            "upgrade to v1.5 to enable per-table DEK isolation)",
                            relid)));
            return;
        }

        SPI_connect();

        snprintf(sql, sizeof(sql),
                 "INSERT INTO pg_vault_tde_catalog "
                 "  (relid, vault_key_name, kms_provider) "
                 "VALUES (%u, %s, %s) "
                 "ON CONFLICT (relid) DO NOTHING",
                 relid,
                 pg_vault_tde_vault_key_name ?
                     quote_literal_cstr(pg_vault_tde_vault_key_name) :
                     quote_literal_cstr("pg-tde-dek"),
                 pg_vault_tde_kms_provider ?
                     quote_literal_cstr(pg_vault_tde_kms_provider) :
                     quote_literal_cstr("vault"));

        rc = SPI_execute(sql, false, 0);
        if (rc < 0)
            ereport(WARNING,
                    (errmsg("pg_vault_tde: could not register encrypted "
                            "relation %u in catalog (SPI rc=%d)",
                            relid, rc)));

        SPI_finish();

        ereport(DEBUG1,
                (errmsg("pg_vault_tde: registered relid=%u in DEK catalog",
                        relid)));
    }

    /*
     * Post-processing for DROP TABLE of encrypted relations:
     * DELETE the catalog rows that we captured before the drop.
     * Also evict the shmem DEK cache slots.
     */
    if (drop_encrypted_oids != NIL)
    {
        ListCell *lc;
        Oid       public_ns;
        bool      catalog_exists;

        /*
         * Check once whether pg_vault_tde_catalog exists (v1.5+ only).
         * On pre-v1.5 deployments the table is absent and we skip the DELETE,
         * but still evict the shmem DEK cache entries.
         */
        public_ns      = get_namespace_oid("public", true);
        catalog_exists = OidIsValid(public_ns) &&
                         OidIsValid(get_relname_relid("pg_vault_tde_catalog",
                                                      public_ns));

        if (catalog_exists)
            SPI_connect();

        foreach(lc, drop_encrypted_oids)
        {
            Oid         relid = lfirst_oid(lc);
            char        sql[256];
            int         rc;

            if (catalog_exists)
            {
                snprintf(sql, sizeof(sql),
                         "DELETE FROM pg_vault_tde_catalog WHERE relid = %u",
                         relid);
                rc = SPI_execute(sql, false, 0);
                if (rc < 0)
                    ereport(WARNING,
                            (errmsg("pg_vault_tde: could not remove catalog "
                                    "entry for dropped relation %u (SPI rc=%d)",
                                    relid, rc)));
            }

            /* Evict shmem slot — this holds the LWLock briefly */
            pg_vault_tde_catalog_evict_rel(relid);

            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: deregistered relid=%u from "
                            "DEK catalog", relid)));
        }

        if (catalog_exists)
            SPI_finish();
        list_free(drop_encrypted_oids);
    }
}

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

    /*
     * v1.5: reserve space for the per-table DEK cache.
     * Size determined by pg_vault_tde.max_encrypted_relations GUC.
     */
    pg_vault_tde_catalog_shmem_request();
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

    /*
     * v1.5: initialise the per-table DEK shmem cache.  Must run after
     * the global KMS shmem (pg_vault_tde_kms_shmem_init) since the catalog
     * cache may call the global DEK path as a fallback for v1.4 tables.
     */
    pg_vault_tde_catalog_shmem_init();

    /*
     * v1.5: activate the KMS provider selected by pg_vault_tde.kms_provider.
     * Providers call their init() function here so they can access shmem.
     */
    if (pg_vault_tde_kms_provider &&
        strcmp(pg_vault_tde_kms_provider, "local") == 0)
    {
        tde_active_kms_provider = pg_vault_tde_kms_local_provider();
    }
    else
    {
        /*
         * Default: vault provider.  The vault provider's init() sets up the
         * curl handle and attempts the configured auth method.
         */
        tde_active_kms_provider = pg_vault_tde_kms_vault_provider();
    }

    if (tde_active_kms_provider && tde_active_kms_provider->init)
        (void) tde_active_kms_provider->init();
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

    /* ----------------------------------------------------------------
     * v1.5 GUC registrations
     * ---------------------------------------------------------------- */

    /* KMS provider selector (v1.5) */
    DefineCustomStringVariable("pg_vault_tde.kms_provider",
        "KMS provider backend: vault (default) or local (PKCS#12 wallet)",
        "Selects which Key Management Service backend is active.  "
        "'vault' (default): uses HashiCorp Vault / OpenBao Transit API.  "
        "'local': uses a PKCS#12 wallet at pg_vault_tde.wallet_path.",
        &pg_vault_tde_kms_provider, "vault", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Local wallet path (v1.5) — default resolved at runtime from $PGDATA */
    DefineCustomStringVariable("pg_vault_tde.wallet_path",
        "Absolute path to the PKCS#12 local wallet file",
        "Used only when pg_vault_tde.kms_provider = 'local'.  "
        "Default: $PGDATA/pg_vault_tde/wallet.p12",
        &pg_vault_tde_wallet_path, "", PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Passphrase env var NAME — never the passphrase itself (v1.5) */
    DefineCustomStringVariable("pg_vault_tde.wallet_passphrase_env",
        "Name of the environment variable holding the wallet passphrase",
        "The passphrase is read from getenv(wallet_passphrase_env) at "
        "startup.  NEVER put the passphrase in postgresql.conf directly.",
        &pg_vault_tde_wallet_passphrase_env, "PG_TDE_WALLET_PASS",
        PGC_POSTMASTER, GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* Auto-open wallet on startup (v1.5) */
    DefineCustomBoolVariable("pg_vault_tde.wallet_auto_open",
        "Auto-open the local wallet on server startup",
        "When true (default), opens the wallet during shmem_startup_hook "
        "if the passphrase env var is set.  When false, defers opening "
        "until the first encrypted relation access.",
        &pg_vault_tde_wallet_auto_open, true, PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* Max encrypted relations in shmem cache (v1.5) */
    DefineCustomIntVariable("pg_vault_tde.max_encrypted_relations",
        "Maximum number of independently-keyed encrypted_heap relations",
        "Controls the size of the per-table DEK cache in shared memory.  "
        "Increase if you have more than 1024 encrypted tables.  "
        "Requires server restart to take effect.",
        &pg_vault_tde_max_encrypted_relations,
        TDE_REL_DEK_CACHE_DEFAULT, 64, 65536,
        PGC_POSTMASTER, 0, NULL, NULL, NULL);

    /* TOAST encryption switch (v1.5) */
    DefineCustomBoolVariable("pg_vault_tde.toast_encryption",
        "Encrypt TOAST chunks for encrypted_heap tables",
        "When true (default in v1.5), TOAST tables for encrypted_heap "
        "relations use encrypted_heap AM and encrypt each chunk with "
        "AES-256-GCM.  Set to false only for debugging or migration.",
        &pg_vault_tde_toast_encryption, true, PGC_SIGHUP,
        0, NULL, NULL, NULL);

    /* Chain hooks so other extensions coexist correctly. */
    prev_shmem_request_hook = shmem_request_hook;
    shmem_request_hook = pg_vault_tde_shmem_request;

    prev_shmem_startup_hook = shmem_startup_hook;
    shmem_startup_hook = pg_vault_tde_shmem_startup;

    /*
     * ProcessUtility hook: intercept CREATE TABLE USING encrypted_heap and
     * DROP TABLE to maintain the per-table DEK catalog automatically.
     * Must run AFTER the DDL so the table OID is already committed.
     */
    prev_process_utility_hook = ProcessUtility_hook;
    ProcessUtility_hook = tde_process_utility_hook;

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
