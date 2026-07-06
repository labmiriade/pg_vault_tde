/*
 * pg_vault_tde.c — Extension entry point and hook registration.
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */
#include "postgres.h"
#include "fmgr.h"
#include "access/htup_details.h" /* GETSTRUCT, HeapTupleIsValid */
#include "access/relation.h"    /* try_relation_open / relation_close */
#include "access/tableam.h"
#include "catalog/indexing.h"   /* systable_beginscan / SysScanDesc */
#include "catalog/namespace.h"
#include "catalog/objectaccess.h" /* object_access_hook, OAT_POST_CREATE */
#include "catalog/pg_class.h"     /* RelationRelationId, Form_pg_class, ClassOidIndexId */
#include "utils/fmgroids.h"     /* F_OIDEQ */
#include "utils/snapmgr.h"      /* SnapshotSelf */
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
#include "access/table.h"
#include "commands/extension.h"

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_iam.h"
#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_hw_accel.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_audit.h"
#include "src/include/pg_vault_tde_rmgr.h"
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
char *pg_vault_tde_extension_name       = "pg_vault_tde";

/* -----------------------------------------------------------------------
 * v1.5 GUC definitions
 * ----------------------------------------------------------------------- */
char *pg_vault_tde_kms_provider           = NULL; /* "vault" | "local" */
char *pg_vault_tde_wallet_path            = NULL; /* path to wallet.p12 */
char *pg_vault_tde_wallet_passphrase_env  = NULL; /* env var NAME */
bool  pg_vault_tde_wallet_auto_open       = true;
int   pg_vault_tde_max_encrypted_relations = 1024;
bool  pg_vault_tde_toast_encryption       = true;
bool  pg_vault_tde_toast_custom_rmgr      = false;  /* gated off by default */

/* -----------------------------------------------------------------------
 * v1.6 GUC definitions — flexible passphrase ingestion
 * ----------------------------------------------------------------------- */
char *pg_vault_tde_wallet_passphrase_file    = NULL; /* path to passphrase file */
char *pg_vault_tde_wallet_passphrase_command = NULL; /* shell command → passphrase */
char *pg_vault_tde_wallet_dev_mode_passphrase = NULL;/* dev-mode only; never prod */
bool  pg_vault_tde_dev_mode                  = false;/* enables dev conveniences */

/*
 * tde_active_kms_provider — selected KMS backend (set in _PG_init).
 * All callers that need KMS operations go through this pointer.
 * Declared extern in pg_vault_tde_kms_provider.h.
 */
const TdeKmsProvider *tde_active_kms_provider = NULL;

/*
 * tde_shmem_started — true after pg_vault_tde_shmem_startup() completes.
 *
 * Used by the kms_provider GUC assign hook to decide whether it is safe to
 * call provider->init() immediately (shmem is ready) or defer until the
 * shmem_startup_hook runs (postmaster pre-shmem phase).
 *
 * This is a plain static (process-local); each backend inherits the true value
 * from the postmaster after it has been forked post-startup.
 */
static bool tde_shmem_started = false;

/* Hook chain pointers — we save the previous hook so we compose correctly. */
static shmem_request_hook_type    prev_shmem_request_hook = NULL;
static shmem_startup_hook_type    prev_shmem_startup_hook = NULL;
static ProcessUtility_hook_type   prev_process_utility_hook = NULL;
static object_access_hook_type    prev_object_access_hook = NULL;

/* Audit hook — NULL unless an external audit module installs one. */
tde_audit_hook audit_hook_ptr = NULL;

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
    tde_audit(AUDIT_LOG_STOP, NULL, true);
    tde_crypto_ctx_cleanup();
    tde_iam_ctx_cleanup();
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
 * tde_kms_provider_assign — GUC assign hook for pg_vault_tde.kms_provider.
 *
 * Fires whenever the GUC changes value: during postgresql.conf processing at
 * postmaster startup, when per-database settings from ALTER DATABASE SET are
 * applied at backend connect time (inside InitPostgres), and on SET inside a
 * session.
 *
 * The hook updates tde_active_kms_provider to the new provider vtable.  If
 * shmem is already ready (tde_shmem_started == true) it also calls init() so
 * the provider can open its wallet / restore its DEK.  In the postmaster
 * pre-shmem phase tde_shmem_started is false, so init() is deferred until
 * pg_vault_tde_shmem_startup().
 *
 * This is the ONLY place that sets tde_active_kms_provider; the previous
 * assignment block in pg_vault_tde_shmem_startup() has been removed.
 */
static void
tde_kms_provider_assign(const char *newval, void *extra)
{
    const TdeKmsProvider *new_provider = NULL;

    if (newval == NULL || newval[0] == '\0')
    {
        /* Empty/unset: clear the pointer, leave init for later */
        tde_active_kms_provider = NULL;
        return;
    }

    if (strcmp(newval, "local") == 0)
        new_provider = pg_vault_tde_kms_local_provider();
    else if (strcmp(newval, "vault") == 0)
        new_provider = pg_vault_tde_kms_vault_provider();
    else
    {
        /* Unknown value — check_hook should have rejected it; be defensive */
        tde_active_kms_provider = NULL;
        return;
    }

    tde_active_kms_provider = new_provider;

    /*
     * Call init() only once shmem is available.  In the postmaster config-load
     * phase tde_shmem_started is still false; init() will be called from
     * pg_vault_tde_shmem_startup() instead.  In a backend (after fork) shmem
     * is already attached, so we can initialise immediately — this is the path
     * that makes ALTER DATABASE SET pg_vault_tde.kms_provider work.
     */
    if (tde_shmem_started && new_provider->init)
        (void) new_provider->init();
}

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
 * tde_object_access_hook — register per-table DEK immediately on table creation.
 *
 * PostgreSQL fires this hook inside the same command as the CREATE TABLE (or
 * CTAS), AFTER the pg_class row is inserted but BEFORE any data is inserted
 * into the new relation.  This timing is critical for CTAS:
 *
 *   CREATE TABLE t USING encrypted_heap AS SELECT ...
 *
 * The ProcessUtility post-processing registers the DEK AFTER
 * standard_ProcessUtility returns, which is too late for CTAS — the TAM
 * tuple_insert callbacks have already run and need the DEK.  By hooking
 * here we guarantee the DEK is in pg_vault_tde_catalog before the first INSERT.
 *
 * IMPORTANT: during OAT_POST_CREATE, CommandCounterIncrement has NOT yet been
 * called, so the new pg_class tuple is not yet visible in the syscache or via
 * try_relation_open().  We must use SnapshotSelf (which sees tuples inserted
 * by the current command regardless of CommandCounterIncrement) with a direct
 * heap scan of pg_class to determine the AM of the new relation.
 *
 * catalog_register_rel is idempotent (skips if entry already exists), so it
 * is safe to call here even though the ProcessUtility post-processing may
 * call it again afterwards for regular CREATE TABLE.
 */
static void
tde_object_access_hook(ObjectAccessType access, Oid classId, Oid objectId,
                       int subId, void *arg)
{
    char           *amname;
    Relation        rel;
    Oid             relam  = InvalidOid;
    char            relkind = '\0';

    /* Chain to any previously registered hook first. */
    if (prev_object_access_hook)
        prev_object_access_hook(access, classId, objectId, subId, arg);

    /* We only care about newly created plain relations. */
    if (access != OAT_POST_CREATE)
        return;
    if (classId != RelationRelationId)
        return;
    if (subId != 0)             /* subId != 0 means a column, not the relation */
        return;

    /*
     * We call CCI here because the OAT_POST_CREATE doesn't do it,
     * so we are not able to open relation created by the same
     * transaction.
     * From a testability point of view, it's not very good:
     * (https://www.postgresql.org/message-id/flat/CAHoZxqvN2eoic_CvjsAvpryyLyA2xG8JmsyMtKFFJz_1oFhfOg@mail.gmail.com)
     *
     * Alternative: scan pg_class with SnapshotSelf (less efficient)
     */
    CommandCounterIncrement();

    rel = try_relation_open(objectId, NoLock);
    if(!rel) ereport(ERROR, errmsg("pg_vault_tde: unable to open relation %u", objectId));

    /*
     * Skip rewrite targets created by VACUUM FULL / ALTER TABLE / CLUSTER.
     * pg_class.relrewrite is set on the transient new heap and is only visible
     * after CommandCounterIncrement() above — which is why we cannot check it
     * via SearchSysCache before the CCI (it would return InvalidOid and the
     * guard would incorrectly pass, registering the temp relation).
     */
    if (OidIsValid(rel->rd_rel->relrewrite))
    {
        table_close(rel, NoLock);
        return;
    }

    relkind = rel->rd_rel->relkind;
    relam = rel->rd_rel->relam;

    table_close(rel, NoLock);

    /* Only handle plain heap and index tables; skip TOAST, sequences, etc. */
    if ((relkind != RELKIND_RELATION && relkind != RELKIND_INDEX))
        return;

    if(!OidIsValid(relam))
        return;

    amname = get_am_name(relam);
    if (amname == NULL || (strcmp(amname, "encrypted_heap") != 0 && strcmp(amname, "tde_btree") != 0))
        return;

    /*
     * Register a fresh per-table DEK now, while we are still inside the
     * CREATE command and before any row is inserted.  catalog_register_rel
     * is idempotent: if the entry already exists it returns immediately
     * without overwriting the existing DEK.
     */
    pg_vault_tde_catalog_register_rel(objectId);

    ereport(DEBUG1,
            errmsg("pg_vault_tde: [object_access] registered DEK for new "
                   "encrypted_heap relation %u", objectId));
}


/*
 * tde_process_utility_hook
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
    bool        alter_tam_away = false; /* converting FROM encrypted_heap TO another TAM */
    bool        alter_tam_into = false; /* converting TO encrypted_heap FROM another TAM */
    List       *drop_encrypted_oids = NIL;  /* OIDs of encrypted tables being dropped */
    List       *evict_only_oids     = NIL;  /* OIDs to evict from shmem only (no catalog row) */

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
                        {
                            drop_encrypted_oids = lappend_oid(drop_encrypted_oids, rid);

                            /*
                             * Also capture the TOAST relation OID to evict its
                             * shmem DEK cache slot.  TOAST tables share the
                             * parent's DEK and are never registered with a
                             * separate row in pg_vault_tde_catalog, so we add
                             * them to evict_only_oids (shmem eviction only) and
                             * NOT to drop_encrypted_oids (which triggers a
                             * catalog DELETE that would produce a spurious
                             * WARNING when no row is found).
                             */
                            if (OidIsValid(rel->rd_rel->reltoastrelid))
                                evict_only_oids = lappend_oid(
                                        evict_only_oids,
                                        rel->rd_rel->reltoastrelid);
                        }
                        relation_close(rel, NoLock);
                    }
                }
            }
        }
    }
    else if (IsA(parsetree, AlterTableStmt))
    {
        AlterTableStmt* stmt = (AlterTableStmt*) parsetree;

        ListCell* lc;
        
        if(stmt->objtype == OBJECT_TABLE) {
            foreach(lc, stmt->cmds) {
                AlterTableCmd* cmd = lfirst_node(AlterTableCmd, lc);

                if(cmd->subtype == AT_SetAccessMethod) {   
                    if(strcmp(cmd->name, "encrypted_heap") == 0) {
                        alter_tam_into = true;
                        break;
                    }
                    else {
                        alter_tam_away = true;
                        break;  
                    }     
                }
            }
        }
    }


    /*
     * We register the tuple table BEFORE utility_hook execution
     * because it's going to rewrite the table with encrypted_heap's
     * methods (insert, multi-insert ecc.) and we MUST have a DEK 
     * before that.
     */
    if(alter_tam_into)
    {
        AlterTableStmt *stmt = (AlterTableStmt *) parsetree;
        Oid         relid;
        Oid         ext_ns;

        relid = RangeVarGetRelid(stmt->relation, NoLock, true /* missing_ok */);
        if (!OidIsValid(relid))
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: could not find "
                            "heap relation '%s' for catalog "
                            "registration",
                            stmt->relation->relname)));
            return;
        }

        ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
        if (!OidIsValid(ext_ns) ||
            !OidIsValid(get_relname_relid("pg_vault_tde_catalog", ext_ns)))
        {
            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: skipping per-table DEKeregistration "
                            "for relid=%u (pg_vault_tde_catalog not found; "
                            "upgrade to v1.5 to enable per-table DEK isolation)",
                            relid)));
            return;
        }

        pg_vault_tde_catalog_register_rel(relid);
        tde_audit(RELATION_ENCRYPT, psprintf("%u", relid), true);

        ereport(DEBUG1,
                (errmsg("pg_vault_tde: registered relid=%u in DEK catalog",
                        relid)));
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
     * We use SPI to INSERT into pg_vault_tde_catalog. 
     * The wrapped_dek column is populated lazily on first access
     * by the catalog hot-path.
     */
    if (is_create_encrypted)
    {
        CreateStmt *stmt   = (CreateStmt *) parsetree;
        Oid         relid;
        Oid         ext_ns;

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
         * Guard: pg_vault_tde_catalog is created by the v1.5 upgrade script.
         * On a pre-v1.5 deployment skip the INSERT gracefully.
         */
        ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
        if (!OidIsValid(ext_ns) ||
            !OidIsValid(get_relname_relid("pg_vault_tde_catalog", ext_ns)))
        {
            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: skipping per-table DEK registration "
                            "for relid=%u (pg_vault_tde_catalog not found; "
                            "upgrade to v1.5 to enable per-table DEK isolation)",
                            relid)));
            return;
        }

        /*
         * Generate a fresh per-table DEK, wrap it under the active KMS
         * provider's KEK, and store the wrapped bytes in pg_vault_tde_catalog.
         * pg_vault_tde_catalog_register_rel() manages its own SPI connection
         * and calls OPENSSL_cleanse() on the plaintext DEK after wrapping.
         */
        pg_vault_tde_catalog_register_rel(relid);
        tde_audit(RELATION_ENCRYPT, psprintf("%u", relid), true);

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
        Oid       ext_ns;
        bool      catalog_exists;

        /*
         * Check once whether pg_vault_tde_catalog exists (v1.5+ only).
         * On pre-v1.5 deployments the table is absent and we skip the DELETE,
         * but still evict the shmem DEK cache entries.
         */
        ext_ns      = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
        catalog_exists = OidIsValid(ext_ns) &&
                         OidIsValid(get_relname_relid("pg_vault_tde_catalog",
                                                      ext_ns));
        
        foreach(lc, drop_encrypted_oids)
        {
            Oid         relid = lfirst_oid(lc);

            if (catalog_exists)
            {
                pg_vault_tde_catalog_deregister_rel(relid);
            }
            else
            {
                /*
                 * Pre-v1.5 deployment: no catalog row to delete, but we must
                 * still evict the shmem DEK cache entry to prevent stale DEK
                 * reuse if the OID is recycled by a future CREATE TABLE.
                 */
                pg_vault_tde_catalog_evict_rel(relid);
            }

            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: deregistered relid=%u from "
                            "DEK catalog", relid)));
        }
        list_free(drop_encrypted_oids);
    }

    /*
     * Evict TOAST table OIDs from the shmem DEK cache.  TOAST tables share
     * the parent's DEK and have no row in pg_vault_tde_catalog, so only a
     * cache eviction is needed here.
     */
    if (evict_only_oids != NIL)
    {
        ListCell *lc;

        foreach(lc, evict_only_oids)
        {
            Oid relid = lfirst_oid(lc);

            pg_vault_tde_catalog_evict_rel(relid);

            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: evicted TOAST relid=%u from "
                            "shmem DEK cache", relid)));
        }
        list_free(evict_only_oids);
    }

    if(alter_tam_away)
    {
        AlterTableStmt *stmt   = (AlterTableStmt *) parsetree;
        Oid         relid;
        Oid         ext_ns;

        relid = RangeVarGetRelid(stmt->relation, NoLock, true /* missing_ok */);
        if (!OidIsValid(relid))
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: could not find "
                            "encrypted_heap relation '%s' for catalog "
                            "deregistration",
                            stmt->relation->relname)));
            return;
        }

        ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
        if (!OidIsValid(ext_ns) ||
            !OidIsValid(get_relname_relid("pg_vault_tde_catalog", ext_ns)))
        {
            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: skipping per-table DEK deregistration "
                            "for relid=%u (pg_vault_tde_catalog not found; "
                            "upgrade to v1.5 to enable per-table DEK isolation)",
                            relid)));
            return;
        }

        pg_vault_tde_catalog_deregister_rel(relid);
        tde_audit(RELATION_DECRYPT, psprintf("%u", relid), true);

        ereport(DEBUG1,
                (errmsg("pg_vault_tde: deregistered relid=%u in DEK catalog",
                        relid)));
    }
}

static const char *
tde_event_string(TdeAuditEvent event)
{
    switch (event)
    {
        case KMS_DEK_ACCESS:        return "DEK_ACCESS";
        case KMS_DEK_CREATE:        return "DEK_CREATE";
        case KMS_DEK_UPDATE:        return "DEK_UPDATE";
        case KMS_DEK_ROTATE:        return "DEK_ROTATE";
        case KMS_DEK_DELETE:        return "DEK_DELETE";
        case KMS_KEK_ROTATE:        return "KEK_ROTATE";
        case KMS_AUTH_SUCCESS:      return "KMS_AUTH_SUCCESS";
        case KMS_AUTH_FAILURE:      return "KMS_AUTH_FAILURE";
        case WALLET_OPEN:           return "WALLET_OPEN";
        case WALLET_CLOSE:          return "WALLET_CLOSE";
        case RELATION_ENCRYPT:      return "RELATION_ENCRYPT";
        case RELATION_DECRYPT:      return "RELATION_DECRYPT";
        case ACCESS_DENIED:         return "ACCESS_DENIED";
        case AUDIT_LOG_START:       return "AUDIT_LOG_START";
        case AUDIT_LOG_STOP:        return "AUDIT_LOG_STOP";
        case INTEGRITY_VIOLATION:   return "INTEGRITY_VIOLATION";
        default:                    return "UNKNOWN";
    }
}

static void tde_audit_handler(TdeAuditEvent event, const char* reloid, bool success)
{
    const char *rolname = OidIsValid(GetUserId())
                          ? GetUserNameFromId(GetUserId(), true)
                          : "(system)";
    ereport(LOG,
        (errmsg("AUDIT: event=%s, oid=%s, user=%s, success=%s, pid=%d",
                tde_event_string(event),
                reloid != NULL ? reloid : "-",
                rolname != NULL ? rolname : "(unknown)",
                success ? "t" : "f",
                MyProcPid),
            errhidestmt(true),
            errhidecontext(true)
        )
    );
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
     * v1.5+: initialise the per-table DEK shmem cache.  Must run after
     * pg_vault_tde_kms_shmem_init (KMS shmem must exist first).
     */
    pg_vault_tde_catalog_shmem_init();

    /*
     * Mark shmem as available.  The kms_provider assign hook checks this flag
     * before calling provider->init(); from this point on any GUC change (e.g.
     * ALTER DATABASE SET applied at backend connect) will trigger init()
     * directly in the assign hook rather than requiring a second startup path.
     */
    tde_shmem_started = true;

    /*
     * tde_active_kms_provider was already set by the GUC assign hook when
     * postgresql.conf was processed during startup.  Call init() now that
     * shmem is available.  If no provider was configured at the cluster level
     * (per-database-only setup) tde_active_kms_provider is NULL here and
     * each backend will activate its provider via the assign hook.
     */
    if (tde_active_kms_provider && tde_active_kms_provider->init)
        (void) tde_active_kms_provider->init();
    else if (!tde_active_kms_provider)
        ereport(LOG,
                errmsg("pg_vault_tde: no cluster-level KMS provider configured; "
                       "per-database provider (ALTER DATABASE SET "
                       "pg_vault_tde.kms_provider) will be activated on first "
                       "connection"));
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
     *
     * WHY PGC_SUSET FOR ALMOST EVERYTHING:
     * All KMS-related GUCs use PGC_SUSET (superuser-settable) rather than
     * PGC_POSTMASTER.  This enables per-database KMS configuration without
     * a server restart: a superuser can run
     *
     *   ALTER DATABASE tenant_a SET pg_vault_tde.vault_key_name = 'tde-a';
     *   ALTER DATABASE tenant_b SET pg_vault_tde.kms_provider   = 'local';
     *
     * and each new connection picks up the effective value for its database.
     * This is the primary mechanism for multi-tenant key isolation within a
     * single PostgreSQL cluster.
     */

    /*
     * vault_url — PGC_SUSET so different databases can target separate Vault
     * clusters or namespaced endpoints without restarting the server.
     */
    DefineCustomStringVariable("pg_vault_tde.vault_url",
        "HashiCorp Vault / OpenBao URL (e.g. https://vault.example.com:8200)",
        NULL, &pg_vault_tde_vault_url, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * vault_namespace — PGC_SUSET so databases can be isolated into separate
     * Vault Enterprise namespaces (e.g. tenant_a vs. tenant_b) via
     * ALTER DATABASE SET without a restart.
     */
    DefineCustomStringVariable("pg_vault_tde.vault_namespace",
        "Vault namespace (enterprise only, empty for community)",
        NULL, &pg_vault_tde_vault_namespace, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* Vault token — secret, not shown in pg_settings (GUC_NOT_IN_SAMPLE) */
    DefineCustomStringVariable("pg_vault_tde.vault_token",
        "Vault token for authentication",
        NULL, &pg_vault_tde_vault_token, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY | GUC_NOT_IN_SAMPLE, NULL, NULL, NULL);

    /*
     * vault_transit_mount — PGC_SUSET so databases can use dedicated Transit
     * engine mounts (e.g. "transit/tenant-a") for key isolation without restart.
     */
    DefineCustomStringVariable("pg_vault_tde.vault_transit_mount",
        "Vault Transit secrets engine mount path",
        NULL, &pg_vault_tde_vault_transit_mount, "transit", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * vault_key_name — PGC_SUSET to enable per-database key isolation: each
     * tenant database can point to a dedicated Transit key (e.g. "tde-dek-a",
     * "tde-dek-b") via ALTER DATABASE SET without requiring a restart.
     */
    DefineCustomStringVariable("pg_vault_tde.vault_key_name",
        "Vault Transit key name for DEK wrapping",
        NULL, &pg_vault_tde_vault_key_name, "pg-tde-dek", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * vault_ca_cert — PGC_SUSET so databases routed to different Vault
     * clusters (with different CAs) can supply the correct trust anchor.
     */
    DefineCustomStringVariable("pg_vault_tde.vault_ca_cert",
        "Path to CA certificate bundle for Vault TLS verification",
        NULL, &pg_vault_tde_vault_ca_cert, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * vault_timeout_ms — PGC_SUSET so high-latency secondary Vault clusters
     * can get a longer timeout without affecting the cluster-wide default.
     */
    DefineCustomIntVariable("pg_vault_tde.vault_timeout_ms",
        "Vault HTTP request timeout in milliseconds (0 = no timeout)",
        NULL, &pg_vault_tde_vault_timeout_ms, 5000, 0, 300000,
        PGC_SUSET, GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* 
     * enabled — PGC_POSTMASTER: fissato all'avvio del server, non modificabile
     * a runtime. Il valore è codificato per-tupla su disco (header vs wire v4
     * cifrato): se il GUC fosse togglabile a runtime, righe scritte con
     * enabled=on e lette con enabled=off restituirebbero ciphertext grezzo
     * come plaintext — perdita di integrità silenziosa.
     */
    DefineCustomBoolVariable("pg_vault_tde.enabled",
        "Enable AES-256-GCM encryption for encrypted_heap tables",
        NULL, &pg_vault_tde_enabled, true, PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* DEK cache TTL in seconds (v1.1) — 0 disables time-based expiry */
    DefineCustomIntVariable("pg_vault_tde.dek_cache_ttl",
        "Per-backend DEK cache time-to-live in seconds (0 = no expiry)",
        "When > 0, each backend re-reads the DEK from shared memory "
        "after this many seconds, even if key rotation has not occurred.",
        &pg_vault_tde_dek_cache_ttl, 0, 0, 86400,
        PGC_SUSET, 0, NULL, NULL, NULL);

    /*
     * vault_auth_method — PGC_SUSET so databases on different Kubernetes
     * namespaces or with different credential stores can use different auth
     * methods (e.g. one uses 'approle', another uses 'kubernetes').
     */
    DefineCustomStringVariable("pg_vault_tde.vault_auth_method",
        "Vault authentication method: token, approle, or kubernetes",
        NULL, &pg_vault_tde_vault_auth_method, "token", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * vault_role_id / vault_secret_id — PGC_SUSET + GUC_NOT_IN_SAMPLE so each
     * database can supply its own AppRole credentials without the secrets
     * appearing in pg_settings, pg_file_settings, or config file samples.
     */
    DefineCustomStringVariable("pg_vault_tde.vault_role_id",
        "Vault AppRole role_id for authentication",
        NULL, &pg_vault_tde_vault_role_id, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY | GUC_NOT_IN_SAMPLE, NULL, NULL, NULL);

    DefineCustomStringVariable("pg_vault_tde.vault_secret_id",
        "Vault AppRole secret_id for authentication",
        NULL, &pg_vault_tde_vault_secret_id, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY | GUC_NOT_IN_SAMPLE, NULL, NULL, NULL);

    /* AppRole role name (v1.4) — used for secret_id rotation after login */
    DefineCustomStringVariable("pg_vault_tde.vault_role_name",
        "Vault AppRole role name for secret_id rotation (v1.4)",
        "When set, pg_vault_tde destroys the used secret_id after a "
        "successful AppRole login, implementing the response_wrapping "
        "single-use pattern.  Must match the role name in "
        "`vault write auth/approle/role/<name> ...`.",
        &pg_vault_tde_vault_role_name, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * vault_k8s_role / vault_k8s_mount — PGC_SUSET so each database (or
     * Kubernetes namespace) can bind to a distinct K8s auth role and mount
     * path without restarting the server.
     */
    DefineCustomStringVariable("pg_vault_tde.vault_k8s_role",
        "Vault Kubernetes auth role name",
        NULL, &pg_vault_tde_vault_k8s_role, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomStringVariable("pg_vault_tde.vault_k8s_mount",
        "Vault Kubernetes auth engine mount path",
        NULL, &pg_vault_tde_vault_k8s_mount, "kubernetes", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

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
        &pg_vault_tde_bgw_enabled, false, PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* Token renewal interval in seconds (v1.3) */
    DefineCustomIntVariable("pg_vault_tde.token_renewal_interval",
        "Vault token renewal interval in seconds (background worker)",
        "How often the background worker renews the Vault token.  "
        "Ignored if bgw_enabled is false.",
        &pg_vault_tde_token_renewal_interval, 3600, 60, 86400,
        PGC_SUSET, GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* ----------------------------------------------------------------
     * v1.5 GUC registrations
     * ---------------------------------------------------------------- */

    /*
     * kms_provider — PGC_SUSET so each database can independently use a
     * different KMS backend (e.g. cluster-default 'vault' but one offline
     * database uses 'local') via ALTER DATABASE SET pg_vault_tde.kms_provider.
     * The provider is re-evaluated per connection from the effective GUC value.
     */
    DefineCustomStringVariable("pg_vault_tde.kms_provider",
        "KMS provider backend: vault or local (PKCS#12 wallet)",
        "Selects which Key Management Service backend is active.  "
        "'vault': uses HashiCorp Vault / OpenBao Transit API.  "
        "'local': uses a PKCS#12 wallet at pg_vault_tde.wallet_path.  "
        "Settable per-database via ALTER DATABASE SET.",
        &pg_vault_tde_kms_provider, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, tde_kms_provider_assign, NULL);

    /* Local wallet path (v1.5) — default resolved at runtime from $PGDATA */
    DefineCustomStringVariable("pg_vault_tde.wallet_path",
        "Absolute path to the PKCS#12 local wallet file",
        "Used only when pg_vault_tde.kms_provider = 'local'.  "
        "Default: /var/lib/pg_vault_tde/<DB_OID>/wallet.p12",
        &pg_vault_tde_wallet_path, "", PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* Passphrase env var NAME — never the passphrase itself (v1.5) */
    DefineCustomStringVariable("pg_vault_tde.wallet_passphrase_env",
        "Name of the environment variable holding the wallet passphrase",
        "The passphrase is read from getenv(wallet_passphrase_env) at "
        "startup.  NEVER put the passphrase in postgresql.conf directly.",
        &pg_vault_tde_wallet_passphrase_env, "",
        PGC_SUSET, GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* Auto-open wallet on startup (v1.5) */
    DefineCustomBoolVariable("pg_vault_tde.wallet_auto_open",
        "Auto-open the local wallet on server startup",
        "When true (default), opens the wallet during shmem_startup_hook "
        "if the passphrase env var is set.  When false, defers opening "
        "until the first encrypted relation access.",
        &pg_vault_tde_wallet_auto_open, true, PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

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
        &pg_vault_tde_toast_encryption, true, PGC_SUSET,
        0, NULL, NULL, NULL);

    /* Custom WAL resource manager for TOAST chunks (logical replication) */
    DefineCustomBoolVariable("pg_vault_tde.toast_custom_rmgr",
        "WAL-log encrypted TOAST chunks under the custom pg_vault_tde rmgr",
        "When true, encrypted TOAST chunks are written via the custom WAL "
        "resource manager (TDE_RMGR_ID) so the logical decoder routes them "
        "away from the reorder buffer's toast_hash, enabling logical "
        "replication of encrypted_heap tables with TOASTed columns.  Requires "
        "the rmgr to be registered at preload time, hence PGC_POSTMASTER.  "
        "Default off.",
        &pg_vault_tde_toast_custom_rmgr, false, PGC_POSTMASTER,
        0, NULL, NULL, NULL);

    /* ----------------------------------------------------------------
     * v1.6 GUC registrations — flexible wallet passphrase ingestion
     * ---------------------------------------------------------------- */

    /*
     * wallet_passphrase_file — read passphrase from a file (v1.6).
     * Takes second priority after wallet_passphrase_command.
     * File must be owned by the postgres OS user, mode 0400 or 0600.
     */
    DefineCustomStringVariable("pg_vault_tde.wallet_passphrase_file",
        "Path to a file containing the wallet passphrase",
        "The wallet passphrase is read from this file at startup.  "
        "The file must be mode 0400 or 0600 (owner-only).  "
        "Incompatible with wallet_passphrase_env if both are set.  "
        "wallet_passphrase_command takes priority if set.",
        &pg_vault_tde_wallet_passphrase_file, "",
        PGC_SUSET, GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * wallet_passphrase_command — shell command whose stdout is the
     * passphrase (v1.6).  Highest priority passphrase source.
     * Examples: "systemd-creds decrypt pg-tde-pass"
     *           "aws secretsmanager get-secret-value --query SecretString
     *             --output text --secret-id pg/tde/wallet"
     */
    DefineCustomStringVariable("pg_vault_tde.wallet_passphrase_command",
        "Shell command whose stdout is the wallet passphrase",
        "Analogous to ssl_passphrase_command.  Output is trimmed and "
        "used as passphrase.  Takes priority over wallet_passphrase_env "
        "and wallet_passphrase_file.  Never use in production without "
        "securing the command output.",
        &pg_vault_tde_wallet_passphrase_command, "",
        PGC_SUSET, GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /*
     * wallet_dev_mode_passphrase — literal plaintext passphrase for
     * development/CI only (v1.6).  IGNORED unless dev_mode = on.
     * Emits WARNING on every use.  NEVER set in production configs.
     */
    DefineCustomStringVariable("pg_vault_tde.wallet_dev_mode_passphrase",
        "Dev-mode inline passphrase (ONLY when dev_mode = on)",
        "Convenience for CI pipelines.  Never set in production.  "
        "Emits a WARNING on every use.  Ignored when dev_mode = off.",
        &pg_vault_tde_wallet_dev_mode_passphrase, "",
        PGC_SUSET, GUC_SUPERUSER_ONLY | GUC_NOT_IN_SAMPLE,
        NULL, NULL, NULL);

    /*
     * dev_mode — enable development conveniences (v1.6).
     * When false (default), wallet_dev_mode_passphrase is silently ignored.
     * When true, ereport(WARNING) fires on every dev passphrase read.
     */
    DefineCustomBoolVariable("pg_vault_tde.dev_mode",
        "Enable development-only conveniences (insecure in production)",
        "When true, pg_vault_tde.wallet_dev_mode_passphrase may be used "
        "as the wallet passphrase.  Always false in production.",
        &pg_vault_tde_dev_mode, false, PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

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
     * Object access hook: register the DEK for newly created encrypted_heap
     * tables BEFORE any data is inserted (critical for CTAS).  Fires after
     * the pg_class row is committed but before the SELECT data is populated.
     */
    prev_object_access_hook = object_access_hook;
    object_access_hook = tde_object_access_hook;

    audit_hook_ptr = tde_audit_handler;
    tde_audit(AUDIT_LOG_START, NULL, true);

    /*
     * Wire the mutable tde_methods copy: copy heapam's TableAmRoutine and
     * override the 6 data-touching callbacks with AES-256-GCM wrappers.
     * Must be done AFTER hooks are chained so that shmem (DEK store) is
     * initialised before any actual crypto is attempted.
     */
    pg_vault_tde_tam_init();

    /*
     * Register the custom WAL resource manager for encrypted TOAST chunks.
     * RegisterCustomRmgr() must run during shared_preload_libraries loading,
     * which is guaranteed here (_PG_init bails out early otherwise).  The rmgr
     * is always registered; the GUC pg_vault_tde.toast_custom_rmgr only gates
     * whether the write path actually uses it.
     */
    tde_rmgr_register();

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
