/*
 * pg_vault_tde_preload_bgw.c — warm the shmem DEK cache at startup (v1.7)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * WHY A WORKER PER DATABASE:
 * -------------------------
 * Everything a preload needs is per-database and unreachable from anywhere
 * else.  pg_vault_tde_catalog is an ordinary table that CREATE EXTENSION
 * creates separately in each database, so only a backend connected to that
 * database can read its wrapped DEKs; the local wallet holding the KEK to
 * unwrap them lives at /var/lib/pg_vault_tde/<db_oid>/wallet.p12 for the same
 * reason.  And a background worker may call
 * BackgroundWorkerInitializeConnection*() exactly once in its life — there is
 * no supported way to move an open backend to another database.
 *
 * So: a launcher that connects to no database, reads the shared pg_database
 * catalog, and starts one short-lived worker per database, one at a time.
 * Sequential rather than parallel because this competes with real startup
 * traffic for max_worker_processes and for the KMS, and a warm cache is worth
 * nothing if getting it costs the cluster its first minute.
 *
 * Once connected, the worker needs no new API: MyDatabaseId is correct, so
 * pg_vault_tde_kms_get_rel_dek() reads the catalog row, unwraps through the
 * active provider, and stores the result under the right (dbid, relid) key.
 *
 * WHAT IT DELIBERATELY DOES NOT DO:
 * ---------------------------------
 * It does not block startup.  The postmaster accepts connections while this
 * runs, so a slow or unreachable KMS costs a cold cache, never availability.
 * It also stops rather than pushing: at pg_vault_tde.max_encrypted_relations
 * there is nothing to gain from unwrapping keys the cache will refuse, and
 * the budget belongs to every database, not to whichever one is preloaded
 * first.
 *
 * OWNERSHIP: @SecurityKMS
 */

#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "access/table.h"
#include "access/tableam.h"      /* TableScanDesc, table_beginscan_catalog */
#include "access/heapam.h"       /* heap_getnext */
#include "access/genam.h"
#include "access/xact.h"
#include "libpq/pqsignal.h"      /* pqsignal */
#include "tcop/tcopprot.h"       /* die() */
#include "catalog/pg_database.h"
#include "commands/dbcommands.h" /* get_database_name */
#include "commands/extension.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"

#include <openssl/crypto.h>

#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_catalog_d.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/include/pg_vault_tde_kms.h"

PGDLLEXPORT void pg_vault_tde_preload_launcher_main(Datum main_arg);
PGDLLEXPORT void pg_vault_tde_preload_worker_main(Datum main_arg);

/* Passed to each per-database worker through bgw_extra. */
typedef struct TdePreloadArgs
{
    Oid     dboid;
} TdePreloadArgs;


/* -------------------------------------------------------------------------
 * tde_preload_one_database — load every DEK this database has a catalog row
 * for, stopping at the cluster-wide cache budget.
 *
 * Runs inside a transaction with an active snapshot.  Returns the number of
 * DEKs loaded; *stopped_early is set when the budget or a KMS failure ended
 * the pass before the catalog did.
 * -------------------------------------------------------------------------*/
static int
tde_preload_one_database(bool *stopped_early)
{
    Oid           ext_oid;
    Oid           ext_ns;
    Oid           catalog_oid;
    Relation      catalog_rel;
    TupleDesc     tupdesc;
    SysScanDesc   scan;
    HeapTuple     tuple;
    int           loaded = 0;
    int           streak = 0;   /* consecutive unwrap failures */

    *stopped_early = false;

    /*
     * No extension here, or an older one without the catalog: nothing to warm.
     * Not an error — most clusters have databases that do not use TDE at all,
     * and the launcher cannot tell which without connecting.
     */
    ext_oid = get_extension_oid(pg_vault_tde_extension_name, true);
    if (!OidIsValid(ext_oid))
        return 0;

    ext_ns = get_extension_schema(ext_oid);
    if (!OidIsValid(ext_ns))
        return 0;

    catalog_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);
    if (!OidIsValid(catalog_oid))
        return 0;

    catalog_rel = table_open(catalog_oid, AccessShareLock);
    tupdesc     = RelationGetDescr(catalog_rel);

    scan = systable_beginscan(catalog_rel, InvalidOid, false, NULL, 0, NULL);

    while (HeapTupleIsValid(tuple = systable_getnext(scan)))
    {
        unsigned char dek[TDE_DEK_LEN];
        Datum         d;
        bool          isnull;
        Oid           relid;

        CHECK_FOR_INTERRUPTS();

        /*
         * Stop at the budget rather than through it.  Past this point
         * tde_rel_dek_cache_store() declines every insert, so each further
         * relation would buy a KMS round-trip and throw the result away — and
         * the budget is shared with every other database, including the ones
         * this launcher has not reached yet.
         */
        if (pg_vault_tde_catalog_cache_entries() >=
            pg_vault_tde_max_encrypted_relations)
        {
            *stopped_early = true;
            ereport(WARNING,
                    errmsg("pg_vault_tde: preload stopped at the DEK cache "
                           "budget of %d after %d key(s) in database \"%s\"",
                           pg_vault_tde_max_encrypted_relations, loaded,
                           get_database_name(MyDatabaseId)),
                    errhint("The budget is shared by every database. Raise "
                            "pg_vault_tde.max_encrypted_relations and restart "
                            "to warm the rest."));
            break;
        }

        d = heap_getattr(tuple, Anum_pg_vault_tde_relid, tupdesc, &isnull);
        if (isnull)
            continue;
        relid = DatumGetObjectId(d);

        /* The relation may have been dropped since its row was written. */
        if (!OidIsValid(relid) || get_rel_name(relid) == NULL)
            continue;

        /*
         * Everything the warm-up needs already happens here: catalog read,
         * provider unwrap, and a store under the correct (dbid, relid) key,
         * because MyDatabaseId is this database.
         */
        if (!pg_vault_tde_kms_get_rel_dek(relid, dek, TDE_DEK_LEN))
        {
            /*
             * Give up once the failures stop looking transient.
             *
             * They are counted consecutively because that is the question
             * actually being asked: a missing passphrase fails every relation
             * and trips the limit straight away, while a one-off failure
             * should not cost the whole warm-up — the next success clears the
             * streak.  Grinding on regardless would fill the log with one
             * provider WARNING per relation while the server is still
             * starting.
             *
             * Worth noting this is not only about remote KMS providers.  The
             * local provider re-derives the KEK from the wallet file on every
             * unwrap rather than caching it, deliberately, to keep the KEK out
             * of process memory between operations — so a preload reopens the
             * wallet once per relation, and a wallet on NFS or SMB fails the
             * same transient way a network KMS does.
             */
            if (++streak > pg_vault_tde_preload_max_failures)
            {
                *stopped_early = true;
                ereport(WARNING,
                        errmsg("pg_vault_tde: preload gave up on database "
                               "\"%s\" after %d consecutive unwrap failure(s), "
                               "having loaded %d key(s)",
                               get_database_name(MyDatabaseId), streak, loaded),
                        errhint("The KMS must be usable without an interactive "
                                "unlock — configure "
                                "pg_vault_tde.wallet_passphrase_command, "
                                "pg_vault_tde.wallet_passphrase_env or the "
                                "pkcs11 PIN variable. Raise "
                                "pg_vault_tde.preload_max_failures to ride out "
                                "a flaky remote KMS. Keys are still loaded on "
                                "first access."));
                break;
            }
            continue;
        }

        streak = 0;         /* progress: the failures were not systemic */
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        loaded++;
    }

    systable_endscan(scan);
    table_close(catalog_rel, AccessShareLock);

    return loaded;
}


/* -------------------------------------------------------------------------
 * pg_vault_tde_preload_worker_main — per-database worker entry point
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_preload_worker_main(Datum main_arg)
{
    TdePreloadArgs args;

    /* Read after PG_END_TRY, so they must survive a longjmp. */
    volatile int   loaded  = 0;
    volatile bool  stopped = false;

    memcpy(&args, MyBgworkerEntry->bgw_extra, sizeof(args));

    pqsignal(SIGTERM, die);
    BackgroundWorkerUnblockSignals();

    BackgroundWorkerInitializeConnectionByOid(args.dboid, InvalidOid, 0);

    /*
     * One failing database must not take the launcher down with it, and the
     * launcher cannot catch an ERROR raised over here.
     */
    PG_TRY();
    {
        SetCurrentStatementStartTimestamp();
        StartTransactionCommand();
        PushActiveSnapshot(GetTransactionSnapshot());

        /*
         * preload_keys is read here, not by the launcher: it is PGC_SUSET so
         * it can be scoped with ALTER DATABASE SET, and a per-database value
         * only resolves once connected.  The connection is the cheap part —
         * what this skips is the catalog scan and one KMS round-trip per
         * relation.
         */
        if (pg_vault_tde_preload_keys)
        {
            bool stopped_here = false;

            loaded  = tde_preload_one_database(&stopped_here);
            stopped = stopped_here;
        }

        PopActiveSnapshot();
        CommitTransactionCommand();
    }
    PG_CATCH();
    {
        ErrorData *edata = CopyErrorData();

        FlushErrorState();
        AbortCurrentTransaction();

        ereport(WARNING,
                errmsg("pg_vault_tde: preload failed for database %u: %s",
                       args.dboid, edata->message));
        FreeErrorData(edata);
        proc_exit(0);
    }
    PG_END_TRY();

    if (loaded > 0 || stopped)
        ereport(LOG,
                errmsg("pg_vault_tde: preloaded %d DEK(s) for database %u%s",
                       loaded, args.dboid,
                       stopped ? " (stopped early)" : ""));

    proc_exit(0);
}


/* -------------------------------------------------------------------------
 * tde_preload_database_list — OIDs of every connectable database
 *
 * pg_database is a shared catalog, so this works on the launcher's
 * no-database connection.  The list is copied into the caller's context
 * because the scan's memory goes away with the transaction.
 * -------------------------------------------------------------------------*/
static List *
tde_preload_database_list(void)
{
    Relation     rel;
    TableScanDesc scan;
    HeapTuple    tup;
    List        *dboids = NIL;
    MemoryContext caller_ctx = CurrentMemoryContext;

    StartTransactionCommand();

    rel  = table_open(DatabaseRelationId, AccessShareLock);
    scan = table_beginscan_catalog(rel, 0, NULL);

    while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
    {
        Form_pg_database pgdb = (Form_pg_database) GETSTRUCT(tup);
        MemoryContext    old;

        if (!pgdb->datallowconn)
            continue;

        old = MemoryContextSwitchTo(caller_ctx);
        dboids = lappend_oid(dboids, pgdb->oid);
        MemoryContextSwitchTo(old);
    }

    table_endscan(scan);
    table_close(rel, AccessShareLock);

    CommitTransactionCommand();

    return dboids;
}


/* -------------------------------------------------------------------------
 * pg_vault_tde_preload_launcher_main — launcher entry point
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_preload_launcher_main(Datum main_arg)
{
    List         *dboids;
    ListCell     *lc;
    MemoryContext ctx;

    pqsignal(SIGTERM, die);
    BackgroundWorkerUnblockSignals();

    /* No database: enough to read the shared pg_database catalog. */
    BackgroundWorkerInitializeConnection(NULL, NULL, 0);

    ctx = AllocSetContextCreate(TopMemoryContext, "tde preload launcher",
                                ALLOCSET_DEFAULT_SIZES);
    MemoryContextSwitchTo(ctx);

    dboids = tde_preload_database_list();

    foreach(lc, dboids)
    {
        Oid                     dboid = lfirst_oid(lc);
        BackgroundWorker        worker;
        BackgroundWorkerHandle *handle;
        TdePreloadArgs          args;
        pid_t                   pid;

        CHECK_FOR_INTERRUPTS();

        args.dboid = dboid;

        memset(&worker, 0, sizeof(worker));
        worker.bgw_flags        = BGWORKER_SHMEM_ACCESS |
                                  BGWORKER_BACKEND_DATABASE_CONNECTION;
        worker.bgw_start_time   = BgWorkerStart_RecoveryFinished;
        worker.bgw_restart_time = BGW_NEVER_RESTART;
        worker.bgw_main_arg     = (Datum) 0;
        worker.bgw_notify_pid   = MyProcPid;
        memcpy(worker.bgw_extra, &args, sizeof(args));

        snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_vault_tde");
        snprintf(worker.bgw_function_name, BGW_MAXLEN,
                 "pg_vault_tde_preload_worker_main");
        snprintf(worker.bgw_name, BGW_MAXLEN,
                 "pg_vault_tde preload: db %u", dboid);
        snprintf(worker.bgw_type, BGW_MAXLEN, "pg_vault_tde preload");

        /*
         * One at a time.  Running every database at once would multiply the
         * KMS round-trips against a server that is still starting up, and
         * would spend max_worker_processes that real work needs more.  A
         * refusal here is not fatal: those databases simply stay cold.
         */
        if (!RegisterDynamicBackgroundWorker(&worker, &handle))
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: could not start the preload worker "
                           "for database %u", dboid),
                    errhint("max_worker_processes may be exhausted; the "
                            "remaining databases are left to load their keys "
                            "on first access."));
            break;
        }

        if (WaitForBackgroundWorkerStartup(handle, &pid) == BGWH_POSTMASTER_DIED)
            proc_exit(1);

        WaitForBackgroundWorkerShutdown(handle);
    }

    ereport(LOG,
            errmsg("pg_vault_tde: DEK preload finished for %d database(s)",
                   list_length(dboids)));

    proc_exit(0);
}


/* -------------------------------------------------------------------------
 * pg_vault_tde_register_preload_bgw — called from _PG_init
 *
 * Must run while shared_preload_libraries is being processed: after the
 * postmaster has forked it is too late to register a static worker.  The
 * launcher is registered whenever the GUC is on at postmaster level; a
 * database that turned preload_keys on for itself alone is still visited,
 * because the worker reads the setting after connecting.
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_register_preload_bgw(void)
{
    BackgroundWorker worker;

    memset(&worker, 0, sizeof(worker));

    snprintf(worker.bgw_name, BGW_MAXLEN, "pg_vault_tde preload launcher");
    snprintf(worker.bgw_type, BGW_MAXLEN, "pg_vault_tde preload");
    snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_vault_tde");
    snprintf(worker.bgw_function_name, BGW_MAXLEN,
             "pg_vault_tde_preload_launcher_main");

    worker.bgw_flags        = BGWORKER_SHMEM_ACCESS |
                              BGWORKER_BACKEND_DATABASE_CONNECTION;
    worker.bgw_start_time   = BgWorkerStart_RecoveryFinished;
    worker.bgw_restart_time = BGW_NEVER_RESTART;   /* a warm-up runs once */
    worker.bgw_main_arg     = (Datum) 0;
    worker.bgw_notify_pid   = 0;

    RegisterBackgroundWorker(&worker);
}
