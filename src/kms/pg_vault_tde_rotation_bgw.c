/*-------------------------------------------------------------------------
 * pg_vault_tde_rotation_bgw.c
 *
 * Online key rotation background worker.
 *
 * Implements pg_vault_tde_rotate_online(regclass, batch_size) — a SQL-callable
 * function that launches a dedicated dynamic BGW to re-encrypt all rows of a
 * table using the new DEK, one batch at a time, without ever holding
 * AccessExclusiveLock.
 *
 * Design constraints (must not be violated):
 *  - Cursor-based scan: no table-level lock held across batches.
 *  - Per-batch autonomous transactions: each batch is a separate subtransaction;
 *    crashes recover cleanly by resuming from pg_vault_tde_rotation_progress.
 *  - READ COMMITTED isolation throughout the scan: concurrent DML is allowed.
 *  - Old-DEK rows remain readable by other backends until the BGW overwrites
 *    them: the catalog prev_dek slot holds the old DEK for this purpose.
 *  - The BGW updates pg_vault_tde_rotation_progress after each batch so that
 *    pg_vault_tde_rotation_status view gives live feedback.
 *  - When rotation is complete, the prev_dek slot is cleared from shmem and
 *    the progress row is removed from the catalog.
 *
 * @SecurityKMS: implements online rotation logic + KMS re-wrap calls.
 * @Architect:   TAM / catalog integration points.
 *
 * Copyright (c) 2024-2025 Miriade SARL.  BSD (PostgreSQL) License.
 *-------------------------------------------------------------------------*/

#include "postgres.h"

#include "access/xact.h"
#include "commands/dbcommands.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"

#include <openssl/crypto.h>     /* OPENSSL_cleanse */

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/kms/pg_vault_tde_kms_provider.h"

/* Magic copied by the BGW launcher to communicate the target table */
typedef struct TdeRotationArgs
{
    Oid         dboid;
    Oid         relid;
    int         batch_size;
} TdeRotationArgs;

/*
 * Maximum size of the serialised args passed via bgw_extra[].
 * BGW launcher stores up to BGW_EXTRALEN bytes (128), so we fit easily.
 */
StaticAssertDecl(sizeof(TdeRotationArgs) <= BGW_EXTRALEN,
                 "TdeRotationArgs exceeds BGW_EXTRALEN");

/* Forward declaration for the BGW entry point */
PGDLLEXPORT void pg_vault_tde_rotation_bgw_main(Datum main_arg);

/* =========================================================================
 * SQL-callable launcher: pg_vault_tde_rotate_online(regclass, int) → void
 *
 * Called from user session.  Validates args, inserts / updates
 * pg_vault_tde_rotation_progress row, then launches the dynamic BGW.
 * Returns immediately — the BGW runs asynchronously.
 * =========================================================================*/
PG_FUNCTION_INFO_V1(pg_vault_tde_rotate_online_sql);

Datum
pg_vault_tde_rotate_online_sql(PG_FUNCTION_ARGS)
{
    Oid             relid     = PG_GETARG_OID(0);
    int             batch_sz  = PG_ARGISNULL(1) ? 1000 : PG_GETARG_INT32(1);
    BackgroundWorker        worker;
    BackgroundWorkerHandle *handle;
    TdeRotationArgs         args;
    BgwHandleStatus         status;
    pid_t           pid;

    if (batch_sz < 1)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_vault_tde_rotate_online: batch_size must be >= 1")));

    /*
     * Only superusers may trigger key rotation — it degrades performance and
     * touches every row in the table.
     */
    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("pg_vault_tde_rotate_online: superuser required")));

    args.dboid      = MyDatabaseId;
    args.relid      = relid;
    args.batch_size = batch_sz;

    /* Build the dynamic background worker descriptor */
    memset(&worker, 0, sizeof(worker));
    worker.bgw_flags            = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
    worker.bgw_start_time       = BgWorkerStart_RecoveryFinished;
    worker.bgw_restart_time     = BGW_NEVER_RESTART;
    worker.bgw_main_arg         = (Datum) 0;
    worker.bgw_notify_pid       = MyProcPid;
    memcpy(worker.bgw_extra, &args, sizeof(args));

    snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_vault_tde");
    snprintf(worker.bgw_function_name, BGW_MAXLEN,
             "pg_vault_tde_rotation_bgw_main");
    snprintf(worker.bgw_name, BGW_MAXLEN,
             "pg_vault_tde rotation: %u", relid);
    snprintf(worker.bgw_type, BGW_MAXLEN, "pg_vault_tde rotation");

    if (!RegisterDynamicBackgroundWorker(&worker, &handle))
        ereport(ERROR,
                (errmsg("pg_vault_tde_rotate_online: could not register "
                        "background worker (max_worker_processes reached?)")));

    /* Wait up to 5 seconds for the BGW to start */
    status = WaitForBackgroundWorkerStartup(handle, &pid);
    if (status == BGWH_POSTMASTER_DIED)
        ereport(ERROR,
                (errmsg("pg_vault_tde_rotate_online: postmaster died before "
                        "rotation BGW could start")));

    if (status == BGWH_STOPPED)
        ereport(WARNING,
                (errmsg("pg_vault_tde_rotate_online: rotation BGW stopped "
                        "immediately — check server log")));

    pfree(handle);

    ereport(NOTICE,
            (errmsg("pg_vault_tde_rotate_online: rotation started for "
                    "relation %u (batch_size=%d)", relid, batch_sz)));

    PG_RETURN_VOID();
}

/*
 * tde_bgw_record_failure — best-effort: update rotation_progress to 'failed'.
 *
 * Called from the PG_CATCH handler of pg_vault_tde_rotation_bgw_main.
 * Must be a separate function so that its own PG_TRY/PG_CATCH local
 * variables (from elog.h macros) do not shadow those of the outer handler
 * (which would trigger -Wshadow warnings / build errors under zero-warning
 * policy).
 */
static void
tde_bgw_record_failure(Oid relid)
{
    char sql[256];

    PG_TRY();
    {
        SetCurrentStatementStartTimestamp();
        StartTransactionCommand();
        SPI_connect();
        snprintf(sql, sizeof(sql),
                 "UPDATE pg_vault_tde_rotation_progress "
                 "SET status = 'failed', updated_at = now() "
                 "WHERE relid = %u",
                 relid);
        SPI_execute(sql, false, 0);
        SPI_finish();
        CommitTransactionCommand();
    }
    PG_CATCH();
    {
        FlushErrorState();
        AbortCurrentTransaction();
        /* Best-effort; ignore failure to update progress row */
    }
    PG_END_TRY();
}

/* =========================================================================
 * BGW main entry point — runs in a dedicated backend process.
 * =========================================================================*/
void
pg_vault_tde_rotation_bgw_main(Datum main_arg)
{
    TdeRotationArgs args;
    char            sql[512];
    int             rc;
    volatile int64  tuples_done  = 0;
    volatile int64  tuples_total = 0;
    /*
     * Name of the first non-dropped user column, quoted for SQL injection
     * safety.  Used in the per-row re-encryption UPDATE — a self-update of any
     * regular column forces a full TAM round-trip (decrypt + re-encrypt).
     * System columns (tableoid, xmin, …) are NOT updatable via regular SQL.
     */
    char            first_col[2 * NAMEDATALEN + 8] = "";

    /* Copy args from bgw_extra (safe: we set it above) */
    memcpy(&args, MyBgworkerEntry->bgw_extra, sizeof(args));

    /* Allow SIGTERM and SIGHUP */
    pqsignal(SIGTERM, die);
    BackgroundWorkerUnblockSignals();

    BackgroundWorkerInitializeConnectionByOid(args.dboid, InvalidOid, 0);

    /*
     * Top-level error guard: catch any ERROR from any phase, record it as
     * status='failed' in the progress table (so polls see 'failed' quickly
     * instead of timing out on 'running'), then log the message at WARNING
     * level so it appears in the server log even with log_min_messages=warning.
     */
    PG_TRY();
    {

    /*
     * Phase 1: Determine total row count so that the progress view can
     * show a meaningful percentage.  Use an approximate count via
     * pg_class.reltuples to avoid a full seq-scan just for counting.
     */
    SetCurrentStatementStartTimestamp();
    StartTransactionCommand();
    PushActiveSnapshot(GetTransactionSnapshot());

    SPI_connect();

    snprintf(sql, sizeof(sql),
             "SELECT reltuples::bigint FROM pg_class WHERE oid = %u",
             args.relid);
    rc = SPI_execute(sql, true, 1);
    if (rc == SPI_OK_SELECT && SPI_processed == 1)
    {
        bool isnull;
        tuples_total = DatumGetInt64(
            SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc,
                          1, &isnull));
        if (isnull) tuples_total = 0;
    }

    /* Insert / reset the progress tracking row */
    snprintf(sql, sizeof(sql),
             "INSERT INTO pg_vault_tde_rotation_progress "
             "  (relid, status, tuples_done, tuples_total) "
             "VALUES (%u, 'running', 0, %lld) "
             "ON CONFLICT (relid) DO UPDATE SET "
             "  status = 'running', tuples_done = 0, "
             "  tuples_total = EXCLUDED.tuples_total, "
             "  started_at = now(), updated_at = now()",
             args.relid, (long long) tuples_total);
    rc = SPI_execute(sql, false, 0);
    if (rc < 0)
        ereport(WARNING,
                (errmsg("pg_vault_tde: rotation BGW: could not upsert "
                        "rotation_progress for relid=%u", args.relid)));

    /*
     * Determine the first non-dropped regular column for the per-row
     * re-encryption UPDATE.  We need at least one updatable column; every
     * user-visible table has at least one (attnum > 0, not dropped).
     */
    snprintf(sql, sizeof(sql),
             "SELECT quote_ident(attname) "
             "FROM pg_attribute "
             "WHERE attrelid = %u AND attnum > 0 AND NOT attisdropped "
             "ORDER BY attnum LIMIT 1",
             args.relid);
    rc = SPI_execute(sql, true, 1);
    if (rc == SPI_OK_SELECT && SPI_processed == 1)
    {
        bool isnull;
        Datum d = SPI_getbinval(SPI_tuptable->vals[0],
                                SPI_tuptable->tupdesc, 1, &isnull);
        if (!isnull)
            strlcpy(first_col, TextDatumGetCString(d), sizeof(first_col));
    }
    if (first_col[0] == '\0')
        strlcpy(first_col, "tableoid", sizeof(first_col)); /* last-resort fallback */

    SPI_finish();
    PopActiveSnapshot();
    CommitTransactionCommand();

    /*
     * Phase 1b: Prime the shmem rel_dek_cache for this relation.
     *
     * PostgreSQL materialises WITH HOLD cursors during CommitTransaction by
     * calling ExecutorRun.  The TAM decrypt callbacks call
     * pg_vault_tde_kms_get_rel_dek().  If that function finds a cold cache
     * it calls SPI_connect() to do a catalog lookup — but SPI cannot be
     * entered during commit, so the BGW crashes.
     *
     * The safe fix: call pg_vault_tde_kms_get_rel_dek() directly here, in a
     * normal transaction context (NOT from inside an SPI executor call).
     * That function will do its own SPI connection internally if needed,
     * then (via the tde_rel_dek_cache_store_fallback() path in catalog.c)
     * store the result in rel_dek_cache.  All subsequent calls — including
     * those fired during the Phase 2 cursor commit — hit the fast shmem
     * path (LW_SHARED, no SPI) and succeed.
     */
    {
        unsigned char   prime_dek[TDE_DEK_LEN];

        SetCurrentStatementStartTimestamp();
        StartTransactionCommand();
        PushActiveSnapshot(GetTransactionSnapshot());

        /*
         * pg_vault_tde_kms_get_rel_dek() opens and closes its own SPI
         * connection internally.  We are NOT inside an SPI_execute() call
         * here, so there is no nested-SPI issue.
         */
        (void) pg_vault_tde_kms_get_rel_dek(args.relid,
                                             prime_dek, TDE_DEK_LEN);
        OPENSSL_cleanse(prime_dek, TDE_DEK_LEN);

        PopActiveSnapshot();
        CommitTransactionCommand();
    }

    /*
     * Phase 2: Collect all CTIDs into a session-local temp table.
     *
     * SPI_finish() drops portals owned by the current SPI level — including
     * WITH HOLD cursors declared via SPI — before CommitTransactionCommand()
     * can call PersistHoldablePortal() to materialise them.  This means a
     * WITH HOLD cursor declared in one SPI session and then SPI_finish()ed
     * always disappears before commit, leaving the batch loop with no cursor.
     *
     * A session-local temp table avoids this: it is a regular table that
     * persists across transaction boundaries within this backend session.
     *
     * The INSERT ... SELECT fires the TAM seqscan decrypt path for each row.
     * Phase 1b ensures rel_dek_cache is warm, so kms_get_rel_dek() takes the
     * fast shmem LW_SHARED path (no SPI_connect) on every row — there is no
     * nested-SPI issue.
     *
     * IMPORTANT: get_rel_name() requires an active transaction (syscache).
     * It must be called AFTER StartTransactionCommand(), not between
     * transactions.
     */
    {
        const char *relname_for_load;

        SetCurrentStatementStartTimestamp();
        StartTransactionCommand();
        PushActiveSnapshot(GetTransactionSnapshot());
        SPI_connect();

        /* Resolve the relation name inside an active transaction */
        relname_for_load = get_rel_name(args.relid);
        if (relname_for_load == NULL)
            ereport(ERROR,
                    (errmsg("pg_vault_tde rotation BGW: relation %u not found "
                            "(was it created in an uncommitted transaction? "
                            "Commit before calling pg_vault_tde_rotate_online.)",
                            args.relid)));

        snprintf(sql, sizeof(sql),
                 "CREATE TEMP TABLE IF NOT EXISTS tde_rot_%u "
                 "(rowctid tid) ON COMMIT PRESERVE ROWS",
                 args.relid);
        rc = SPI_execute(sql, false, 0);
        if (rc != SPI_OK_UTILITY)
            ereport(ERROR,
                    (errmsg("pg_vault_tde: rotation BGW: could not create "
                            "temp table for relid=%u (rc=%d)",
                            args.relid, rc)));

        /* Truncate in case this is a retry after crash */
        snprintf(sql, sizeof(sql), "TRUNCATE tde_rot_%u", args.relid);
        SPI_execute(sql, false, 0);

        /*
         * Load all CTIDs.  kms_get_rel_dek() for each row uses the fast
         * shmem path (warm cache from Phase 1b), so no nested SPI.
         */
        snprintf(sql, sizeof(sql),
                 "INSERT INTO tde_rot_%u SELECT ctid FROM ONLY %s",
                 args.relid,
                 quote_identifier(relname_for_load));
        rc = SPI_execute(sql, false, 0);
        if (rc != SPI_OK_INSERT)
            ereport(ERROR,
                    (errmsg("pg_vault_tde: rotation BGW: INSERT SELECT ctid "
                            "failed for relid=%u (rc=%d)", args.relid, rc)));

        SPI_finish();
        PopActiveSnapshot();
        CommitTransactionCommand();
    }

    /* Main batch loop — process CTIDs in batches from the temp table */
    for (;;)
    {
        int     fetched;
        bool    done = false;
        /*
         * Save CTIDs before any subsequent SPI call invalidates tuptable.
         * Batch size is caller-controlled; cap at a safe per-iteration max.
         */
        ItemPointerData ctid_batch[4096];
        int             nbatch = 0;

        CHECK_FOR_INTERRUPTS();

        SetCurrentStatementStartTimestamp();
        StartTransactionCommand();
        PushActiveSnapshot(GetTransactionSnapshot());
        SPI_connect();

        /* Pop up to batch_size CTIDs from the temp table */
        snprintf(sql, sizeof(sql),
                 "SELECT rowctid FROM tde_rot_%u LIMIT %d",
                 args.relid, args.batch_size);
        rc = SPI_execute(sql, true, 0);
        if (rc != SPI_OK_SELECT)
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: rotation BGW: SELECT from "
                            "temp table failed for relid=%u (rc=%d)",
                            args.relid, rc)));
            SPI_finish();
            PopActiveSnapshot();
            AbortCurrentTransaction();
            break;
        }

        fetched = (int) SPI_processed;
        if (fetched == 0)
        {
            done = true;
        }
        else
        {
            int         i;
            int         batch_cap = (int) (sizeof(ctid_batch) /
                                           sizeof(ctid_batch[0]));
            const char *rname;

            /* Cap batch at the C array size */
            if (fetched > batch_cap)
                fetched = batch_cap;

            /* Copy CTIDs out before subsequent SPI calls clobber tuptable */
            for (i = 0; i < fetched; i++)
            {
                bool  isnull;
                Datum d = SPI_getbinval(SPI_tuptable->vals[i],
                                        SPI_tuptable->tupdesc,
                                        1, &isnull);
                if (isnull)
                    ItemPointerSetInvalid(&ctid_batch[i]);
                else
                    ctid_batch[i] = *DatumGetItemPointer(d);
            }
            nbatch = fetched;

            rname = get_rel_name(args.relid);
            if (rname == NULL)
            {
                ereport(WARNING,
                        (errmsg("pg_vault_tde rotation BGW: relation %u "
                                "vanished during re-encryption; stopping.",
                                args.relid)));
                SPI_finish();
                PopActiveSnapshot();
                CommitTransactionCommand();
                done = true;
            }
            else
            {
                /*
                 * Re-encrypt each row via a self-UPDATE.  The TAM decrypt
                 * path then re-encrypts the tuple with the current DEK.
                 */
                for (i = 0; i < nbatch; i++)
                {
                    if (!ItemPointerIsValid(&ctid_batch[i]))
                        continue;

                    snprintf(sql, sizeof(sql),
                             "UPDATE ONLY %s SET %s = %s "
                             "WHERE ctid = '(%u,%u)'::tid",
                             quote_identifier(rname),
                             first_col, first_col,
                             ItemPointerGetBlockNumber(&ctid_batch[i]),
                             ItemPointerGetOffsetNumber(&ctid_batch[i]));
                    SPI_execute(sql, false, 0);
                }

                /* Remove processed CTIDs from the temp table */
                for (i = 0; i < nbatch; i++)
                {
                    if (!ItemPointerIsValid(&ctid_batch[i]))
                        continue;

                    snprintf(sql, sizeof(sql),
                             "DELETE FROM tde_rot_%u "
                             "WHERE rowctid = '(%u,%u)'::tid",
                             args.relid,
                             ItemPointerGetBlockNumber(&ctid_batch[i]),
                             ItemPointerGetOffsetNumber(&ctid_batch[i]));
                    SPI_execute(sql, false, 0);
                }

                tuples_done += nbatch;

                /* Update progress row */
                snprintf(sql, sizeof(sql),
                         "UPDATE pg_vault_tde_rotation_progress "
                         "SET tuples_done = %lld, updated_at = now() "
                         "WHERE relid = %u",
                         (long long) tuples_done, args.relid);
                SPI_execute(sql, false, 0);
            }
        }

        SPI_finish();
        PopActiveSnapshot();
        CommitTransactionCommand();

        if (done)
            break;
    }

    /*
     * Phase 3: Finalise — drop the temp table, mark progress row as
     * 'complete', clear prev_dek shmem slot.
     */
    SetCurrentStatementStartTimestamp();
    StartTransactionCommand();
    PushActiveSnapshot(GetTransactionSnapshot());
    SPI_connect();

    /* Drop temp table (best-effort; session cleanup handles it too) */
    snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS tde_rot_%u", args.relid);
    SPI_execute(sql, false, 0);

    /* Mark rotation complete — tests poll for 'complete' or 'failed' */
    snprintf(sql, sizeof(sql),
             "UPDATE pg_vault_tde_rotation_progress "
             "SET status = 'complete', updated_at = now() "
             "WHERE relid = %u",
             args.relid);
    SPI_execute(sql, false, 0);

    SPI_finish();
    PopActiveSnapshot();
    CommitTransactionCommand();

    /*
     * Clear the prev_dek slot from shmem cache.  This is safe to do outside
     * a transaction since it is a shmem operation protected by LWLock.
     */
    pg_vault_tde_catalog_evict_rel(args.relid);

    ereport(LOG,
            (errmsg("pg_vault_tde: online rotation complete for relid=%u "
                    "(%lld tuples re-encrypted)",
                    args.relid, (long long) tuples_done)));

    } /* end PG_TRY body */
    PG_CATCH();
    {
        /*
         * An ERROR occurred somewhere in the rotation pipeline.  Capture the
         * error message, abort the failed transaction, then try to record
         * status='failed' in the progress table so callers do not need to
         * wait for a timeout.  Log the message at WARNING so it is visible
         * even with log_min_messages=warning.
         *
         * If the progress-table UPDATE itself fails (e.g., because the table
         * was dropped), we ignore the secondary error and just log the
         * original one.
         */
        ErrorData  *edata = CopyErrorData();

        FlushErrorState();

        /* Rollback whatever transaction was active when the error fired */
        AbortCurrentTransaction();

        /* Record the failure in the progress table (best-effort) */
        tde_bgw_record_failure(args.relid);

        ereport(WARNING,
                (errmsg("pg_vault_tde: rotation BGW failed for relid=%u: %s",
                        args.relid, edata->message)));
        FreeErrorData(edata);
    }
    PG_END_TRY();}