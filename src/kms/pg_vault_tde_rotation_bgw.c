/*-------------------------------------------------------------------------
 * pg_vault_tde_rotation_bgw.c
 *
 * Online key rotation background worker.
 *
 * Implements pg_vault_tde_rotate_online(regclass, batch_size) — a SQL-callable
 * function that launches a dedicated dynamic BGW to re-encrypt all rows of a
 * table using the new DEK, without ever holding AccessExclusiveLock.
 *
 * Design (v2 — no SPI):
 *  - Direct heap access (table_open + systable_beginscan + CatalogTupleInsert/
 *    Update) for all pg_vault_tde_rotation_progress operations.  No SPI.
 *  - table_open + table_beginscan + table_tuple_update for re-encryption,
 *    mirroring pg_vault_tde_reencrypt_table() in pg_vault_tde_tam.c.
 *  - Single transaction for the full scan: RowExclusiveLock is compatible
 *    with concurrent reads, inserts, updates, and deletes.
 *  - Old-DEK rows remain readable until overwritten because the shmem
 *    prev_dek slot is populated for this relation during the grace period.
 *  - tde_btree indexes are rebuilt after the scan (AES-256-SIV keys are
 *    DEK-bound; stale ciphertexts silently break equality lookups).
 *  - When rotation is complete the shmem cache entry is evicted so the
 *    next access reloads the new wrapped DEK via the full unwrap path.
 *
 * @SecurityKMS: online rotation logic + KMS re-wrap calls.
 * @Architect:   TAM / catalog integration points.
 *
 * Copyright (c) 2024-2025 Miriade SARL.  BSD (PostgreSQL) License.
 *-------------------------------------------------------------------------*/

#include "postgres.h"

#include "access/genam.h"           /* systable_beginscan, SysScanDesc */
#include "access/heapam.h"          /* heap_form_tuple, heap_getattr */
#include "access/htup_details.h"    /* GETSTRUCT */
#include "access/tableam.h"         /* table_open/close, table_tuple_update */
#include "access/xact.h"
#include "catalog/index.h"          /* reindex_index, ReindexParams */
#include "catalog/indexing.h"       /* CatalogTupleInsert, CatalogTupleUpdate */
#include "commands/extension.h"     /* get_extension_oid, get_extension_schema */
#include "catalog/pg_class.h"       /* Form_pg_class */
#include "commands/defrem.h"        /* get_index_am_oid */
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"           /* die */
#include "utils/builtins.h"
#include "utils/fmgroids.h"         /* F_OIDEQ */
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"         /* SearchSysCache1, RELOID */
#include "utils/timestamp.h"        /* GetCurrentTransactionStartTimestamp */

#include <openssl/crypto.h>         /* OPENSSL_cleanse */

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/kms/pg_vault_tde_kms_provider.h"
#include "src/include/pg_vault_tde_tam.h"

/*
 * Column numbers in pg_vault_tde_rotation_progress (1-based, matches DDL):
 *   relid, status, tuples_done, tuples_total, started_at, updated_at
 */
#define Anum_rot_prog_relid         1
#define Anum_rot_prog_status        2
#define Anum_rot_prog_tuples_done   3
#define Anum_rot_prog_tuples_total  4
#define Anum_rot_prog_started_at    5
#define Anum_rot_prog_updated_at    6
#define Natts_rot_prog              6

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

/* =========================================================================
 * tde_progress_upsert — insert or update a pg_vault_tde_rotation_progress row.
 *
 * Uses direct heap access (table_open + systable_beginscan + CatalogTuple*)
 * instead of SPI so this can be called safely from any transaction context,
 * including the BGW's per-phase transactions.
 *
 * Must be called with an active transaction (requires syscache and a snapshot).
 *
 * Must be a separate function from pg_vault_tde_rotation_bgw_main so that the
 * PG_TRY/PG_CATCH local variables declared by elog.h macros in
 * tde_bgw_record_failure do not shadow those of the outer handler (which would
 * trigger -Wshadow errors under the zero-warning build policy).
 * =========================================================================*/
static void
tde_progress_upsert(Oid relid, const char *status,
                    int64 tuples_done, int64 tuples_total)
{
    Oid         ext_ns;
    Oid         prog_oid;
    Oid         idx_oid;
    Relation    prog_rel;
    TupleDesc   tdesc;
    ScanKeyData skey;
    SysScanDesc scan;
    HeapTuple   old_tup;
    HeapTuple   new_tup;
    Datum       values[Natts_rot_prog];
    bool        nulls[Natts_rot_prog];
    TimestampTz now = GetCurrentTransactionStartTimestamp();

    ext_ns   = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
    prog_oid = get_relname_relid("pg_vault_tde_rotation_progress", ext_ns);
    if (!OidIsValid(prog_oid))
        return;                     /* extension not yet fully installed */

    prog_rel = table_open(prog_oid, RowExclusiveLock);
    tdesc    = RelationGetDescr(prog_rel);

    memset(nulls, false, sizeof(nulls));
    values[Anum_rot_prog_relid        - 1] = ObjectIdGetDatum(relid);
    values[Anum_rot_prog_status       - 1] = CStringGetTextDatum(status);
    values[Anum_rot_prog_tuples_done  - 1] = Int64GetDatum(tuples_done);
    values[Anum_rot_prog_tuples_total - 1] = Int64GetDatum(tuples_total);
    values[Anum_rot_prog_updated_at   - 1] = TimestampTzGetDatum(now);

    idx_oid = get_relname_relid("pg_vault_tde_rotation_progress_pkey", ext_ns);

    ScanKeyInit(&skey, Anum_rot_prog_relid,
                BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));
    scan = systable_beginscan(prog_rel, idx_oid, OidIsValid(idx_oid),
                              GetTransactionSnapshot(), 1, &skey);
    old_tup = systable_getnext(scan);

    if (HeapTupleIsValid(old_tup))
    {
        bool old_null;

        /* Preserve the original started_at timestamp on updates */
        values[Anum_rot_prog_started_at - 1] =
            heap_getattr(old_tup, Anum_rot_prog_started_at, tdesc, &old_null);
        if (old_null)
            nulls[Anum_rot_prog_started_at - 1] = true;

        new_tup = heap_form_tuple(tdesc, values, nulls);
        CatalogTupleUpdate(prog_rel, &old_tup->t_self, new_tup);
    }
    else
    {
        /* First insert: set started_at = now */
        values[Anum_rot_prog_started_at - 1] = TimestampTzGetDatum(now);
        new_tup = heap_form_tuple(tdesc, values, nulls);
        CatalogTupleInsert(prog_rel, new_tup);
    }

    systable_endscan(scan);
    heap_freetuple(new_tup);
    table_close(prog_rel, RowExclusiveLock);
}

/*
 * tde_bgw_record_failure — best-effort: mark rotation as 'failed'.
 *
 * Separate function to avoid -Wshadow on PG_TRY/PG_CATCH local variables
 * (see comment above tde_progress_upsert).
 */
static void
tde_bgw_record_failure(Oid relid)
{
    PG_TRY();
    {
        SetCurrentStatementStartTimestamp();
        StartTransactionCommand();
        PushActiveSnapshot(GetTransactionSnapshot());
        tde_progress_upsert(relid, "failed", 0, 0);
        PopActiveSnapshot();
        CommitTransactionCommand();
    }
    PG_CATCH();
    {
        FlushErrorState();
        AbortCurrentTransaction();
        /* Best-effort; ignore secondary failure */
    }
    PG_END_TRY();
}

/* =========================================================================
 * BGW main entry point — runs in a dedicated backend process.
 *
 * Three phases, no SPI:
 *   Phase 1 — read reltuples from syscache; upsert progress row as 'running'.
 *   Phase 2 — re-encrypt all live rows via table_beginscan + table_tuple_update
 *              (mirrors pg_vault_tde_reencrypt_table in pg_vault_tde_tam.c);
 *              rebuild tde_btree indexes (SIV keys are DEK-bound).
 *   Phase 3 — update progress row to 'complete'; evict shmem DEK cache entry.
 * =========================================================================*/
void
pg_vault_tde_rotation_bgw_main(Datum main_arg)
{
    TdeRotationArgs args;
    int64           tuples_done  = 0;
    int64           tuples_total = 0;

    memcpy(&args, MyBgworkerEntry->bgw_extra, sizeof(args));

    pqsignal(SIGTERM, die);
    BackgroundWorkerUnblockSignals();

    BackgroundWorkerInitializeConnectionByOid(args.dboid, InvalidOid, 0);

    /*
     * Top-level error guard: on any ERROR, abort the active transaction,
     * record status='failed' in the progress table, and log at WARNING so
     * callers polling pg_vault_tde_rotation_status see 'failed' promptly
     * rather than timing out on 'running'.
     */
    PG_TRY();
    {

    /* -----------------------------------------------------------------------
     * Phase 1: Approximate row count via pg_class syscache.
     * Avoids a full sequential scan just for an estimate shown in the
     * monitoring view.  reltuples = -1 means the table has never been
     * ANALYZEd; treat that as 0.
     * --------------------------------------------------------------------- */
    SetCurrentStatementStartTimestamp();
    StartTransactionCommand();
    PushActiveSnapshot(GetTransactionSnapshot());

    {
        HeapTuple     pg_class_tup;
        Form_pg_class pg_class_form;

        pg_class_tup = SearchSysCache1(RELOID, ObjectIdGetDatum(args.relid));
        if (HeapTupleIsValid(pg_class_tup))
        {
            pg_class_form = (Form_pg_class) GETSTRUCT(pg_class_tup);
            tuples_total  = (int64) pg_class_form->reltuples;
            if (tuples_total < 0) 
                tuples_total = 0;   /* -1 = unanalyzed */
            ReleaseSysCache(pg_class_tup);
        }
    }

    tde_progress_upsert(args.relid, "running", 0, tuples_total);

    PopActiveSnapshot();
    CommitTransactionCommand();

    /* -----------------------------------------------------------------------
     * Phase 2: Re-encrypt all live rows.
     *
     * table_tuple_update dispatches through the encrypted_heap TAM callback
     * (pg_vault_tde_tuple_update), which decrypts the old row, re-encrypts
     * it with the current DEK, and writes a new heap version. 
     *
     * RowExclusiveLock is compatible with concurrent reads, inserts, updates,
     * and deletes — only DDL (AccessExclusiveLock) will wait.
     *
     * --------------------------------------------------------------------- */
    {
        SetCurrentStatementStartTimestamp();
        StartTransactionCommand();
        PushActiveSnapshot(GetTransactionSnapshot());

        if (get_rel_name(args.relid) == NULL)
            ereport(ERROR,
                    (errmsg("pg_vault_tde rotation BGW: relation %u not found; "
                            "commit the CREATE TABLE before calling "
                            "pg_vault_tde_rotate_online()",
                            args.relid)));

        if (get_rel_relkind(args.relid) == RELKIND_INDEX)
        {
            Oid             tde_btree_amoid = get_index_am_oid("tde_btree", true);
            ReindexParams   reindex_params  = {0};

            /* Only tde_btree indexes have a DEK entry — validate before touching shmem. */
            if (!OidIsValid(tde_btree_amoid) ||
                get_rel_relam(args.relid) != tde_btree_amoid)
                ereport(ERROR,
                        (errcode(ERRCODE_WRONG_OBJECT_TYPE),
                         errmsg("pg_vault_tde_rotate_online: index %u is not a "
                                "tde_btree index — only tde_btree indexes "
                                "have DEK entries", args.relid)));

            pg_vault_tde_catalog_zero_rel_dek(args.relid);
            pg_vault_tde_catalog_update_rel_dek(args.relid, pg_vault_tde_vault_key_name);
            CommandCounterIncrement();

            reindex_index(NULL, args.relid, false,
                          get_rel_persistence(args.relid), &reindex_params);
            tuples_done = tuples_total;
        }
        else
        {
            pg_vault_tde_catalog_zero_rel_dek(args.relid);
            pg_vault_tde_catalog_update_rel_dek(args.relid, pg_vault_tde_vault_key_name);
            /* CommandCounterIncrement makes the new catalog row visible to kms_get_rel_dek's
             * slow path — without it, reencrypt_table re-encrypts with the old DEK. */
            CommandCounterIncrement();

            tuples_done = pg_vault_tde_reencrypt_table(args.relid);
        }

        PopActiveSnapshot();
        CommitTransactionCommand();
    }

    /* -----------------------------------------------------------------------
     * Phase 3: Mark rotation complete;
     * --------------------------------------------------------------------- */
    SetCurrentStatementStartTimestamp();
    StartTransactionCommand();
    PushActiveSnapshot(GetTransactionSnapshot());
    tde_progress_upsert(args.relid, "complete", tuples_done, tuples_total);
    PopActiveSnapshot();
    CommitTransactionCommand();

    ereport(LOG,
            (errmsg("pg_vault_tde: online rotation complete for relid=%u "
                    "(%lld tuples re-encrypted)",
                    args.relid, (long long) tuples_done)));

    } /* end PG_TRY body */
    PG_CATCH();
    {
        ErrorData *edata = CopyErrorData();

        FlushErrorState();
        AbortCurrentTransaction();

        tde_bgw_record_failure(args.relid);

        ereport(WARNING,
                (errmsg("pg_vault_tde: rotation BGW failed for relid=%u: %s",
                        args.relid, edata->message)));
        FreeErrorData(edata);
    }
    PG_END_TRY();
}