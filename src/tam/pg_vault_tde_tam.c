/*
 * pg_vault_tde_tam.c - Table Access Method (TAM) handler for pg_vault_tde
 *
 * Architecture: mutable copy of heapam's TableAmRoutine, initialised by
 * pg_vault_tde_tam_init() called from _PG_init.  Four write + seven read
 * callbacks are overridden; every structural callback (VACUUM, ANALYZE, HOT,
 * CLUSTER, index build, truncate ...) delegates unchanged to heapam.
 *
 * Wire format on disk (per tuple):
 *   [HeapTupleHeader  (t_hoff bytes, PLAINTEXT - MVCC fields)]
 *   [IV (12 B) | CIPHERTEXT (N B) | GCM TAG (16 B)]
 *
 * Total overhead vs. plain heap: TDE_GCM_OVERHEAD (28) bytes per stored tuple.
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */

#include "postgres.h"

#include "access/heapam.h"          /* heap_insert, heap_update, heap_multi_insert,
                                       heap_getnextslot */
#include "access/heaptoast.h"       /* heap_toast_insert_or_update — called BEFORE
                                       encryption to externalize large attributes */
#include "access/htup_details.h"    /* HeapTupleHeaderData, HEAPTUPLESIZE,
                                       HeapTupleHeaderSetSpeculativeToken */
#include "access/relscan.h"         /* IndexScanDesc, TableScanDesc */
#include "access/tableam.h"         /* TableAmRoutine, GetHeapamTableAmRoutine */
#if PG_VERSION_NUM < 180000
#include "nodes/tidbitmap.h"        /* TBMIterateResult (PG17 bitmap scan API) */
#endif
#include "catalog/index.h"          /* IndexBuildCallback, index_build_range_scan,
                                       FormIndexDatum */
#include "executor/tuptable.h"      /* TupleTableSlotOps, TTSOpsBufferHeapTuple,
                                       ExecClearTuple, ExecFetchSlotHeapTuple,
                                       ExecForceStoreHeapTuple, TupIsNull */
#include "executor/executor.h"      /* CreateExecutorState, FreeExecutorState,
                                       GetPerTupleExprContext */
#include "catalog/pg_am_d.h"        /* HEAP_TABLE_AM_OID */
#include "utils/rel.h"              /* RelationGetRelid */
#include "utils/memutils.h"
#include "utils/snapmgr.h"          /* GetLatestSnapshot, RegisterSnapshot,
                                       UnregisterSnapshot */
#include "miscadmin.h"              /* CHECK_FOR_INTERRUPTS */

#include "src/include/pg_vault_tde_crypto.h"  /* tde_gcm_encrypt, tde_gcm_decrypt,
                                                  TDE_GCM_OVERHEAD */
#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_guc.h"      /* pg_vault_tde_enabled */

#include <openssl/crypto.h>         /* OPENSSL_cleanse */
#include <string.h>                 /* memcpy */

/* ============================================================
 * Module-level mutable copy of heapam's TableAmRoutine.
 * Populated by pg_vault_tde_tam_init() at _PG_init time.
 * ============================================================ */
static TableAmRoutine tde_methods;

/*
 * Saved original heapam callbacks (non-NULL after tam_init).
 *
 * We intercept ALL read paths that deliver a HeapTuple into a slot:
 *  - scan_getnextslot      : sequential scan
 *  - index_fetch_tuple     : index scan (CRITICAL — was missing)
 *  - scan_bitmap_next_tuple: bitmap heap scan (BitmapHeapScan nodes)
 *  - scan_analyze_next_tuple: ANALYZE statistics collection
 *  - scan_sample_next_tuple: TABLESAMPLE clauses
 *  - tuple_fetch_row_version: direct TID fetch (TidScan, lock recheck)
 *  - tuple_lock            : SELECT FOR UPDATE / FOR SHARE
 *
 * Write paths call heap_insert / heap_update / heap_multi_insert directly.
 */
static const TupleTableSlotOps *(*heapam_slot_callbacks_cb)(Relation rel);
static bool       (*heapam_scan_getnextslot_cb)(TableScanDesc, ScanDirection,
                                                 TupleTableSlot *);
static bool       (*heapam_index_fetch_tuple_cb)(struct IndexFetchTableData *,
                                                  ItemPointer, Snapshot,
                                                  TupleTableSlot *, bool *, bool *);
/*
 * PG18 redesigned the bitmap-heap scan API: TBMIterateResult was removed from
 * scan_bitmap_next_tuple and replaced with per-call output counters.
 * PG17 signature: bool (TableScanDesc, struct TBMIterateResult *, TupleTableSlot *)
 * PG18 signature: bool (TableScanDesc, TupleTableSlot *, bool *recheck,
 *                        uint64 *lossy_pages, uint64 *exact_pages)
 */
#if PG_VERSION_NUM >= 180000
static bool       (*heapam_scan_bitmap_next_tuple_cb)(TableScanDesc,
                                                       TupleTableSlot *,
                                                       bool *, uint64 *,
                                                       uint64 *);
#else
static bool       (*heapam_scan_bitmap_next_tuple_cb)(TableScanDesc,
                                                       struct TBMIterateResult *,
                                                       TupleTableSlot *);
#endif
static bool       (*heapam_scan_analyze_next_tuple_cb)(TableScanDesc,
                                                        TransactionId,
                                                        double *, double *,
                                                        TupleTableSlot *);
static bool       (*heapam_scan_sample_next_tuple_cb)(TableScanDesc,
                                                       struct SampleScanState *,
                                                       TupleTableSlot *);
static bool       (*heapam_tuple_fetch_row_version_cb)(Relation, ItemPointer,
                                                        Snapshot, TupleTableSlot *);
static TM_Result  (*heapam_tuple_lock_cb)(Relation, ItemPointer, Snapshot,
                                           TupleTableSlot *, CommandId,
                                           LockTupleMode, LockWaitPolicy,
                                           uint8, TM_FailureData *);
/*
 * index_build_range_scan: called by CREATE INDEX to scan the table and build
 * index entries.  heapam's implementation calls heap_getnext() which guards
 * itself with:
 *     if (rel->rd_tableam != GetHeapamTableAmRoutine()) ERROR;
 * We now use a custom scan loop (table_scan_getnextslot) instead of
 * delegating to heapam's index_build_range_scan, so no saved pointer needed.
 */

/* ============================================================
 * Internal helpers: encrypt / decrypt a HeapTuple
 *
 * Both functions operate ONLY on the user-data portion [t_hoff .. t_len),
 * leaving HeapTupleHeader (xmin, xmax, ctid, infomask, null bitmap) as
 * plaintext. This is required for MVCC, HOT, and VACUUM to work correctly.
 * ============================================================ */

/*
 * tde_encrypt_heap_tuple
 *
 * Returns a palloc'd HeapTuple whose user-data region is replaced with
 *   [IV(12) | AES-256-GCM ciphertext | TAG(16)]
 * Header bytes [0 .. t_hoff) are copied verbatim (plaintext).
 * Caller must pfree the returned tuple; no need to cleanse (it is ciphertext).
 */
static HeapTuple
tde_encrypt_heap_tuple(HeapTuple plain)
{
    Size        hdr_len   = plain->t_data->t_hoff;
    char       *user_data = (char *) plain->t_data + hdr_len;
    Size        user_len  = plain->t_len - hdr_len;
    Size        enc_len   = 0;
    char       *enc_buf;
    HeapTuple   enc;

    /*
     * user_len may be 0 for tuples with all-NULL columns (only the null
     * bitmap lives in the header, no column data follows).  AES-256-GCM
     * handles zero-length plaintext correctly: output is [IV(12)|TAG(16)],
     * giving us authenticated integrity protection even on null-only rows.
     * We must NOT Assert(user_len > 0) here.
     */

    /*
     * Pass-through mode: when pg_vault_tde.enabled = false the tuple is
     * copied verbatim.  This allows measuring the overhead of the AES-GCM
     * layer in isolation by toggling a single GUC at server start.
     */
    if (!pg_vault_tde_enabled)
    {
        HeapTuple copy = heap_copytuple(plain);
        return copy;
    }

    enc_buf = tde_gcm_encrypt(user_data, user_len, &enc_len);
    Assert(enc_len == user_len + TDE_GCM_OVERHEAD);

    enc = (HeapTuple) palloc0(HEAPTUPLESIZE + hdr_len + enc_len);
    enc->t_len      = (uint32) (hdr_len + enc_len);
    enc->t_self     = plain->t_self;
    enc->t_tableOid = plain->t_tableOid;
    enc->t_data     = (HeapTupleHeader) ((char *) enc + HEAPTUPLESIZE);

    memcpy(enc->t_data, plain->t_data, hdr_len);                 /* header verbatim */
    memcpy((char *) enc->t_data + hdr_len, enc_buf, enc_len);    /* encrypted payload */

    pfree(enc_buf);  /* ciphertext - no need to cleanse */
    return enc;
}

/*
 * tde_decrypt_heap_tuple
 *
 * Takes an on-disk HeapTuple (header plain, user-data encrypted) and returns
 * a palloc'd HeapTuple with the user-data portion decrypted.
 * GCM tag verification is performed inside tde_gcm_decrypt; bad tags cause
 * ereport(ERROR) — tampered tuples never return data to the caller.
 *
 * Caller must OPENSSL_cleanse + pfree the returned tuple after use,
 * OR pass it to ExecForceStoreHeapTuple with shouldFree=true.
 *
 * Exported (non-static) so the logical decoding output plugin can decrypt
 * WAL-sourced tuples from encrypted_heap relations.
 */
HeapTuple
tde_decrypt_heap_tuple(HeapTuple enc)
{
    Size        hdr_len   = enc->t_data->t_hoff;
    char       *enc_data  = (char *) enc->t_data + hdr_len;
    Size        enc_len   = enc->t_len - hdr_len;
    Size        pt_len    = 0;
    char       *pt_buf;
    HeapTuple   plain;

    /*
     * Pass-through mode: when encryption is disabled the stored tuple is
     * already plaintext — return a copy unchanged.
     */
    if (!pg_vault_tde_enabled)
    {
        HeapTuple copy = heap_copytuple(enc);
        return copy;
    }

    if (enc_len < (Size) TDE_GCM_OVERHEAD)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("pg_vault_tde: encrypted tuple too short (%zu bytes)",
                        enc_len)));

    pt_buf = tde_gcm_decrypt(enc_data, enc_len, &pt_len);
    Assert(pt_len == enc_len - TDE_GCM_OVERHEAD);

    plain = (HeapTuple) palloc0(HEAPTUPLESIZE + hdr_len + pt_len);
    plain->t_len      = (uint32) (hdr_len + pt_len);
    plain->t_self     = enc->t_self;
    plain->t_tableOid = enc->t_tableOid;
    plain->t_data     = (HeapTupleHeader) ((char *) plain + HEAPTUPLESIZE);

    memcpy(plain->t_data, enc->t_data, hdr_len);
    memcpy((char *) plain->t_data + hdr_len, pt_buf, pt_len);

    OPENSSL_cleanse(pt_buf, pt_len);
    pfree(pt_buf);

    return plain;
}

/*
 * pg_vault_tde_decode_slot
 *
 * Common helper for all read paths: given a slot that contains an encrypted
 * buffer-backed HeapTuple (filled by a heapam call), swap in the decrypted
 * equivalent. Releases the buffer pin before storing the decrypted palloc'd
 * tuple so the slot transitions from buffer-backed to palloc-backed.
 */
static void
pg_vault_tde_decode_slot(TupleTableSlot *slot)
{
    BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
    HeapTuple   enc_copy;
    HeapTuple   plain;
    ItemPointerData saved_tid;
    Oid         saved_tableoid;

    /*
     * bslot->base.tuple points directly INTO the shared buffer page.
     * heapam sets t_self = ItemPointerSet(block, offset) + t_tableOid
     * before ExecStoreBufferHeapTuple, so this IS the physical address.
     *
     * ExecFetchSlotHeapTuple(slot, false, ...) must NOT be used here:
     * when materialize=false it may return the in-place tupdata workspace
     * whose t_self is uninitialized (it is NOT the buffer pointer).
     */
    Assert(TTS_IS_BUFFERTUPLE(slot));

    /*
     * Double-decode guard: if bslot->buffer == InvalidBuffer the slot has
     * already been decoded (ExecForceStoreHeapTuple clears the buffer pin
     * and leaves buffer==InvalidBuffer while keeping base.tuple pointing
     * to the palloc'd decrypted copy).  Calling decrypt a second time would
     * produce garbage and crash on GCM authentication failure.
     */
    if (bslot->buffer == InvalidBuffer)
        return;

    Assert(bslot->base.tuple != NULL);

    ItemPointerCopy(&bslot->base.tuple->t_self, &saved_tid);
    saved_tableoid = bslot->base.tuple->t_tableOid;

    /*
     * Palloc a copy of the encrypted tuple now (while buffer pin is held)
     * so we can pass it to tde_decrypt_heap_tuple after releasing the pin.
     */
    enc_copy = heap_copytuple(bslot->base.tuple);

    /* Release buffer pin (bslot->base.tuple is now dangling - don't use) */
    ExecClearTuple(slot);

    /* Decrypt (verifies GCM tag; ereport(ERROR) on tamper) */
    plain = tde_decrypt_heap_tuple(enc_copy);
    pfree(enc_copy);

    /* Stamp physical address onto decrypted tuple */
    ItemPointerCopy(&saved_tid, &plain->t_self);
    plain->t_tableOid = saved_tableoid;

    /*
     * Store decrypted tuple; slot takes ownership (shouldFree=true).
     *
     * IMPORTANT: ExecForceStoreHeapTuple into a BufferHeapTupleTableSlot
     * does NOT set slot->tts_tid (it calls ExecClearTuple then copies the
     * tuple into bslot->base.tuple without calling tts_buffer_heap_store_tuple).
     * We must set tts_tid manually after the call.
     */
    ExecForceStoreHeapTuple(plain, slot, true);
    ItemPointerCopy(&saved_tid, &slot->tts_tid);
}

/* ============================================================
 * Overridden TAM callbacks — read paths
 *
 * Every function that causes heapam to fill a TupleTableSlot with a
 * buffer-backed HeapTuple must be wrapped here so we decrypt before
 * the executor sees the data.  Missing any one of these leaves a hole
 * through which encrypted bytes reach the query planner or user.
 * ============================================================ */

/*
 * pg_vault_tde_slot_callbacks
 *
 * Always returns TTSOpsBufferHeapTuple regardless of what heapam would pick.
 * decode_slot casts the slot to BufferHeapTupleTableSlot to access the
 * buffer pin; if heapam ever returned a different slot type the cast would
 * be invalid.  By forcing buffer-backed slots we guarantee the cast is safe
 * and the double-decode guard (bslot->buffer == InvalidBuffer) works.
 */
static const TupleTableSlotOps *
pg_vault_tde_slot_callbacks(Relation rel)
{
    (void) heapam_slot_callbacks_cb;  /* suppress unused-variable warning */
    return &TTSOpsBufferHeapTuple;
}

/* ---- Sequential scan (SeqScan, TidRangeScan) ---- */

/*
 * pg_vault_tde_scan_getnextslot
 *
 * SeqScan / TidRangeScan read path.  Delegates to heapam which fills the
 * slot with a buffer-backed encrypted tuple, then decrypts in-place via
 * decode_slot.  This is the most commonly exercised read path in OLTP.
 */
static bool
pg_vault_tde_scan_getnextslot(TableScanDesc scan, ScanDirection direction,
                               TupleTableSlot *slot)
{
    if (!heapam_scan_getnextslot_cb(scan, direction, slot))
        return false;

    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);
    return true;
}

/*
 * pg_vault_tde_index_fetch_tuple
 *
 * Covers ALL regular index scans (Index Scan, Index Only Scan heap fetch).
 * heapam's index_fetch_tuple fills the slot from the heap buffer identified
 * by the TID returned from the index.  Without this wrapper, every index
 * scan returned raw ciphertext to the executor.
 *
 * IDENTITY-CHECK WORKAROUND
 * -------------------------
 * heapam's index_fetch_tuple internally calls heap_hot_search_buffer() to
 * traverse HOT chains.  That function guards itself with:
 *
 *   if (rel->rd_tableam != GetHeapamTableAmRoutine())
 *       ereport(ERROR, "only heap AM is supported");
 *
 * Our mutable tde_methods copy lives at a different address than heapam's
 * static const pointer, so the check always fails.  We fix this by
 * temporarily restoring rd_tableam to the real heapam pointer for the
 * duration of the delegate call, then putting our AM back.  This is safe
 * because RelationData is per-backend (local relcache); no other backend
 * shares our local copy.
 */
static bool
pg_vault_tde_index_fetch_tuple(struct IndexFetchTableData *scan,
                                ItemPointer tid, Snapshot snapshot,
                                TupleTableSlot *slot,
                                bool *call_again, bool *all_dead)
{
    bool                     result;
    const TableAmRoutine    *saved_am = scan->rel->rd_tableam;
    const TableAmRoutine   **rdam     =
        (const TableAmRoutine **) (void *) &scan->rel->rd_tableam;

    /*
     * Impersonate stock heapam so heap_hot_search_buffer's identity check
     * passes.  We MUST restore saved_am even on error, otherwise the
     * relcache entry is left pointing to heapam's static struct and all
     * subsequent operations on this relation silently bypass encryption.
     */
    *rdam  = GetHeapamTableAmRoutine();

    PG_TRY();
    {
        result = heapam_index_fetch_tuple_cb(scan, tid, snapshot, slot,
                                             call_again, all_dead);
    }
    PG_CATCH();
    {
        *rdam = saved_am;
        PG_RE_THROW();
    }
    PG_END_TRY();

    *rdam  = saved_am;

    if (result && !TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);
    return result;
}

/*
 * pg_vault_tde_scan_bitmap_next_tuple
 *
 * Covers BitmapHeapScan nodes. The bitmap executor calls this after the
 * bitmap index scan has produced a table-block bitmap; heapam fills the
 * slot per-tuple within each bitmap block.
 *
 * PG17: TBMIterateResult-based API (block + offsets passed per call).
 * PG18: TBMIterateResult was removed; recheck / lossy / exact counters
 *       are passed as out-parameters directly.
 */
#if PG_VERSION_NUM >= 180000
static bool
pg_vault_tde_scan_bitmap_next_tuple(TableScanDesc scan,
                                     TupleTableSlot *slot,
                                     bool *recheck,
                                     uint64 *lossy_pages,
                                     uint64 *exact_pages)
{
    if (!heapam_scan_bitmap_next_tuple_cb(scan, slot, recheck,
                                          lossy_pages, exact_pages))
        return false;

    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);
    return true;
}
#else
static bool
pg_vault_tde_scan_bitmap_next_tuple(TableScanDesc scan,
                                     struct TBMIterateResult *tbmres,
                                     TupleTableSlot *slot)
{
    if (!heapam_scan_bitmap_next_tuple_cb(scan, tbmres, slot))
        return false;

    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);
    return true;
}
#endif

/*
 * pg_vault_tde_scan_analyze_next_tuple
 *
 * Covers ANALYZE / autovacuum analyze.  Without this, pg_statistic entries
 * are computed over ciphertext leading to wildly wrong cardinality estimates
 * and broken query plans.
 */
static bool
pg_vault_tde_scan_analyze_next_tuple(TableScanDesc scan,
                                      TransactionId OldestXmin,
                                      double *liverows, double *deadrows,
                                      TupleTableSlot *slot)
{
    if (!heapam_scan_analyze_next_tuple_cb(scan, OldestXmin,
                                           liverows, deadrows, slot))
        return false;

    /*
     * heapam returns true also for dead tuples it counted but did not store
     * in the slot.  TupIsNull() guards against decoding an empty slot.
     */
    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);
    return true;
}

/*
 * pg_vault_tde_scan_sample_next_tuple
 *
 * Covers TABLESAMPLE clauses (e.g., SELECT ... FROM t TABLESAMPLE BERNOULLI).
 */
static bool
pg_vault_tde_scan_sample_next_tuple(TableScanDesc scan,
                                     struct SampleScanState *scanstate,
                                     TupleTableSlot *slot)
{
    if (!heapam_scan_sample_next_tuple_cb(scan, scanstate, slot))
        return false;

    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);
    return true;
}

/* ---- Index build (CREATE INDEX) ---- */

/*
 * pg_vault_tde_index_build_range_scan
 *
 * Custom implementation for CREATE INDEX / REINDEX on encrypted_heap tables.
 *
 * heapam's index_build_range_scan calls heap_getnext() which reads raw
 * encrypted tuples and has an identity check on rd_tableam.  Swapping
 * rd_tableam to heapam makes the identity check pass but causes
 * FormIndexDatum to extract keys from encrypted (garbage) data.
 *
 * We solve this by using our own scan loop that goes through
 * table_scan_getnextslot() which dispatches through our decrypt-aware
 * scan_getnextslot wrapper.  This ensures FormIndexDatum sees decrypted
 * (plaintext) attributes, producing correct index keys for both
 * CREATE INDEX and REINDEX operations.
 *
 * This is a simplified version of heapam_index_build_range_scan that
 * handles visibility, callback dispatch, and memory management but
 * does not implement dead-tuple tracking, index-tuples-alive progress
 * reporting, or tuple freezing.  These are future improvements.
 */
static double
pg_vault_tde_index_build_range_scan(Relation heap_rel,
                                     Relation index_rel,
                                     struct IndexInfo *index_info,
                                     bool allow_sync,
                                     bool anyvisible,
                                     bool progress,
                                     BlockNumber start_blockno,
                                     BlockNumber numblocks,
                                     IndexBuildCallback callback,
                                     void *callback_state,
                                     TableScanDesc scan)
{
    bool                    own_scan = false;
    bool                    need_unregister = false;
    Snapshot                snapshot = NULL;
    EState                 *estate;
    ExprContext            *econtext;
    TupleTableSlot         *slot;
    double                  reltuples = 0;
    Datum                   values[INDEX_MAX_KEYS];
    bool                    isnull[INDEX_MAX_KEYS];

    /*
     * Set up executor state for FormIndexDatum expression evaluation.
     * This mirrors what heapam_index_build_range_scan does.
     */
    estate   = CreateExecutorState();
    econtext = GetPerTupleExprContext(estate);
    slot     = table_slot_create(heap_rel, NULL);
    econtext->ecxt_scantuple = slot;

    /*
     * Open a table scan if the caller did not provide one.
     * The scan goes through our TableAmRoutine, so scan_getnextslot
     * dispatches to pg_vault_tde_scan_getnextslot which decrypts.
     */
    if (scan == NULL)
    {
        snapshot = RegisterSnapshot(GetLatestSnapshot());
        need_unregister = true;
        scan = table_beginscan_strat(heap_rel, snapshot, 0, NULL,
                                     allow_sync, true);
        own_scan = true;
    }

    /*
     * Main scan loop.  table_scan_getnextslot dispatches through
     * rd_tableam->scan_getnextslot, which is our decrypt wrapper.
     * The slot receives decrypted plaintext data.
     */
    while (table_scan_getnextslot(scan, ForwardScanDirection, slot))
    {
        HeapTuple   heapTuple;
        bool        tupleIsAlive = true;

        CHECK_FOR_INTERRUPTS();

        MemoryContextReset(econtext->ecxt_per_tuple_memory);

        /*
         * For MVCC snapshots all returned tuples are visible.
         * For SnapshotAny (used during some non-concurrent index builds)
         * we'd need to check visibility explicitly, but CREATE INDEX
         * CONCURRENTLY takes a different code path.
         */
        if (!tupleIsAlive)
            continue;

        /*
         * Extract index-key values from the decrypted slot and invoke
         * the index AM's callback to insert the index tuple.
         */
        FormIndexDatum(index_info, slot, estate, values, isnull);

        heapTuple = ExecFetchSlotHeapTuple(slot, false, NULL);

        callback(index_rel, &heapTuple->t_self, values, isnull,
                 tupleIsAlive, callback_state);

        reltuples += 1;
    }

    if (own_scan)
        table_endscan(scan);

    if (need_unregister)
        UnregisterSnapshot(snapshot);

    ExecDropSingleTupleTableSlot(slot);
    FreeExecutorState(estate);

    return reltuples;
}

/* ---- Direct TID fetch (TidScan, lock rechecks) ---- */

/*
 * pg_vault_tde_tuple_fetch_row_version
 *
 * Covers TidScan and UPDATE/DELETE recheck paths.  When the executor needs
 * to re-fetch a specific tuple version by its physical TID (e.g., after an
 * EvalPlanQual recheck on a concurrent UPDATE), heapam reads the on-disk
 * encrypted tuple into the slot.  We must decrypt it before the executor
 * evaluates the row against the query predicate.
 */
static bool
pg_vault_tde_tuple_fetch_row_version(Relation relation,
                                      ItemPointer tid,
                                      Snapshot snapshot,
                                      TupleTableSlot *slot)
{
    if (!heapam_tuple_fetch_row_version_cb(relation, tid, snapshot, slot))
        return false;

    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);
    return true;
}

/*
 * pg_vault_tde_tuple_lock
 *
 * Covers SELECT FOR UPDATE / FOR SHARE.  heapam acquires a tuple-level
 * lock and populates the slot with the locked tuple version.  The slot
 * is only valid on TM_Ok; other results (TM_Updated, TM_BeingModified)
 * leave the slot empty or partially filled, so we decrypt only on TM_Ok.
 */
static TM_Result
pg_vault_tde_tuple_lock(Relation relation, ItemPointer tid,
                         Snapshot snapshot, TupleTableSlot *slot,
                         CommandId cid, LockTupleMode mode,
                         LockWaitPolicy wait_policy, uint8 flags,
                         TM_FailureData *tmfd)
{
    TM_Result result;

    result = heapam_tuple_lock_cb(relation, tid, snapshot, slot, cid,
                                  mode, wait_policy, flags, tmfd);

    /* Slot is only populated (and meaningful) on TM_Ok */
    if (result == TM_Ok && !TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);

    return result;
}

/* ---- Write paths (encrypt) ---- */

/*
 * pg_vault_tde_tuple_insert
 *
 * Standard single-row INSERT path.  Materialises the slot into a
 * HeapTuple, TOASTs large attributes on the plaintext, encrypts the
 * (now-small) user-data portion via AES-256-GCM, then delegates to
 * heap_insert for WAL and buffer-pool storage.
 *
 * TOAST must happen BEFORE encryption: heap_insert calls
 * heap_toast_insert_or_update which deforms the tuple to inspect
 * individual attributes.  If the user-data is encrypted ciphertext,
 * deformation reads random IV bytes as varlena headers → SIGSEGV.
 *
 * After pre-TOAST + encryption the tuple is well below
 * TOAST_TUPLE_TARGET, so we suppress TOAST inside heap_insert by
 * temporarily clearing reltoastrelid (safe — rd_rel is per-backend
 * relcache, same pattern as rd_tableam impersonation).
 */
static void
pg_vault_tde_tuple_insert(Relation rel, TupleTableSlot *slot,
                           CommandId cid, int options,
                           struct BulkInsertStateData *bistate)
{
    bool       shouldFree = true;
    HeapTuple  plain;
    HeapTuple  toasted;
    HeapTuple  enc;
    Oid        saved_toastrelid;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);

    /*
     * Pre-TOAST: externalize large attributes BEFORE encryption.
     * TOAST chunks are stored via standard heap (pg_vault_tde_toast_am
     * returns HEAP_TABLE_AM_OID).  After this, inline values are replaced
     * by small TOAST pointers and the tuple fits in a single page.
     */
    if (OidIsValid(rel->rd_rel->reltoastrelid) &&
        plain->t_len > TOAST_TUPLE_THRESHOLD)
        toasted = heap_toast_insert_or_update(rel, plain, NULL, options);
    else
        toasted = plain;

    enc = tde_encrypt_heap_tuple(toasted);
    enc->t_tableOid = plain->t_tableOid;

    /*
     * Suppress TOAST inside heap_insert — we already handled it above.
     * reltoastrelid is per-backend (relcache local copy), same pattern as
     * the rd_tableam impersonation in index_fetch_tuple.
     */
    saved_toastrelid = rel->rd_rel->reltoastrelid;
    rel->rd_rel->reltoastrelid = InvalidOid;

    PG_TRY();
    {
        heap_insert(rel, enc, cid, options, bistate);
        rel->rd_rel->reltoastrelid = saved_toastrelid;

        ItemPointerCopy(&enc->t_self, &slot->tts_tid);
        slot->tts_tableOid = enc->t_tableOid;
    }
    PG_CATCH();
    {
        rel->rd_rel->reltoastrelid = saved_toastrelid;
        if (shouldFree)
        {
            Size hdr = plain->t_data->t_hoff;
            OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
            pfree(plain);
        }
        if (toasted != plain)
            pfree(toasted);
        pfree(enc);
        PG_RE_THROW();
    }
    PG_END_TRY();

    if (shouldFree)
    {
        Size hdr = plain->t_data->t_hoff;
        OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
        pfree(plain);
    }
    if (toasted != plain)
        pfree(toasted);
    pfree(enc);
}

static void
pg_vault_tde_tuple_insert_speculative(Relation rel, TupleTableSlot *slot,
                                       CommandId cid, volatile int options,
                                       struct BulkInsertStateData *bistate,
                                       uint32 specToken)
{
    bool       shouldFree = true;
    HeapTuple  plain;
    HeapTuple  toasted;
    HeapTuple  enc;
    Oid        saved_toastrelid;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);

    /* Stamp the speculative token on the header BEFORE encrypting so it is
     * preserved verbatim in the encrypted tuple's plaintext header area. */
    HeapTupleHeaderSetSpeculativeToken(plain->t_data, specToken);
    options |= HEAP_INSERT_SPECULATIVE;

    /* Pre-TOAST on plaintext (see tuple_insert comment for rationale) */
    if (OidIsValid(rel->rd_rel->reltoastrelid) &&
        plain->t_len > TOAST_TUPLE_THRESHOLD)
        toasted = heap_toast_insert_or_update(rel, plain, NULL, options);
    else
        toasted = plain;

    enc = tde_encrypt_heap_tuple(toasted);
    enc->t_tableOid = plain->t_tableOid;

    saved_toastrelid = rel->rd_rel->reltoastrelid;
    rel->rd_rel->reltoastrelid = InvalidOid;

    PG_TRY();
    {
        heap_insert(rel, enc, cid, options, bistate);
        rel->rd_rel->reltoastrelid = saved_toastrelid;

        ItemPointerCopy(&enc->t_self, &slot->tts_tid);
        slot->tts_tableOid = enc->t_tableOid;
    }
    PG_CATCH();
    {
        rel->rd_rel->reltoastrelid = saved_toastrelid;
        if (shouldFree)
        {
            Size hdr = plain->t_data->t_hoff;
            OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
            pfree(plain);
        }
        if (toasted != plain)
            pfree(toasted);
        pfree(enc);
        PG_RE_THROW();
    }
    PG_END_TRY();

    if (shouldFree)
    {
        Size hdr = plain->t_data->t_hoff;
        OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
        pfree(plain);
    }
    if (toasted != plain)
        pfree(toasted);
    pfree(enc);
}

/*
 * pg_vault_tde_multi_insert
 *
 * COPY / bulk-insert path.  Encrypts all tuples in a batch then calls
 * heap_multi_insert once — amortising page-lock and WAL overhead across
 * nslots rows instead of paying it per row with heap_insert.
 *
 * Algorithm (3-phase):
 *   Phase 1 — Pre-TOAST + encrypt every slot into an encrypted HeapTuple.
 *             The original plaintext slots survive untouched (COPY needs
 *             them later for index key formation via ExecInsertIndexTuples).
 *   Phase 2 — Suppress reltoastrelid and call heap_multi_insert with the
 *             encrypted HeapTuple array.  This is a single heap operation
 *             that acquires the buffer lock just once per page.
 *   Phase 3 — Copy physical TIDs from the inserted tuples back to the
 *             original slots so COPY's index maintenance has correct ctids.
 *
 * Performance: ~30-40 % faster than per-row heap_insert for bulk COPY on
 * typical 100-500 byte rows (measured via bench_tde.sh).
 */
static void
pg_vault_tde_multi_insert(Relation rel, TupleTableSlot **slots, int nslots,
                           CommandId cid, int options,
                           struct BulkInsertStateData *bistate)
{
    HeapTuple       *enc_tuples;        /* encrypted HeapTuples */
    TupleTableSlot **enc_slots;         /* temporary slots for heap_multi_insert */
    volatile int encrypted_count = 0;   /* how many we encrypted (for cleanup) */
    int         i;
    Oid         table_oid = RelationGetRelid(rel);
    Oid         saved_toastrelid = rel->rd_rel->reltoastrelid;
    TupleDesc   tupdesc = RelationGetDescr(rel);

    enc_tuples = (HeapTuple *) palloc(nslots * sizeof(HeapTuple));
    enc_slots  = (TupleTableSlot **) palloc(nslots * sizeof(TupleTableSlot *));

    /*
     * Phase 1: pre-TOAST + encrypt each tuple.
     *
     * We build temporary HeapTupleTableSlot slots to hold the encrypted
     * tuples, because PG17+ heap_multi_insert takes TupleTableSlot **.
     * The original slots survive untouched — COPY needs them later for
     * index key formation via ExecInsertIndexTuples.
     */
    PG_TRY();
    {
        for (i = 0; i < nslots; i++)
        {
            HeapTuple  plain;
            HeapTuple  toasted;
            bool       sf = true;

            plain = ExecFetchSlotHeapTuple(slots[i], true, &sf);
            plain->t_tableOid = table_oid;

            /* Pre-TOAST on plaintext (see tuple_insert for rationale) */
            if (OidIsValid(saved_toastrelid) &&
                plain->t_len > TOAST_TUPLE_THRESHOLD)
                toasted = heap_toast_insert_or_update(rel, plain, NULL, options);
            else
                toasted = plain;

            enc_tuples[i] = tde_encrypt_heap_tuple(toasted);
            enc_tuples[i]->t_tableOid = table_oid;

            /* Create a temporary slot and store the encrypted tuple in it */
            enc_slots[i] = MakeSingleTupleTableSlot(tupdesc,
                                                     &TTSOpsHeapTuple);
            ExecForceStoreHeapTuple(enc_tuples[i], enc_slots[i], false);

            encrypted_count = i + 1;

            /* Free intermediates eagerly */
            if (toasted != plain)
                pfree(toasted);
            if (sf)
            {
                Size hdr = plain->t_data->t_hoff;
                OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
                pfree(plain);
            }
        }

        /*
         * Phase 2: batched heap insert with TOAST suppressed.
         *
         * Suppress reltoastrelid so heap_multi_insert does not attempt to
         * TOAST the (already encrypted) tuples — their byte pattern is
         * random-looking ciphertext and would confuse the TOAST deformer.
         */
        rel->rd_rel->reltoastrelid = InvalidOid;
        heap_multi_insert(rel, enc_slots, nslots, cid, options, bistate);
        rel->rd_rel->reltoastrelid = saved_toastrelid;

        /*
         * Phase 3: propagate physical TIDs back to the original slots.
         *
         * heap_multi_insert updates enc_slots[i]->tts_tid with the physical
         * (block, offset) where the row landed.  COPY's index maintenance
         * reads slots[i]->tts_tid for the tid column of index entries.
         */
        for (i = 0; i < nslots; i++)
        {
            ItemPointerCopy(&enc_slots[i]->tts_tid, &slots[i]->tts_tid);
            slots[i]->tts_tableOid = table_oid;
        }
    }
    PG_CATCH();
    {
        /* Restore TOAST relid unconditionally on error */
        rel->rd_rel->reltoastrelid = saved_toastrelid;

        /* Drop temporary slots and free encrypted tuples */
        for (i = 0; i < (int) encrypted_count; i++)
        {
            ExecDropSingleTupleTableSlot(enc_slots[i]);
            pfree(enc_tuples[i]);
        }
        pfree(enc_slots);
        pfree(enc_tuples);
        PG_RE_THROW();
    }
    PG_END_TRY();

    /* Normal cleanup: drop temporary slots and free encrypted tuples */
    for (i = 0; i < nslots; i++)
    {
        ExecDropSingleTupleTableSlot(enc_slots[i]);
        pfree(enc_tuples[i]);
    }
    pfree(enc_slots);
    pfree(enc_tuples);
}

/*
 * pg_vault_tde_tuple_update
 *
 * UPDATE path: pre-TOASTs the plaintext, encrypts the (now-small) tuple,
 * then delegates to heap_update with TOAST suppressed.  heap_update may
 * return TM_Updated or other non-Ok results on concurrent modification;
 * we only propagate the new ctid to the slot on TM_Ok.
 */
static TM_Result
pg_vault_tde_tuple_update(Relation rel, ItemPointer otid,
                           TupleTableSlot *slot, CommandId cid,
                           Snapshot snapshot, Snapshot crosscheck,
                           bool wait, TM_FailureData *tmfd,
                           LockTupleMode *lockmode,
                           TU_UpdateIndexes *update_indexes)
{
    bool       shouldFree = true;
    HeapTuple  plain;
    HeapTuple  toasted;
    HeapTuple  enc;
    TM_Result  result;
    Oid        saved_toastrelid;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);

    /*
     * Pre-TOAST on plaintext.  For UPDATE we pass NULL as oldtup because
     * the old tuple is encrypted and cannot be used for delta-TOAST
     * optimization (heap_toast_insert_or_update would deform cipher text).
     */
    if (OidIsValid(rel->rd_rel->reltoastrelid) &&
        plain->t_len > TOAST_TUPLE_THRESHOLD)
        toasted = heap_toast_insert_or_update(rel, plain, NULL, 0);
    else
        toasted = plain;

    enc = tde_encrypt_heap_tuple(toasted);
    enc->t_tableOid = plain->t_tableOid;

    saved_toastrelid = rel->rd_rel->reltoastrelid;
    rel->rd_rel->reltoastrelid = InvalidOid;

    PG_TRY();
    {
        result = heap_update(rel, otid, enc, cid, crosscheck, wait,
                             tmfd, lockmode, update_indexes);
        rel->rd_rel->reltoastrelid = saved_toastrelid;

        if (result == TM_Ok)
        {
            ItemPointerCopy(&enc->t_self, &slot->tts_tid);
            slot->tts_tableOid = enc->t_tableOid;
        }
    }
    PG_CATCH();
    {
        rel->rd_rel->reltoastrelid = saved_toastrelid;
        if (shouldFree)
        {
            Size hdr = plain->t_data->t_hoff;
            OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
            pfree(plain);
        }
        if (toasted != plain)
            pfree(toasted);
        pfree(enc);
        PG_RE_THROW();
    }
    PG_END_TRY();

    if (shouldFree)
    {
        Size hdr = plain->t_data->t_hoff;
        OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
        pfree(plain);
    }
    if (toasted != plain)
        pfree(toasted);
    pfree(enc);

    return result;
}

/* ---- TOAST AM delegation ---- */

/*
 * pg_vault_tde_toast_am
 *
 * Forces TOAST tables for encrypted_heap relations to use the standard heap AM
 * (HEAP_TABLE_AM_OID = 2).  Without this, PG18 creates TOAST tables using the
 * parent's AM (via create_toast_table → table_relation_toast_am → relam).  A
 * TOAST table with encrypted_heap AM triggers a guard in heap_getnext():
 *   if (rd_tableam != GetHeapamTableAmRoutine()) ERROR "only heap AM is supported"
 * because our tde_methods copy lives at a different address than heapam's
 * static const struct.
 *
 * LIMITATION: Column values that exceed the TOAST threshold (~2 kB) are stored
 * in the heap-based TOAST table and are NOT individually encrypted.  Only
 * inline column values (stored directly in the encrypted_heap page) are
 * encrypted.  Full per-chunk TOAST encryption is on the roadmap.
 */
static Oid
pg_vault_tde_toast_am(Relation rel)
{
    (void) rel;
    return HEAP_TABLE_AM_OID;  /* standard heap AM, always safe for TOAST */
}

/* ============================================================
 * Initialisation
 * ============================================================ */

/*
 * pg_vault_tde_tam_init
 *
 * Called ONCE from _PG_init after shmem hooks are registered.
 * Copies heapam's TableAmRoutine into the mutable tde_methods struct,
 * saves original callbacks, then installs encrypted wrappers.
 */
void
pg_vault_tde_tam_init(void)
{
    const TableAmRoutine *heapam = GetHeapamTableAmRoutine();

    memcpy(&tde_methods, heapam, sizeof(TableAmRoutine));

    /* --- Save originals for every read path we wrap --- */
    heapam_slot_callbacks_cb                = heapam->slot_callbacks;
    heapam_scan_getnextslot_cb              = heapam->scan_getnextslot;
    heapam_index_fetch_tuple_cb             = heapam->index_fetch_tuple;
    heapam_scan_bitmap_next_tuple_cb        = heapam->scan_bitmap_next_tuple;
    heapam_scan_analyze_next_tuple_cb       = heapam->scan_analyze_next_tuple;
    heapam_scan_sample_next_tuple_cb        = heapam->scan_sample_next_tuple;
    heapam_tuple_fetch_row_version_cb       = heapam->tuple_fetch_row_version;
    heapam_tuple_lock_cb                    = heapam->tuple_lock;

    /* --- Install encrypt/decrypt wrappers --- */

    /* Slot type: always buffer-backed (needed for decode_slot cast) */
    tde_methods.slot_callbacks              = pg_vault_tde_slot_callbacks;

    /* Write paths: encrypt before calling heapam storage layer */
    tde_methods.tuple_insert                = pg_vault_tde_tuple_insert;
    tde_methods.tuple_insert_speculative    = pg_vault_tde_tuple_insert_speculative;
    tde_methods.multi_insert                = pg_vault_tde_multi_insert;
    tde_methods.tuple_update                = pg_vault_tde_tuple_update;

    /* Read paths: delegate to heapam then decrypt the returned slot */
    tde_methods.scan_getnextslot            = pg_vault_tde_scan_getnextslot;
    tde_methods.index_fetch_tuple           = pg_vault_tde_index_fetch_tuple;
    tde_methods.scan_bitmap_next_tuple      = pg_vault_tde_scan_bitmap_next_tuple;
    tde_methods.scan_analyze_next_tuple     = pg_vault_tde_scan_analyze_next_tuple;
    tde_methods.scan_sample_next_tuple      = pg_vault_tde_scan_sample_next_tuple;
    tde_methods.tuple_fetch_row_version     = pg_vault_tde_tuple_fetch_row_version;
    tde_methods.tuple_lock                  = pg_vault_tde_tuple_lock;

    /* Index build: bypass rd_tableam identity check inside heap_getnext */
    tde_methods.index_build_range_scan      = pg_vault_tde_index_build_range_scan;

    /*
     * Force TOAST tables for encrypted_heap to use the standard heap AM.
     * PG18's heapam_relation_toast_am returns InvalidOid which causes
     * create_toast_table to fall back to the parent's relam (encrypted_heap).
     * A TOAST table with our AM is rejected by heap_getnext's identity check.
     * By returning HEAP_TABLE_AM_OID we get a plain heap TOAST table; large
     * column values work but are stored unencrypted (documented v1 limitation).
     */
    tde_methods.relation_toast_am           = pg_vault_tde_toast_am;

    /* All other callbacks (delete, complete_speculative, scan_begin/end/rescan,
     * finish_bulk_insert, vacuum, analyze, relation_*, parallelscan_*, ...) are
     * inherited from heapam unchanged via the memcpy above. */

    ereport(LOG,
            (errmsg("pg_vault_tde: TAM initialised "
                    "(AES-256-GCM, 4 write + 7 read paths wired, heapam delegate)")));
}

/*
 * pg_vault_tde_get_tableam_routine
 *
 * Returns &tde_methods. Valid after pg_vault_tde_tam_init(); before that the
 * struct is zeroed which is safe while no DDL can run.
 */
extern const TableAmRoutine *pg_vault_tde_get_tableam_routine(void);

const TableAmRoutine *
pg_vault_tde_get_tableam_routine(void)
{
    return &tde_methods;
}

/* ================================================================
 * SQL-callable utility functions (v1.1)
 *
 * These functions are registered in pg_vault_tde--1.0.sql and provide
 * operational tooling for encrypted tables: re-encryption after key
 * rotation, integrity verification, and storage overhead reporting.
 * ================================================================ */

#include "executor/spi.h"
#include "funcapi.h"               /* get_call_result_type, BlessTupleDesc */
#include "utils/lsyscache.h"       /* get_rel_name */
#include "utils/builtins.h"        /* quote_identifier */

/*
 * pg_vault_tde_reencrypt_table(regclass [, batch_size int DEFAULT 1000])
 *
 * Re-encrypts all live rows in an encrypted_heap table with the current DEK.
 * Implements a self-referencing UPDATE (SET first_col = first_col) which
 * physically triggers the TAM read path (decrypt) followed by the write
 * path (re-encrypt with current DEK), without changing any column values.
 *
 * When used after key rotation with prev_dek fallback:
 *   1. rotate_key() saves old DEK → prev_dek
 *   2. set_test_dek() / vault_fetch_dek() sets new DEK
 *   3. reencrypt_table() reads old rows (fallback to prev_dek) and
 *      writes new tuples (encrypted with current DEK)
 *   4. clear_prev_dek() wipes old key material
 *
 * After re-encryption, run VACUUM to physically remove old ciphertext
 * from the heap pages (dead tuples from the UPDATE still contain
 * old-DEK ciphertext until reclaimed).
 *
 * The batch_size parameter is accepted for API compatibility but currently
 * the entire table is re-encrypted in a single UPDATE statement.
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_reencrypt_table);
PGDLLEXPORT Datum
pg_vault_tde_reencrypt_table(PG_FUNCTION_ARGS)
{
    Oid             relid = PG_GETARG_OID(0);
    char           *relname;
    Relation        rel;
    TupleDesc       desc;
    const char     *first_col = NULL;
    int             j, ret;
    StringInfoData  cmd;
    uint64          total_updated;

    relname = get_rel_name(relid);
    if (relname == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_TABLE),
                 errmsg("relation with OID %u does not exist", relid)));

    /*
     * Find the first non-dropped user column for the dummy UPDATE.
     * We open the relation briefly just to inspect the tuple descriptor.
     */
    rel = table_open(relid, AccessShareLock);
    desc = RelationGetDescr(rel);

    for (j = 0; j < desc->natts; j++)
    {
        Form_pg_attribute att = TupleDescAttr(desc, j);
        if (!att->attisdropped)
        {
            first_col = pstrdup(NameStr(att->attname));
            break;
        }
    }
    table_close(rel, AccessShareLock);

    if (first_col == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("table has no user columns to re-encrypt")));

    /*
     * Execute UPDATE t SET first_col = first_col via SPI.
     * The TAM intercepts both the read (decrypt, with prev_dek fallback)
     * and write (re-encrypt with current DEK) paths automatically.
     */
    SPI_connect();

    initStringInfo(&cmd);
    appendStringInfo(&cmd, "UPDATE %s SET %s = %s",
                     quote_identifier(relname),
                     quote_identifier(first_col),
                     quote_identifier(first_col));

    ret = SPI_execute(cmd.data, false, 0);
    if (ret != SPI_OK_UPDATE)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("pg_vault_tde_reencrypt_table: UPDATE failed (SPI code %d)",
                        ret)));

    total_updated = SPI_processed;
    pfree(cmd.data);
    SPI_finish();

    ereport(NOTICE,
            (errmsg("pg_vault_tde: re-encrypted " UINT64_FORMAT " rows in %s",
                    total_updated, relname)));

    PG_RETURN_VOID();
}

/*
 * pg_vault_tde_verify_integrity(regclass)
 *   → (total_tuples bigint, failed_tuples bigint)
 *
 * Scans all live tuples in a raw heapam scan (bypassing TAM decrypt) and
 * manually attempts GCM decryption on each.  Catches per-tuple failures
 * via PG_TRY/PG_CATCH so a single corrupted row does not abort the scan.
 *
 * Returns a composite with the total tuple count and the number whose
 * GCM authentication tag verification failed.
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_verify_integrity);
PGDLLEXPORT Datum
pg_vault_tde_verify_integrity(PG_FUNCTION_ARGS)
{
    Oid                  relid = PG_GETARG_OID(0);
    Relation             rel;
    TupleTableSlot      *slot;
    TableScanDesc        scan;
    const TableAmRoutine *saved_am;
    volatile int64       total = 0;
    volatile int64       failed = 0;
    TupleDesc            tupdesc;
    Datum                values[2];
    bool                 nulls[2] = {false, false};
    HeapTuple            result_tup;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    tupdesc = BlessTupleDesc(tupdesc);

    rel = table_open(relid, AccessShareLock);

    /*
     * Swap rd_tableam to heapam so the scan returns raw encrypted tuples
     * without triggering our decrypt-on-read wrappers.
     */
    saved_am = rel->rd_tableam;
    {
        const TableAmRoutine **rdam = (const TableAmRoutine **)(void *)&rel->rd_tableam;
        *rdam = GetHeapamTableAmRoutine();
    }

    PG_TRY();
    {
        slot = table_slot_create(rel, NULL);
        scan = table_beginscan(rel, GetActiveSnapshot(), 0, NULL);

        while (table_scan_getnextslot(scan, ForwardScanDirection, slot))
        {
            BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;

            total++;

            /*
             * Try to decrypt the raw tuple.  On GCM auth failure the crypto
             * layer raises ERROR; we catch it and count the failure.
             * Use PG_TRY(2) to avoid variable shadowing with outer PG_TRY.
             */
            PG_TRY(2);
            {
                HeapTuple plain = tde_decrypt_heap_tuple(bslot->base.tuple);
                pfree(plain);
            }
            PG_CATCH(2);
            {
                failed++;
                FlushErrorState();
            }
            PG_END_TRY(2);
        }

        table_endscan(scan);
        ExecDropSingleTupleTableSlot(slot);
    }
    PG_CATCH();
    {
        const TableAmRoutine **rdam = (const TableAmRoutine **)(void *)&rel->rd_tableam;
        *rdam = saved_am;
        PG_RE_THROW();
    }
    PG_END_TRY();

    {
        const TableAmRoutine **rdam = (const TableAmRoutine **)(void *)&rel->rd_tableam;
        *rdam = saved_am;
    }
    table_close(rel, AccessShareLock);

    values[0] = Int64GetDatum((int64) total);
    values[1] = Int64GetDatum((int64) failed);
    result_tup = heap_form_tuple(tupdesc, values, nulls);

    PG_RETURN_DATUM(HeapTupleGetDatum(result_tup));
}

/*
 * pg_vault_tde_encrypted_size(regclass)
 *   → (total_tuples bigint, encryption_overhead_bytes bigint)
 *
 * Reports the storage overhead imposed by TDE on the given table.
 * Each encrypted tuple carries TDE_GCM_OVERHEAD (28) bytes of overhead:
 * 12-byte IV + 16-byte GCM tag.  The total overhead is simply
 * total_tuples × 28.
 *
 * Uses SPI to count live rows (which also validates readability).
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_encrypted_size);
PGDLLEXPORT Datum
pg_vault_tde_encrypted_size(PG_FUNCTION_ARGS)
{
    Oid             relid = PG_GETARG_OID(0);
    char           *relname;
    StringInfoData  cmd;
    int             ret;
    int64           total;
    TupleDesc       tupdesc;
    Datum           values[2];
    bool            nulls[2] = {false, false};
    HeapTuple       result_tup;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    tupdesc = BlessTupleDesc(tupdesc);

    relname = get_rel_name(relid);
    if (relname == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_TABLE),
                 errmsg("relation with OID %u does not exist", relid)));

    SPI_connect();

    initStringInfo(&cmd);
    appendStringInfo(&cmd, "SELECT count(*) FROM %s", quote_identifier(relname));

    ret = SPI_execute(cmd.data, true, 0);
    if (ret != SPI_OK_SELECT)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("pg_vault_tde_encrypted_size: count query failed")));

    {
        bool isnull;
        total = DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[0],
                                            SPI_tuptable->tupdesc, 1, &isnull));
    }

    pfree(cmd.data);
    SPI_finish();

    values[0] = Int64GetDatum(total);
    values[1] = Int64GetDatum(total * (int64) TDE_GCM_OVERHEAD);
    result_tup = heap_form_tuple(tupdesc, values, nulls);

    PG_RETURN_DATUM(HeapTupleGetDatum(result_tup));
}

