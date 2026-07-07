/*
 * pg_vault_tde_tam.c - Table Access Method (TAM) handler for pg_vault_tde
 *
 * Architecture: mutable copy of heapam's TableAmRoutine, initialised by
 * pg_vault_tde_tam_init() called from _PG_init.  Four write + seven read
 * callbacks are overridden; every structural callback (VACUUM, ANALYZE, HOT,
 * CLUSTER, index build, truncate ...) delegates unchanged to heapam.
 *
 * Wire format on disk (per tuple), v4 IV-first trailer:
 *   [HeapTupleHeader (t_hoff bytes, PLAINTEXT - MVCC fields)]
 *   [IV(12) | CIPHERTEXT(N) | GCM TAG(16) | VERSION(1) | GENERATION(8)]
 *
 * Overhead vs. plain heap: TDE_V4_OVERHEAD (37) bytes/tuple. IV-first disables
 * HOT on encrypted tables but keeps tde_btree coherent.
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#include "postgres.h"
#include "executor/spi.h"
#include "access/heapam.h"          /* heap_insert, heap_update, heap_multi_insert,
                                       heap_getnextslot */
#include "access/heaptoast.h"       /* TOAST_TUPLE_THRESHOLD, TOAST_MAX_CHUNK_SIZE */
#include "access/toast_internals.h" /* TOAST_TUPLE_THRESHOLD */
#include "access/genam.h"           /* index_insert */
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
#include "catalog/catalog.h"        /* GetNewOidWithIndex */
#include "commands/defrem.h"        /* get_table_am_oid — used by toast_am */
#include "utils/rel.h"              /* RelationGetRelid */
#include "utils/memutils.h"
#include "utils/snapmgr.h"          /* GetLatestSnapshot, RegisterSnapshot,
                                       UnregisterSnapshot */
#include "miscadmin.h"              /* CHECK_FOR_INTERRUPTS */
#include "varatt.h"                 /* VARSIZE_ANY_EXHDR, VARATT_IS_EXTERNAL,
                                       SET_VARSIZE_COMPRESSED, VARHDRSZ_COMPRESSED */

#include "access/rewriteheap.h"
#include "commands/vacuum.h"

#include "access/toast_compression.h" /* TOAST_PGLZ_COMPRESSION_ID */
#include "src/include/pg_vault_tde_crypto.h"  /* tde_gcm_encrypt, tde_gcm_decrypt,
                                                  TDE_V4_OVERHEAD */
#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_guc.h"      /* pg_vault_tde_enabled */
#include "src/include/pg_vault_tde_iam.h"      /* tde_iam_build_in_progress,
                                                  tde_iam_encrypt_index_datum */
#include "src/include/pg_vault_tde_toast.h"
#include "src/include/pg_vault_tde_catalog.h"
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
static bool       (*heapam_tuple_satisfies_snapshot_cb)(Relation,
                                                         TupleTableSlot *,
                                                         Snapshot);
/* save original heapam delete callback */
static TM_Result (*heapam_tuple_delete_cb)(Relation rel,
                                           ItemPointer tid,
                                           CommandId cid,
                                           Snapshot snapshot,
                                           Snapshot crosscheck,
                                           bool wait,
                                           TM_FailureData *tmfd,
                                           bool changingPart);
                                           
static HeapTuple pg_vault_tde_toast_insert_or_update(Relation rel, HeapTuple tup, HeapTuple old_tuple, int options);

/* custom delete callback */
static TM_Result pg_vault_tde_tuple_delete(Relation rel,
                                           ItemPointer tid,
                                           CommandId cid,
                                           Snapshot snapshot,
                                           Snapshot crosscheck,
                                           bool wait,
                                           TM_FailureData *tmfd,
                                           bool changingPart);

static bool tde_tuple_has_external(HeapTuple tup, Relation rel);

static HeapTuple tde_prepare_encrypt_tuple(Relation rel, HeapTuple plain, HeapTuple old, HeapTuple *toasted_out, int options);

static inline void tde_release_plain(HeapTuple plain)
{
    Size hdr = plain->t_data->t_hoff;
    OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
    pfree(plain);
}

static HeapTuple tde_prepare_encrypt_tuple(Relation rel, HeapTuple plain, HeapTuple old, HeapTuple *toasted_out, int options)
{
    HeapTuple toasted = pg_vault_tde_toast_insert_or_update(rel, plain, old, options);
    HeapTuple enc = tde_encrypt_heap_tuple(toasted, RelationGetRelid(rel));

    enc->t_data->t_infomask &= ~HEAP_HASEXTERNAL;
    enc->t_tableOid = plain->t_tableOid;
    *toasted_out = toasted;

    return enc;
}

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
 * Returns a palloc'd HeapTuple whose user-data region is replaced with the
 * v4 wire format produced by tde_gcm_encrypt():
 *   [IV(12) | CIPHERTEXT(N) | TAG(16) | VERSION(1) | GENERATION(8)]
 * Total overhead: TDE_V4_OVERHEAD (37 bytes) per encrypted user-data region.
 *
 * Header bytes [0 .. t_hoff) are copied verbatim (plaintext) because MVCC
 * fields (xmin, xmax, ctid, infomask, null bitmap) must remain readable by
 * heapam without decryption.
 *
 * Caller must pfree the returned tuple; OPENSSL_cleanse is NOT required
 * on the returned tuple because it contains only ciphertext.
 */
HeapTuple
tde_encrypt_heap_tuple(HeapTuple plain, Oid relid)
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
     * handles zero-length plaintext correctly: output is [IV(12)|TAG(16)|VERSION(1)|GEN(8)],
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
    enc_buf = tde_gcm_encrypt(relid, user_data, user_len, &enc_len);
    Assert(enc_len == user_len + TDE_V4_OVERHEAD);
    enc = (HeapTuple) palloc0(HEAPTUPLESIZE + hdr_len + enc_len);
    enc->t_len      = (uint32) (hdr_len + enc_len);
    enc->t_self     = plain->t_self;
    enc->t_tableOid = plain->t_tableOid;
    enc->t_data     = (HeapTupleHeader) ((char *) enc + HEAPTUPLESIZE);
    memcpy(enc->t_data, plain->t_data, hdr_len);                 /* header verbatim */
    memcpy((char *) enc->t_data + hdr_len, enc_buf, enc_len);    /* encrypted payload */
    pfree(enc_buf);  /* ciphertext - no need to cleanse */

    /*
     * Clear HEAP_HASEXTERNAL on the encrypted tuple.  From the core's point of
     * view the encrypted tuple is an opaque blob with no external columns — the
     * TOAST pointer lives INSIDE the ciphertext, invisible to heap_deform.
     * Leaving the bit set makes core touch the ciphertext as if it had external
     * data; in particular ExtractReplicaIdentity() (heap_delete/heap_update) runs
     * toast_flatten_tuple()/heap_deform_tuple() on the ciphertext and logs a
     * garbage replica identity, breaking logical UPDATE/DELETE.  TOAST lifecycle
     * is driven by the TAM itself (per-attribute VARATT scan on the decrypted
     * tuple, tde_tuple_has_external_slow), not this bit — and VACUUM FULL already
     * writes encrypted tuples with this bit cleared, so the codebase copes.
     */
    enc->t_data->t_infomask &= ~HEAP_HASEXTERNAL;

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
tde_decrypt_heap_tuple(HeapTuple enc, Oid relid)
{
    Size        hdr_len   = enc->t_data->t_hoff;
    char       *enc_data  = (char *) enc->t_data + hdr_len;
    Size        enc_len   = enc->t_len - hdr_len;
    Size        pt_len    = enc_len - TDE_V4_OVERHEAD;
    HeapTuple   plain;
    /* Pass-through mode: stored tuple is plaintext — return a copy. */
    if (!pg_vault_tde_enabled)
        return heap_copytuple(enc);
    /* Every v4 tuple carries TDE_V4_OVERHEAD bytes; shorter means corrupt. */
    if (hdr_len > enc->t_len || enc_len < (Size) TDE_V4_OVERHEAD)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("pg_vault_tde: encrypted tuple too short (%zu bytes)",
                        enc_len)));
    /* Allocate once, copy header, then decrypt straight into user-data. */
    plain = (HeapTuple) palloc0(HEAPTUPLESIZE + hdr_len + pt_len);
    plain->t_data = (HeapTupleHeader) ((char *) plain + HEAPTUPLESIZE);
    memcpy(plain->t_data, enc->t_data, hdr_len);
    /* GCM auth failure ereports inside; returns false only on non-v4 version byte. */
    if (!tde_gcm_decrypt(relid, enc_data, enc_len,
                         (char *) plain->t_data + hdr_len, &pt_len))
    {
        pfree(plain);
        ereport(ERROR,
                    (errmsg("pg_vault_tde: decryption failed")));
    }
    plain->t_len      = (uint32) (hdr_len + pt_len);
    plain->t_self     = enc->t_self;
    plain->t_tableOid = enc->t_tableOid;
    return plain;
}
/*
 * pg_vault_tde_decode_slot
 *
 * Common helper for all read paths: given a slot that contains an encrypted
 * buffer-backed HeapTuple (filled by a heapam call), swap in the decrypted
 * equivalent.
 *
 * PERFORMANCE CRITICAL — buffer pin management:
 *
 * We must NOT call ExecClearTuple() explicitly before the decrypt step.
 * Doing so releases the shared buffer pin immediately after copying ONE
 * tuple.  During a sequential scan the buffer manager may then evict the
 * page, forcing a re-pin (shared-buffer hit) on the very next tuple that
 * lives on the same page.  The result is O(rows) buffer hits instead of
 * O(pages) — a 4x overhead for 1M rows (~4M hits vs ~7K).
 *
 * Instead we let ExecForceStoreHeapTuple() release the pin internally
 * (it calls ExecClearTuple as its first step).  The pin stays held during
 * the in-place decrypt, and is released only once per tuple
 * by the force-store call — preserving the natural page-at-a-time access
 * pattern of heapam.
 */
static void
pg_vault_tde_decode_slot(TupleTableSlot *slot)
{
    BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
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
     * Decrypt the buffer-backed tuple directly while the slot still holds the
     * pin.  tde_decrypt_heap_tuple pallocs the plaintext copy; the encrypted
     * source is read straight from the shared buffer.
     *
     * NOTE: Do NOT call ExecClearTuple() here.  The buffer pin must stay
     * held until ExecForceStoreHeapTuple() below, which releases it as
     * part of its internal ExecClearTuple.  Releasing early causes O(rows)
     * buffer hits during sequential scans (see function header comment).
     */
    /* Decrypt (verifies GCM tag; ereport(ERROR) on tamper) */
    /*
     * Extract the relation OID from the encrypted tuple copy.
     * heapam sets t_tableOid = RelationGetRelid(scan->rs_rd) when filling
     * slots during a heap scan, so this is valid here (buffer still pinned
     * when heap_copytuple runs above).
     * For tuples from index scans, t_tableOid is also set by heap_hot_search_buffer.
     */
    plain = tde_decrypt_heap_tuple(bslot->base.tuple, saved_tableoid);


    /* Stamp physical address onto decrypted tuple */
    ItemPointerCopy(&saved_tid, &plain->t_self);
    plain->t_tableOid = saved_tableoid;
    /*
     * Store decrypted tuple; slot takes ownership (shouldFree=true).
     *
     * ExecForceStoreHeapTuple calls ExecClearTuple internally as its first
     * step, which releases the buffer pin.  This is the ONLY place the pin
     * is released — exactly once per tuple, and only after the plaintext copy
     * has already been produced by tde_decrypt_heap_tuple above.
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
    (void) rel;
    return &TTSOpsBufferHeapTuple;
}
/* ---- Sequential scan (SeqScan, TidRangeScan) ---- */
/*
 * pg_vault_tde_scan_getnextslot
 *
 * SeqScan / TidRangeScan read path.  Delegates to heapam which fills the
 * slot with a buffer-backed encrypted tuple, then decrypts in-place via
 * decode_slot.  This is the most commonly exercised read path in OLTP.
 *
 * v1.6: For TOAST tables, TOAST chunks are now encrypted (prev. plaintext v1.0–v1.6).
 * When we receive a TOAST chunk, tde_decrypt_heap_tuple will call
 * pg_vault_tde_kms_get_rel_dek(TOAST_relid, ...) which automatically routes to
 * the parent table's DEK, so the chunk is correctly decrypted.
 */
static bool
pg_vault_tde_scan_getnextslot(TableScanDesc scan, ScanDirection direction,
                               TupleTableSlot *slot)
{
    if (!heapam_scan_getnextslot_cb(scan, direction, slot))
        return false;
    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);  /* decode handles TOAST chunks automatically */
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
 *
 * v1.6: TOAST chunks are now encrypted.  We decrypt after the delegate call
 * using automatic routing (tde_decrypt_heap_tuple → pg_vault_tde_kms_get_rel_dek
 * handles TOAST relid → parent_relid mapping).
 */
static bool
pg_vault_tde_index_fetch_tuple(struct IndexFetchTableData *scan,
                                ItemPointer tid, Snapshot snapshot,
                                TupleTableSlot *slot,
                                bool *call_again, bool *all_dead)
{
    bool                     result;
    const TableAmRoutine    *saved_am;
    const TableAmRoutine   **rdam;
    saved_am = scan->rel->rd_tableam;
    rdam     = (const TableAmRoutine **) (void *) &scan->rel->rd_tableam;
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
        pg_vault_tde_decode_slot(slot);  /* automatic TOAST parent_relid routing */
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
 *
 * v1.6: TOAST chunks are now encrypted and decrypted automatically.
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
        pg_vault_tde_decode_slot(slot);  /* automatic TOAST routing */
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
        pg_vault_tde_decode_slot(slot);  /* automatic TOAST routing */
    return true;
}
#endif
/*
 * pg_vault_tde_scan_analyze_next_tuple
 *
 * Covers ANALYZE / autovacuum analyze.  Without this, pg_statistic entries
 * are computed over ciphertext leading to wildly wrong cardinality estimates
 * and broken query plans.
 *
 * v1.6: TOAST chunks are now encrypted and decrypted automatically.
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
        pg_vault_tde_decode_slot(slot);  /* automatic TOAST routing */
    return true;
}
/*
 * pg_vault_tde_scan_sample_next_tuple
 *
 * Covers TABLESAMPLE clauses (e.g., SELECT ... FROM t TABLESAMPLE BERNOULLI).
 *
 * v1.6: TOAST chunks are now encrypted and decrypted automatically.
 */
static bool
pg_vault_tde_scan_sample_next_tuple(TableScanDesc scan,
                                     struct SampleScanState *scanstate,
                                     TupleTableSlot *slot)
{
    if (!heapam_scan_sample_next_tuple_cb(scan, scanstate, slot))
        return false;
    if (!TupIsNull(slot))
        pg_vault_tde_decode_slot(slot);  /* automatic TOAST routing */
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
    OffsetNumber            root_offsets[MaxHeapTuplesPerPage];
    BlockNumber             root_blkno = InvalidBlockNumber;
    /*
     * TOAST relations: do NOT delegate to heapam's index_build_range_scan.
     * heapam's implementation calls heap_getnext, whose PG18 identity check
     * (rd_tableam == GetHeapamTableAmRoutine) FAILS for our encrypted_heap
     * AM and aborts with "only heap AM is supported".
     *
     * The custom scan loop below dispatches via table_scan_getnextslot →
     * pg_vault_tde_scan_getnextslot, which decrypts TOAST chunks correctly
     * before FormIndexDatum extracts the index keys (chunk_id, chunk_seq).
     */
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
     * rd_tableam->scan_getnextslot, which is our decrypt wrapper
     * (pg_vault_tde_scan_getnextslot → pg_vault_tde_decode_slot).
     * The slot receives decrypted plaintext data.
     *
     * MEMORY CONTEXT DISCIPLINE — why we switch contexts around the scan:
     *
     * decode_slot allocates the decrypted HeapTuple via palloc in
     * CurrentMemoryContext and stores it in the slot with shouldFree=true
     * (ExecForceStoreHeapTuple).  The slot takes ownership: the next
     * ExecClearTuple will pfree the tuple.
     *
     * We also have a per-tuple ExprContext (ecxt_per_tuple_memory) that
     * is reset each iteration to reclaim FormIndexDatum temporaries and
     * encrypted index datums.
     *
     * BUG (fixed): if table_scan_getnextslot is called while
     * CurrentMemoryContext == ecxt_per_tuple_memory, the decrypted tuple
     * ends up IN that context.  MemoryContextReset then frees it (zeroing
     * the palloc chunk header).  On the next iteration, ExecClearTuple
     * sees TTS_FLAG_SHOULDFREE and calls pfree on the now-dead pointer
     * → "pfree called with invalid pointer (header 0x0000000000000000)".
     *
     * Fix: capture the caller's MemoryContext ("scan_mcxt") BEFORE the
     * loop, and switch to it for the table_scan_getnextslot call.  This
     * ensures decode_slot's decrypted tuple lives in a stable context
     * that is NOT reset per-tuple.  Only FormIndexDatum evaluation and
     * index-key encryption run in ecxt_per_tuple_memory.
     */
    {
        MemoryContext scan_mcxt = CurrentMemoryContext;
        for (;;)
        {
            HeapTuple       heapTuple;
            bool            tupleIsAlive = true;
            MemoryContext   oldcxt;
            ItemPointerData itid;

            CHECK_FOR_INTERRUPTS();
            /*
             * Reset per-tuple memory from the previous iteration.  This
             * frees FormIndexDatum temporaries and encrypted index datums.
             * The decrypted HeapTuple in the slot is NOT in this context
             * (it lives in scan_mcxt), so this is safe.
             */
            ResetExprContext(econtext);
            /*
             * Proactively clear the slot to pfree the decoded tuple from
             * the previous iteration NOW, while its palloc chunk header
             * is still valid.  Without this, the pfree happens inside
             * heapam's tts_buffer_heap_store_tuple (called during the
             * next table_scan_getnextslot), which is too late if any
             * intermediate operation corrupted the chunk header.
             *
             * On the first iteration the slot is empty, so this is a
             * no-op.  On subsequent iterations the slot holds a decoded
             * plaintext tuple with TTS_FLAG_SHOULDFREE, allocated in
             * scan_mcxt by ExecForceStoreHeapTuple → heap_copytuple.
             * ExecClearTuple calls tts_buffer_heap_clear which does
             * heap_freetuple (pfree) and resets the slot to empty state.
             */
            ExecClearTuple(slot);
            /*
             * Fetch the next decrypted tuple.  We explicitly switch to
             * scan_mcxt so that decode_slot's palloc (inside
             * tde_decrypt_heap_tuple) allocates the decrypted HeapTuple
             * in the stable context, not in ecxt_per_tuple_memory.
             */
            oldcxt = MemoryContextSwitchTo(scan_mcxt);
            if (!table_scan_getnextslot(scan, ForwardScanDirection, slot))
            {
                MemoryContextSwitchTo(oldcxt);
                break;
            }
            MemoryContextSwitchTo(oldcxt);
            /*
             * For SnapshotAny (used during some non-concurrent index builds)
             * we'd need to check visibility explicitly, but CREATE INDEX
             * CONCURRENTLY takes a different code path.
             */
            if (!tupleIsAlive)
                continue;
            /*
             * Switch to per-tuple context for FormIndexDatum evaluation
             * and index-key encryption.  These allocations are ephemeral
             * and will be reclaimed by ResetExprContext at the top of the
             * next iteration.
             */
            oldcxt = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);
            FormIndexDatum(index_info, slot, estate, values, isnull);
            heapTuple = ExecFetchSlotHeapTuple(slot, false, NULL);


            /* 
             * If HeapTuple is HeapOnly it can't have index to directly 
             * point to it. The index should point to the root tuple (line pointer).
             * This happen if a tuple has been update in HOT method.
             */
            itid = heapTuple->t_self;

            if(HeapTupleIsHeapOnly(heapTuple))
            {
                BlockNumber     blkno =  ItemPointerGetBlockNumber(&itid); 
                OffsetNumber off;

                if(blkno != root_blkno)
                {
                    Buffer buf = ReadBuffer(heap_rel, blkno);
                    LockBuffer(buf, BUFFER_LOCK_SHARE);

                    /* 
                     * Populate a 1-based OffsetNumber array with values for the 
                     * whole page. Select the correspondent to heapTuple below 
                     * in the code with ItemPointerGetOffsetNumber
                     */
                    heap_get_root_tuples(BufferGetPage(buf), root_offsets);

                    LockBuffer(buf, BUFFER_LOCK_UNLOCK);
                    ReleaseBuffer(buf);
                    root_blkno = blkno;
                }

                off = ItemPointerGetOffsetNumber(&itid);
                ItemPointerSet(&itid, blkno, root_offsets[off-1]);
            }
            /*
             * If a tde_btree index is being built (signalled by IAM's
             * ambuild), encrypt each non-null index key value with
             * AES-256-SIV before passing it to the btree build callback.
             *
             * We build a SEPARATE enc_values[] array rather than modifying
             * values[] in-place.  _bt_spool copies the datum bytes into
             * its own IndexTuple buffer immediately, so the palloc'd
             * enc_bytea does not need to outlive the callback call.
             */
            if (tde_iam_build_in_progress)
            {
                Datum  enc_values[INDEX_MAX_KEYS];
                bool   enc_isnull[INDEX_MAX_KEYS];
                int    nbuildcols = index_info->ii_NumIndexAttrs;
                int    kcol;
                memcpy(enc_values, values, nbuildcols * sizeof(Datum));
                memcpy(enc_isnull, isnull, nbuildcols * sizeof(bool));
                for (kcol = 0; kcol < nbuildcols; kcol++)
                {
                    if (!enc_isnull[kcol])
                    {
                        if (TDE_IS_ENC_OPS_COL(index_rel, kcol))
                        {
                            enc_values[kcol] = tde_iam_encrypt_fixed_type_datum(
                                                   index_rel,
                                                   enc_values[kcol],
                                                   index_rel->rd_opcintype[kcol]);
                        }
                        else
                        {
                            Form_pg_attribute att = TupleDescAttr(index_rel->rd_att, kcol);
                            enc_values[kcol] = tde_iam_encrypt_index_datum(
                                                    index_rel,
                                                   enc_values[kcol],
                                                   att->attbyval,
                                                   att->attlen);
                        }
                    }
                }
                MemoryContextSwitchTo(oldcxt);
                callback(index_rel, &itid, enc_values, enc_isnull,
                         tupleIsAlive, callback_state);
            }
            else
            {
                MemoryContextSwitchTo(oldcxt);
                callback(index_rel, &itid, values, isnull,
                         tupleIsAlive, callback_state);
            }
            reltuples += 1;
        }
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
 *
 * v1.6: TOAST chunks are now encrypted and decrypted automatically.
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
        pg_vault_tde_decode_slot(slot);  /* automatic TOAST routing */
    return true;
}
/*
 * pg_vault_tde_tuple_lock
 *
 * Covers SELECT FOR UPDATE / FOR SHARE.  heapam acquires a tuple-level
 * lock and populates the slot with the locked tuple version.  The slot
 * is only valid on TM_Ok; other results (TM_zd, TM_BeingModified)
 * leave the slot empty or partially filled, so we decrypt only on TM_Ok.
 *
 * v1.6: TOAST chunks are now encrypted and decrypted automatically.
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
        pg_vault_tde_decode_slot(slot);  /* automatic TOAST routing */
    return result;
}

/*
 * pg_vault_tde_tuple_satisfies_snapshot
 *
 * Visibility recheck used by RI foreign-key triggers via
 * table_tuple_satisfies_snapshot (RI_FKey_check, ri_triggers.c).  heapam's
 * version takes the slot's pinned buffer content lock and runs
 * HeapTupleSatisfiesVisibility on the on-buffer tuple — it asserts the slot
 * still holds a valid buffer pin.
 *
 * Our read paths decrypt into a palloc'd HeapTuple and release the pin
 * (decode_slot leaves bslot->buffer == InvalidBuffer), so delegating would
 * call LockBuffer(InvalidBuffer) → GetBufferDescriptor(-1) → SIGSEGV.
 *
 * The MVCC header is plaintext and copied verbatim into the decrypted tuple,
 * so visibility only needs the page the tuple lives on (for hint bits).
 * Re-pin it from the tuple's physical TID, lock shared, run the standard check.
 */
static bool
pg_vault_tde_tuple_satisfies_snapshot(Relation rel, TupleTableSlot *slot,
                                       Snapshot snapshot)
{
    BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
    Buffer  buffer;
    bool    res;

    Assert(TTS_IS_BUFFERTUPLE(slot));

    /* Still buffer-backed (non-decrypted slot): heapam handles it directly. */
    if (bslot->buffer != InvalidBuffer)
        return heapam_tuple_satisfies_snapshot_cb(rel, slot, snapshot);

    /* Decrypted slot: re-pin the page the tuple lives on for the check. */
    buffer = ReadBuffer(rel,
                        ItemPointerGetBlockNumber(&bslot->base.tuple->t_self));
    LockBuffer(buffer, BUFFER_LOCK_SHARE);
    res = HeapTupleSatisfiesVisibility(bslot->base.tuple, snapshot, buffer);
    LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
    ReleaseBuffer(buffer);
    return res;
}

/*
 * pg_vault_tde_toast_insert_or_update
 *
 * Decides whether a tuple needs custom TOAST handling and, if so, delegates
 * to pg_vault_tde_toast_tuple() which splits oversized attributes into
 * encrypted TOAST chunks, stores them in the TOAST relation, and returns a
 * new tuple with external varlena pointers substituted in place.
 *
 * If the tuple fits within TOAST_TUPLE_THRESHOLD or the relation has no TOAST
 * table, the original tuple is returned unchanged (no allocation).
 *
 * Called from every write path (tuple_insert, tuple_insert_speculative,
 * multi_insert, tuple_update) before tde_encrypt_heap_tuple so that the
 * main-table row is always small (≤ TOAST_TUPLE_TARGET) when it reaches
 * heap_insert / heap_update.
 */
static HeapTuple
pg_vault_tde_toast_insert_or_update(Relation rel, HeapTuple tup,
                                     HeapTuple old_tup, int options)
{
    if (OidIsValid(rel->rd_rel->reltoastrelid) &&
        tup->t_len > TOAST_TUPLE_THRESHOLD)
    {
        return pg_vault_tde_toast_tuple(rel, tup, old_tup, options);
    }
    else
    {
        return tup;
    }
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
 * TOAST must happen BEFORE encryption in a custom chunk writer path.
 * The core plaintext TOAST path is intentionally disabled.
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
    HeapTuple  plain = NULL;
    HeapTuple  toasted = NULL;
    HeapTuple  enc = NULL;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);
    /*
     * The PG_TRY wraps the entire encrypt → heap_insert pipeline so errors
     * also perform local cleanup (reltoastrelid restore, OPENSSL_cleanse, pfree).
     */
    PG_TRY();
    {
        enc = tde_prepare_encrypt_tuple(rel, plain, NULL, &toasted, options);
        heap_insert(rel, enc, cid, options, bistate);

        ItemPointerCopy(&enc->t_self, &slot->tts_tid);
        slot->tts_tableOid = enc->t_tableOid;
    }
    PG_CATCH();
    {
        if (shouldFree && plain != NULL)
        {
            tde_release_plain(plain);
        }
        if (toasted != NULL && toasted != plain)
            pfree(toasted);
        if (enc != NULL)
            pfree(enc);
        PG_RE_THROW();
    }
    PG_END_TRY();
    if (shouldFree)
    {
        tde_release_plain(plain);
    }
    if (toasted != plain)
        pfree(toasted);
    pfree(enc);
}
/*
 * pg_vault_tde_tuple_insert_speculative
 *
 * Speculative INSERT path used by ON CONFLICT DO NOTHING / DO UPDATE (UPSERT).
 * Mirrors pg_vault_tde_tuple_insert but stamps the speculative token onto the
 * HeapTupleHeader BEFORE encryption so the token survives the round-trip.
 *
 * The speculative token occupies bytes in the HeapTupleHeader, which we leave
 * as plaintext (same as xmin/xmax/ctid).  heap_confirm_speculative_insertion
 * later reads and clears the token directly on the page without going through
 * our TAM, so it must be in the unencrypted header region.
 */
static void
pg_vault_tde_tuple_insert_speculative(Relation rel, TupleTableSlot *slot,
                                       CommandId cid, volatile int options,
                                       struct BulkInsertStateData *bistate,
                                       uint32 specToken)
{
    bool       shouldFree = true;
    HeapTuple  plain = NULL;
    HeapTuple  toasted = NULL;
    HeapTuple  enc = NULL;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);
    /* Stamp the speculative token on the header BEFORE encrypting so it is
     * preserved verbatim in the encrypted tuple's plaintext header area.
     *
    * NOTE: HEAP_INSERT_SPECULATIVE must be stamped in the tuple header before
    * encryption so speculative insertion metadata survives round-trip. */
    HeapTupleHeaderSetSpeculativeToken(plain->t_data, specToken);
    options |= HEAP_INSERT_SPECULATIVE;
    PG_TRY();
    {
        enc = tde_prepare_encrypt_tuple(rel, plain, NULL, &toasted, options);
        heap_insert(rel, enc, cid, options, bistate);

        ItemPointerCopy(&enc->t_self, &slot->tts_tid);
        slot->tts_tableOid = enc->t_tableOid;
    }
    PG_CATCH();
    {
        if (shouldFree && plain != NULL)
            tde_release_plain(plain);
        if (toasted != NULL && toasted != plain)
            pfree(toasted);
        if (enc != NULL)
            pfree(enc);
        PG_RE_THROW();
    }
    PG_END_TRY();
    if (shouldFree)
        tde_release_plain(plain);
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
    TupleDesc   tupdesc = RelationGetDescr(rel);

    /* In-flight intermediates for the iteration that may throw */
    volatile HeapTuple plain_inflight = NULL;
    volatile HeapTuple toasted_inflight = NULL;
    volatile bool      plain_inflight_owned = false;
    enc_tuples = (HeapTuple *) palloc(nslots * sizeof(HeapTuple));
    enc_slots  = (TupleTableSlot **) palloc(nslots * sizeof(TupleTableSlot *));
    /*
    * Phase 1: pre-TOAST (custom writer) + encrypt each tuple.
     *
     * We build temporary HeapTupleTableSlot slots to hold the encrypted
     * tuples, because PG17+ heap_multi_insert takes TupleTableSlot **.
     * The original slots survive untouched — COPY needs them later for
     * index key formation via ExecInsertIndexTuples.
     *
    * The PG_TRY also covers pre-TOAST handling so that an error
    * (including from tde_encrypt_heap_tuple) restores
     * reltoastrelid and OPENSSL_cleanses the plaintext intermediates.
    * TOAST writes in the custom path are expected to be transactional.
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
            
            /* Track in-flight pointers for the cleanup path */
            plain_inflight = plain;
            plain_inflight_owned = sf;
            toasted_inflight = NULL;
            
            enc_tuples[i] = tde_prepare_encrypt_tuple(rel, plain, NULL, &toasted, options);

            toasted_inflight = (toasted != plain) ? toasted : NULL;
            /* Create a temporary slot and store the encrypted tuple in it */
            enc_slots[i] = MakeSingleTupleTableSlot(tupdesc,
                                                     &TTSOpsHeapTuple);
            ExecForceStoreHeapTuple(enc_tuples[i], enc_slots[i], false);
            encrypted_count = i + 1;
            /* Free intermediates eagerly */
            if (toasted != plain)
                pfree(toasted);
            if (sf)
                tde_release_plain(plain);
            /* Iteration completed cleanly — clear in-flight tracking */
            plain_inflight = NULL;
            plain_inflight_owned = false;
            toasted_inflight = NULL;
        }
        /*
         * Phase 2: batched heap insert with TOAST suppressed.
         *
         * Suppress reltoastrelid so heap_multi_insert does not attempt to
         * TOAST the (already encrypted) tuples — their byte pattern is
         * random-looking ciphertext and would confuse the TOAST deformer.
         */
      
        heap_multi_insert(rel, enc_slots, nslots, cid, options, bistate);
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
        /* Clean up in-flight iteration plaintexts (cleanse + free) */
        if (plain_inflight != NULL && plain_inflight_owned)
        {
            HeapTuple p = plain_inflight;
            tde_release_plain(p);
        }
        if (toasted_inflight != NULL)
            pfree(toasted_inflight);
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
    HeapTuple  plain = NULL;
    HeapTuple volatile old_tuple = NULL;
    HeapTuple  toasted = NULL;
    HeapTuple  enc = NULL;
    TM_Result  result;
   
    TupleTableSlot *slot_old = NULL;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);

    slot_old = table_slot_create(rel, NULL);

    PG_TRY();
    {
        bool old_has_external = false;
        if (pg_vault_tde_tuple_fetch_row_version(rel, otid, snapshot, slot_old))
        {
            old_tuple = ExecFetchSlotHeapTuple(slot_old, false, NULL);
            old_has_external = tde_tuple_has_external(old_tuple, rel);
        }

        enc = tde_prepare_encrypt_tuple(rel, plain, old_tuple, &toasted, 0);

        result = heap_update(rel, otid, enc, cid, crosscheck, wait,
                             tmfd, lockmode, update_indexes);

        if (result == TM_Ok)
        {
            ItemPointerCopy(&enc->t_self, &slot->tts_tid);
            slot->tts_tableOid = enc->t_tableOid;

            /* Check toasted (plaintext): enc is ciphertext with HASEXTERNAL cleared. */
            if (old_tuple != NULL && old_has_external && !HeapTupleHasExternal(toasted))
                heap_toast_delete(rel, old_tuple, false);
        }
    }
    PG_CATCH();
    {
        if (shouldFree && plain != NULL)
        {
            tde_release_plain(plain);
        }
        if (toasted != NULL && toasted != plain)
            pfree(toasted);

        if (enc != NULL)
            pfree(enc);

        if (slot_old != NULL)
            ExecDropSingleTupleTableSlot(slot_old);

        PG_RE_THROW();
    }
    PG_END_TRY();
    if (shouldFree)
    {
        tde_release_plain(plain);
    }
    if (toasted != plain)
        pfree(toasted);
    pfree(enc);

    if (slot_old != NULL)
        ExecDropSingleTupleTableSlot(slot_old);

    return result;
}

/*
 * tde_tuple_has_external
 *
 * Per-attribute scan for VARATT_IS_EXTERNAL varlenas on a decrypted heap
 * tuple. This is necessary because flag HEAP_HASEXTERNAL is cleansed 
 * in insert before calling heap_insert(), otherwise it will call
 * heap_toast_insert_or_update.
*/
static bool
tde_tuple_has_external(HeapTuple tup, Relation rel)
{
    int natts;
    TupleDesc tupdesc;
    Datum stack_values[MAX_STACK_ATTRS];
    bool  stack_isnull[MAX_STACK_ATTRS];
    
    Datum *values = stack_values;
    bool  *isnull = stack_isnull;
    bool  has_ext = false;

    if(!OidIsValid(rel->rd_rel->reltoastrelid)) 
        return false;
    
    tupdesc = RelationGetDescr(rel);
    natts = tupdesc->natts;

    if (unlikely(natts > MAX_STACK_ATTRS))
    {
        values = (Datum *) palloc(natts * sizeof(Datum));
        isnull = (bool *) palloc(natts * sizeof(bool));
    }

    /* 
     * Previous version was using heap_getattr (O(n)) in a for loop
     * for every attr in heaptuple resulting in a O(n²). 
     * In the current vesion: Deforming is O(n) so the total complexity 
     * is O(n + n) = O(n).
     */
    heap_deform_tuple(tup, tupdesc, values, isnull); 

    for (int i = 0; i < natts; i++)
    {
        Form_pg_attribute att = TupleDescAttr(tupdesc, i);

        if (!isnull[i] && !att->attisdropped && att->attlen == -1)
        {
            if (VARATT_IS_EXTERNAL(DatumGetPointer(values[i])))
            {
                has_ext = true;
                break; 
            }
        }
    }

    if (unlikely(natts > MAX_STACK_ATTRS))
    {
       pfree(values);
       pfree(isnull);
    }

    return has_ext;
}

/*
 * pg_vault_tde_tuple_delete
 *
 * DELETE path.  Delegates the physical row removal to heapam's tuple_delete,
 * then cleans up any TOAST chunks that belong to the deleted row.
 *
 * TOAST detection is two-level:
 *  1. HeapTupleHasExternal(plain) — fast-path check of the HEAP_HASEXTERNAL
 *     infomask bit.  Normally reliable, but VACUUM FULL clears this bit on
 *     encrypted tuples to satisfy rewrite_heap_tuple's assertion
 *     (see pg_vault_tde_relation_copy_for_cluster).
 *  2. tde_tuple_has_external() — per-attribute VARATT_IS_EXTERNAL scan
 *     on the decrypted tuple.  Falls back to this when the bit is clear so
 *     TOAST chunks from VACUUM FULL-rewritten rows are never orphaned.
 *
 * We must fetch and decrypt the tuple BEFORE calling heapam's delete so that
 * the decrypted plaintext is available for the TOAST scan.  After TM_Ok is
 * confirmed, heap_toast_delete cleans up the TOAST relation.
 */
static TM_Result
pg_vault_tde_tuple_delete(Relation rel,
                           ItemPointer tid,
                           CommandId cid,
                           Snapshot snapshot,
                           Snapshot crosscheck,
                           bool wait,
                           TM_FailureData *tmfd,
                           bool changingPart)
{
    TM_Result result;
    TupleTableSlot * slot = NULL;
    HeapTuple volatile plain = NULL;
   
    bool volatile has_externals = false;
    bool shouldFree = false;

    slot = table_slot_create(rel, NULL);

    if(pg_vault_tde_tuple_fetch_row_version(rel, tid, snapshot, slot)){
        plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
        /*
         * Check HEAP_HASEXTERNAL first (fast path).  Fall back to a
         * per-attribute scan because VACUUM FULL clears HEAP_HASEXTERNAL
         * from encrypted tuples to satisfy rewrite_heap_tuple's assertion;
         * without the fallback those TOAST chunks would be orphaned.
         */
        has_externals = tde_tuple_has_external(plain, rel);
    }

    PG_TRY();
    {
        result = heapam_tuple_delete_cb(rel, tid, cid, snapshot, crosscheck, wait, tmfd, changingPart);

        if(result == TM_Ok && has_externals) heap_toast_delete(rel, plain, false);
    }
    PG_CATCH();
    {
        if (shouldFree)
            tde_release_plain(plain);

        if (slot != NULL)
            ExecDropSingleTupleTableSlot(slot);

        PG_RE_THROW();
    }
    PG_END_TRY();

    if (shouldFree)
        tde_release_plain(plain);
    
    if (slot != NULL)
        ExecDropSingleTupleTableSlot(slot);

    return result;
}


/*
 * pg_vault_tde_relation_copy_for_cluster
 *
 * Called by VACUUM FULL and CLUSTER to rewrite all live tuples from OldTable
 * into NewTable.
 *
 * We cannot use heapam_relation_copy_for_cluster for two reasons:
 *
 *  1. Buffer-pin problem: table_beginscan dispatches to our TAM override
 *     (pg_vault_tde_scan_getnextslot), which decrypts and calls
 *     ExecForceStoreHeapTuple — releasing the buffer pin before control
 *     returns to us.  HeapTupleSatisfiesVacuum then receives InvalidBuffer
 *     and crashes when it tries to set hint bits via MarkBufferDirtyHint.
 *
 *  2. TOAST problem: heapam's implementation calls toast_flatten_tuple on
 *     enc_raw (ciphertext), which tries to dereference TOAST pointers embedded
 *     in encrypted bytes → wild-pointer dereference → crash.
 *
 * Fix: scan OldTable directly via heap_beginscan / heap_getnext, which
 * bypasses our TAM override and keeps hscan->rs_cbuf valid.
 *
 * TOAST handling: if the decrypted tuple has external TOAST pointers (into
 * OldTable's TOAST relation), we bring all values inline via
 * toast_flatten_tuple (which reads TOAST chunks through our TAM →
 * tde_index_fetch_tuple → decode_slot, so each chunk is auto-decrypted),
 * then re-TOAST into NewTable via pg_vault_tde_toast_tuple (which encrypts
 * each new chunk).
 *
 * rewrite_heap_tuple asserts !HeapTupleHasExternal(newTuple).  For re-toasted
 * tuples we clear HEAP_HASEXTERNAL from enc_new's t_infomask before the call.
 * TOAST chunk cleanup on later DELETE is still correct because
 * pg_vault_tde_tuple_delete uses tde_tuple_has_external as a fallback
 * that does a per-attribute varlena tag scan instead of relying on the flag.
 */
static void
pg_vault_tde_relation_copy_for_cluster(Relation OldTable,
                                        Relation NewTable,
                                        Relation OldIndex,
                                        bool use_sort,
                                        TransactionId OldestXmin,
                                        TransactionId *xid_cutoff,
                                        MultiXactId *multi_cutoff,
                                        double *num_tuples,
                                        double *tups_vacuumed,
                                        double *tups_recently_dead)
{
    HeapScanDesc    hscan;
    HeapTuple       enc_raw;        /* raw ciphertext, points into buffer page */
    RewriteState    rwstate;
    TupleDesc       tupdesc = RelationGetDescr(OldTable);

    struct VacuumCutoffs cutoffs;

    /*
     * rd_tableam impersonation: heap_beginscan, heap_getnext, and
     * heap_endscan all assert rel->rd_tableam == GetHeapamTableAmRoutine().
     * We swap OldTable->rd_tableam for the duration of the entire scan and
     * restore it in a single place — after heap_endscan — whether we succeed
     * or not.  The outer PG_TRY guarantees restoration on any error path
     * (including errors thrown by the inner per-tuple PG_TRY).
     *
     * RelationData is per-backend (local relcache copy), so the swap is safe
     * from concurrency.
     */
    const TableAmRoutine       *saved_am = OldTable->rd_tableam;
    const TableAmRoutine      **rdam =
        (const TableAmRoutine **) (void *) &OldTable->rd_tableam;

    cutoffs.OldestXmin   = OldestXmin;
    cutoffs.relfrozenxid = OldTable->rd_rel->relfrozenxid;
    cutoffs.relminmxid   = OldTable->rd_rel->relminmxid;

    rwstate = begin_heap_rewrite(OldTable, NewTable, OldestXmin,
                                 *xid_cutoff, *multi_cutoff);

    *rdam = GetHeapamTableAmRoutine();

    /*
     * Outer PG_TRY: covers the full scan (beginscan → loop → endscan).
     * Its sole job is to restore *rdam on any error so that subsequent
     * operations on OldTable see the correct encrypted_heap AM again.
     * Crypto-material cleanup is handled by the inner per-tuple PG_TRY.
     */
    PG_TRY();
    {
        /*
         * PG17 introduced a mandatory async read stream in heapgettup.
         * heap_fetch_next_buffer asserts scan->rs_read_stream != NULL, and
         * the stream is created in heap_beginscan only when SO_TYPE_SEQSCAN
         * is present.  Without it, every heapgettup call crashes (Assert in
         * cassert builds, NULL-deref segfault in release builds).  This is
         * unconditional because it already applies on PG17, the minimum
         * supported version.
         */
        hscan = (HeapScanDesc) heap_beginscan(OldTable, SnapshotAny, 0, NULL,
                                              NULL,
                                              SO_TYPE_SEQSCAN |
                                              SO_ALLOW_STRAT | SO_ALLOW_SYNC);

        while ((enc_raw = heap_getnext((TableScanDesc) hscan,
                                       ForwardScanDirection)) != NULL)
        {
            Buffer          buf = hscan->rs_cbuf;
            HeapTuple       enc_copy = NULL;
            HeapTuple       plain = NULL;
            HeapTuple       plain_for_write = NULL;  /* what gets re-encrypted */
            HeapTuple       enc_new = NULL;

            HTSV_Result     res;
            HeapPageFreeze  pagefrz = {0};
            HeapTupleFreeze frz;
            bool            totally_frozen;
            bool volatile   had_external = false;

            CHECK_FOR_INTERRUPTS();

            /*
             * HeapTupleSatisfiesVacuum needs a valid buffer to call
             * MarkBufferDirtyHint when setting hint bits.  hscan->rs_cbuf is
             * valid here because heap_getnext has not yet advanced to the
             * next page.
             */
            res = HeapTupleSatisfiesVacuum(enc_raw, OldestXmin, buf);

            if (res == HEAPTUPLE_DEAD)
            {
                *tups_vacuumed += 1;
                continue;
            }
            if (res == HEAPTUPLE_RECENTLY_DEAD)
                *tups_recently_dead += 1;
            else if (res == HEAPTUPLE_LIVE)
                *num_tuples += 1;
            /* INSERT_IN_PROGRESS / DELETE_IN_PROGRESS: copy as-is */

            /*
             * Copy the encrypted tuple out of the buffer page.  heap_getnext
             * returns a pointer directly into the pinned page; the next call
             * may advance to a new page and unpin this one.  enc_copy also
             * serves as the "old" argument to rewrite_heap_tuple for MVCC
             * mapping.
             */
            enc_copy = heap_copytuple(enc_raw);

            /*
             * Apply tuple freeze to the plaintext HEADER of enc_copy.  Our
             * wire format stores the HeapTupleHeader (xmin, xmax, infomask,
             * infomask2, null bitmap) in plaintext; only [t_hoff .. t_len) is
             * encrypted.  tde_encrypt_heap_tuple copies the header verbatim,
             * so freeze changes applied here are preserved in enc_new.
             */
            if (heap_prepare_freeze_tuple(enc_copy->t_data, &cutoffs,
                                          &pagefrz, &frz, &totally_frozen))
            {
                enc_copy->t_data->t_infomask  = frz.t_infomask;
                enc_copy->t_data->t_infomask2 = frz.t_infomask2;
                HeapTupleHeaderSetXmax(enc_copy->t_data, frz.xmax);
            }

            /*
             * Inner PG_TRY: protects crypto key material (DEK copy inside
             * tde_decrypt/encrypt_heap_tuple).  Does NOT touch *rdam — the
             * outer PG_CATCH owns that responsibility.  PG_RE_THROW propagates
             * the error upward so the outer handler restores *rdam before the
             * error reaches the caller.
             */
            PG_TRY(2);
            {
                plain = tde_decrypt_heap_tuple(enc_copy, RelationGetRelid(OldTable));
                plain_for_write = plain;

                /* Header bit is cleared on disk (see tde_encrypt_heap_tuple);
                 * scan the plaintext, else the re-TOAST migration below is
                 * skipped and the rewrite keeps OldTable's TOAST pointers. */
                if (tde_tuple_has_external(plain, OldTable))
                {
                    /*
                     * External TOAST pointers in the decrypted tuple reference
                     * OldTable's TOAST relation.  Bring all values inline first
                     * (toast_flatten_tuple reads chunks via our TAM →
                     * auto-decrypted), then re-TOAST into NewTable
                     * (pg_vault_tde_toast_tuple encrypts each new chunk).
                     */
                    HeapTuple plain_flat;

                    plain_flat = toast_flatten_tuple(plain, tupdesc);

                    /* plain is no longer needed; cleanse before freeing */
                    {
                        Size hdr = plain->t_data->t_hoff;
                        OPENSSL_cleanse((char *) plain->t_data + hdr,
                                        plain->t_len - hdr);
                        pfree(plain);
                        plain = NULL;
                    }

                    plain_for_write = pg_vault_tde_toast_tuple(NewTable,
                                                                plain_flat, NULL, 0);
                    pfree(plain_flat);
                    had_external = true;
                }

                /*
                 * Encrypt the new tuple using OldTable's DEK, not NewTable's.
                 * After finish_heap_swap the physical file lands under
                 * OldTable's relid — the catalog entry for OldTable's relid
                 * must match the DEK used here or every subsequent read will
                 * get a GCM authentication failure.
                 */
                enc_new = tde_encrypt_heap_tuple(plain_for_write,
                                                 RelationGetRelid(OldTable));

                /*
                 * rewrite_heap_tuple asserts !HeapTupleHasExternal(newTuple):
                 * it expects TOAST to be flattened inline before the call.
                 * For re-toasted tuples enc_new has HEAP_HASEXTERNAL set in
                 * its plaintext header (the bit is valid in the plaintext
                 * domain — the encrypted data region contains opaque
                 * ciphertext, not actual TOAST pointers that
                 * rewrite_heap_tuple could dereference).
                 *
                 * Clear the flag so the assertion passes.
                 * pg_vault_tde_tuple_delete compensates via
                 * tde_tuple_has_external, which does a per-attribute
                 * VARATT_IS_EXTERNAL scan on the decrypted tuple regardless
                 * of this flag.
                 */
                if (had_external)
                    enc_new->t_data->t_infomask &= ~HEAP_HASEXTERNAL;

                rewrite_heap_tuple(rwstate, enc_copy, enc_new);
            }
            PG_CATCH(2);
            {
                /* Cleanse any plaintext key mterial before re-throwing. */
                if (plain != NULL)
                {
                    Size hdr = plain->t_data->t_hoff;
                    OPENSSL_cleanse((char *) plain->t_data + hdr,
                                    plain->t_len - hdr);
                    pfree(plain);
                }
                if (plain_for_write != NULL && plain_for_write != plain)
                {
                    Size hdr = plain_for_write->t_data->t_hoff;
                    OPENSSL_cleanse((char *) plain_for_write->t_data + hdr,
                                    plain_for_write->t_len - hdr);
                    pfree(plain_for_write);
                }
                if (enc_copy != NULL)
                    pfree(enc_copy);
                if (enc_new != NULL)
                    pfree(enc_new);
                PG_RE_THROW();  /* outer PG_CATCH will restore *rdam */
            }
            PG_END_TRY(2);

            /* Cleanse and free plaintext on the success path. */
            if (plain_for_write != NULL)
            {
                Size hdr = plain_for_write->t_data->t_hoff;
                OPENSSL_cleanse((char *) plain_for_write->t_data + hdr,
                                plain_for_write->t_len - hdr);
                pfree(plain_for_write);
                /* plain == plain_for_write (non-TOAST) or freed early (TOAST) */
            }
            pfree(enc_copy);
            pfree(enc_new);
        }   /* end while */

        heap_endscan((TableScanDesc) hscan);
        end_heap_rewrite(rwstate);
    }
    PG_CATCH();
    {
        /*
         * Restore the AM pointer before re-throwing.  heap_endscan may not
         * have been reached, but the relcache entry must be left consistent
         * for any subsequent operation on OldTable in this backend.
         */
        *rdam = saved_am;
        PG_RE_THROW();
    }
    PG_END_TRY();

    /* Restore on the success path (heap_endscan completed normally). */
    *rdam = saved_am;
}



/* ---- TOAST AM delegation ---- */
/*
 * pg_vault_tde_toast_am
 *
 * Selects the AM for TOAST tables created for encrypted_heap relations.
 *
 * When pg_vault_tde.toast_encryption = on (default), we return the OID of
 * the encrypted_heap AM so that TOAST chunks are stored encrypted.
 * Each chunk passes through our tuple_insert hook (tde_gcm_encrypt) and is
 * read back via our scan_getnextslot (tde_gcm_decrypt).  The external TOAST
 * pointer in the main table is unencrypted (it carries only OIDs and sequence
 * numbers, no payload).
 *
 * When toast_encryption = off, or when the encrypted_heap AM cannot be found
 * (e.g. during bootstrap), we fall back to HEAP_TABLE_AM_OID.  This keeps
 * the PG18 guard in heap_getnext() from triggering: without impersonation,
 * the TOAST index build calls heap_getnext() on the TOAST table which asserts
 * rd_tableam == GetHeapamTableAmRoutine().  Our pg_vault_tde_index_build_range_scan
 * correctly handles this via a custom scan loop, so the encrypted_heap AM
 * is safe here.
 */
static Oid
pg_vault_tde_toast_am(Relation rel)
{
    (void) rel;
    if (pg_vault_tde_toast_encryption)
    {
        /*
         * Look up the registered encrypted_heap AM OID from the catalog.
         * missing_ok = true so that if the AM is somehow unregistered (e.g.
         * during extension drop) we degrade gracefully to plain TOAST storage
         * rather than ERROR-ing out at CREATE TABLE time.
         */
        Oid encheap_oid = get_table_am_oid("encrypted_heap", true);
        if (OidIsValid(encheap_oid))
            return encheap_oid;
        ereport(WARNING,
                (errmsg("[TDE] encrypted_heap AM not found; TOAST will use standard heap"),
                 errhint("Ensure pg_vault_tde is installed and pg_vault_tde.toast_encryption=on is intentional.")));
    }
    /* Fallback: standard heap AM for TOAST (unencrypted chunks) */
    return HEAP_TABLE_AM_OID;
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
    heapam_scan_getnextslot_cb              = heapam->scan_getnextslot;
    heapam_index_fetch_tuple_cb             = heapam->index_fetch_tuple;
    heapam_scan_bitmap_next_tuple_cb        = heapam->scan_bitmap_next_tuple;
    heapam_scan_analyze_next_tuple_cb       = heapam->scan_analyze_next_tuple;
    heapam_scan_sample_next_tuple_cb        = heapam->scan_sample_next_tuple;
    heapam_tuple_fetch_row_version_cb       = heapam->tuple_fetch_row_version;
    heapam_tuple_lock_cb                    = heapam->tuple_lock;
    heapam_tuple_satisfies_snapshot_cb      = heapam->tuple_satisfies_snapshot;
    heapam_tuple_delete_cb                  = heapam->tuple_delete;
    /* --- Install encrypt/decrypt wrappers --- */
    /* Slot type: always buffer-backed (needed for decode_slot cast) */
    tde_methods.slot_callbacks              = pg_vault_tde_slot_callbacks;
    /* Write paths: encrypt before calling heapam storage layer */
    tde_methods.tuple_insert                = pg_vault_tde_tuple_insert;
    tde_methods.tuple_insert_speculative    = pg_vault_tde_tuple_insert_speculative;
    tde_methods.multi_insert                = pg_vault_tde_multi_insert;
    tde_methods.tuple_update                = pg_vault_tde_tuple_update;
    tde_methods.tuple_delete                = pg_vault_tde_tuple_delete;
    /* Read paths: delegate to heapam then decrypt the returned slot */
    tde_methods.scan_getnextslot            = pg_vault_tde_scan_getnextslot;
    tde_methods.index_fetch_tuple           = pg_vault_tde_index_fetch_tuple;
    tde_methods.scan_bitmap_next_tuple      = pg_vault_tde_scan_bitmap_next_tuple;
    tde_methods.scan_analyze_next_tuple     = pg_vault_tde_scan_analyze_next_tuple;
    tde_methods.scan_sample_next_tuple      = pg_vault_tde_scan_sample_next_tuple;
    tde_methods.tuple_fetch_row_version     = pg_vault_tde_tuple_fetch_row_version;
    tde_methods.tuple_lock                  = pg_vault_tde_tuple_lock;
    /* Visibility recheck (RI FK triggers): tolerate decrypted, unpinned slots */
    tde_methods.tuple_satisfies_snapshot    = pg_vault_tde_tuple_satisfies_snapshot;
    /* Index build: bypass rd_tableam identity check inside heap_getnext */
    tde_methods.index_build_range_scan      = pg_vault_tde_index_build_range_scan;
    tde_methods.relation_copy_for_cluster   = pg_vault_tde_relation_copy_for_cluster;
    /*
     * Ensure TOAST tables for encrypted_heap use encrypted_heap AM so that
     * chunk reads go through our TAM callbacks (tde_index_fetch_tuple →
     * decode_slot → tde_decrypt_heap_tuple).  The custom TOAST writer in
     * pg_vault_tde_toast_save_datum handles the write side.
     * When toast_encryption = off or the AM is not found, we fall back to
     * HEAP_TABLE_AM_OID (large column values work but are stored unencrypted).
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
 *   1. KMS provider replaces current DEK → prev_dek retained
 *   2. reencrypt_table() reads old rows (fallback to prev_dek),
 *      writes new tuples (encrypted with current DEK), and
 *      rebuilds any tde_btree indexes (SIV keys are DEK-bound)
 *   3. KMS provider wipes prev_dek after re-encryption completes
 *
 * Why tde_btree indexes must be rebuilt:
 *   AES-256-SIV is deterministic under a fixed DEK: same plaintext + same DEK
 *   → same ciphertext.  After DEK rotation the SIV ciphertexts stored in
 *   the index no longer match what aminsert would produce with the new DEK,
 *   so equality lookups silently return empty results.  REINDEX re-encrypts
 *   every key datum with the current DEK, restoring correctness.
 *   Standard btree indexes are unaffected (they store only ctid).
 *
 * After re-encryption, run VACUUM to physically remove old ciphertext
 * from the heap pages (dead tuples from the UPDATE still contain
 * old-DEK ciphertext until reclaimed).
 *
 * The batch_size parameter is accepted for API compatibility but currently
 * the entire table is re-encrypted in a single UPDATE statement.
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_reencrypt_table_sql);
PGDLLEXPORT Datum
pg_vault_tde_reencrypt_table_sql(PG_FUNCTION_ARGS)
{
    Oid                 relid = PG_GETARG_OID(0);

    pg_vault_tde_reencrypt_table(relid);

    PG_RETURN_VOID();
}

int64 pg_vault_tde_reencrypt_table(Oid relid)
{    
    Relation rel;
    TableScanDesc       scan;
    TupleTableSlot     *slot;
    CommandId           cid;
    TU_UpdateIndexes    update_idxs;
    LockTupleMode       lock_mode;
    List               *tde_index_oids = NIL;
    Oid                 tde_btree_amoid;
    int64               tuples_done = 0;

    rel = table_open(relid, RowExclusiveLock);
    slot = table_slot_create(rel, NULL);

    cid = GetCurrentCommandId(true);
    lock_mode = LockTupleExclusive;

    scan = table_beginscan(rel, GetActiveSnapshot(), 0, NULL);

    while (table_scan_getnextslot(scan, ForwardScanDirection, slot))
    {
        ItemPointerData otid = slot->tts_tid;
        TM_FailureData  tmfd;
        TM_Result       result;

        CHECK_FOR_INTERRUPTS();

        result = pg_vault_tde_tuple_update(rel,
                                           &otid,
                                           slot,
                                           cid,
                                           GetActiveSnapshot(),
                                           InvalidSnapshot,
                                           true,
                                           &tmfd,
                                           &lock_mode,
                                           &update_idxs);

        if (result != TM_Ok)
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("pg_vault_tde: reencrypting table failed with TAM code %d", result)));
        tuples_done++;
    }

    /*
     * Collect OIDs of tde_btree indexes before releasing the relation.
     * We must rebuild them because AES-256-SIV key material is DEK-bound:
     * after rotation the stored ciphertexts no longer match lookups under
     * the new DEK.  Standard btree (and heap) indexes need no rebuild.
     */
    tde_btree_amoid = get_index_am_oid("tde_btree", true);
    if (OidIsValid(tde_btree_amoid))
    {
        List       *idxlist = RelationGetIndexList(rel);
        ListCell   *lc;

        foreach(lc, idxlist)
        {
            Oid         idxoid = lfirst_oid(lc);
            Relation    idxrel = index_open(idxoid, AccessShareLock);

            if (idxrel->rd_rel->relam == tde_btree_amoid)
                tde_index_oids = lappend_oid(tde_index_oids, idxoid);

            index_close(idxrel, AccessShareLock);
        }
        list_free(idxlist);
    }

    ExecDropSingleTupleTableSlot(slot);
    table_endscan(scan);
    table_close(rel, NoLock); /* lock released at end of transaction */

    /*
     * Rebuild each tde_btree index with the new DEK.  reindex_index()
     * acquires AccessExclusiveLock on the index; we still hold
     * RowExclusiveLock on the heap from table_open above — within the same
     * transaction these are compatible (no self-deadlock).
     */
    if (tde_index_oids != NIL)
    {
        ReindexParams   reindex_params = {0};
        ListCell       *lc;

        foreach(lc, tde_index_oids)
        {
            Oid idxoid = lfirst_oid(lc);

            /*
             * Pass '\0' for persistence to inherit the index's own
             * relpersistence (RELPERSISTENCE_PERMANENT / UNLOGGED / TEMP).
             * Passing '\0' tells reindex_index not to override it.
             */
            reindex_index(NULL, idxoid, false, get_rel_persistence(idxoid), &reindex_params);
            ereport(NOTICE,
                    errmsg("pg_vault_tde: rebuilt tde_btree index %u on table %u",
                           idxoid, relid));
        }
        list_free(tde_index_oids);
    }

    ereport(NOTICE, errmsg("pg_vault_tde: reencrypted table: %u", relid));

    return tuples_done;
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
                HeapTuple plain = tde_decrypt_heap_tuple(bslot->base.tuple,
                                                          RelationGetRelid(rel));
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
 * Each encrypted tuple carries TDE_V4_OVERHEAD (37) bytes of overhead:
 * 1-byte version + 8-byte generation + 12-byte IV + 16-byte GCM tag.
 * The total overhead is simply total_tuples × 37.
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
    values[1] = Int64GetDatum(total * (int64) TDE_V4_OVERHEAD);
    result_tup = heap_form_tuple(tupdesc, values, nulls);
    PG_RETURN_DATUM(HeapTupleGetDatum(result_tup));
}
