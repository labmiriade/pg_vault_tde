/*
 * pg_vault_tde_rmgr.c — Custom WAL resource manager for encrypted TOAST.
 *
 * See src/include/pg_vault_tde_rmgr.h for the full rationale.  Encrypted TOAST
 * chunks are WAL-logged under TDE_RMGR_ID instead of RM_HEAP_ID so that:
 *
 *   - rm_redo delegates to heap_redo(): the record payload is the standard
 *     xl_heap_insert format, and heap_redo dispatches on the info bits, never
 *     on the rmid — so crash recovery / DR is unaffected.
 *
 *   - rm_decode replaces heap_decode for these records.  This is the whole
 *     point: heap_decode would queue the chunk into the reorder buffer's
 *     toast_hash, and ReorderBufferToastReplace() would later heap_deform the
 *     (still encrypted) main tuple to splice the chunks back in — producing
 *     garbage and crashing ("got sequence entry ... for toast chunk").  By
 *     routing chunks here, toast_hash stays NULL and core leaves the main
 *     tuple alone.
 *
 * Delivery of the decrypted TOAST value to the subscriber happens in two steps:
 *
 *   - rm_decode CAPTURES each encrypted chunk tuple into a per-transaction
 *     store (no catalog access — there is no historic snapshot during decode).
 *   - tde_toast_stitch(), called by the output plugin's change_cb AFTER the
 *     main tuple has been decrypted (historic snapshot active), reconstructs
 *     the plaintext value from the captured+decrypted chunks and rewrites the
 *     external on-disk toast pointers into in-memory INDIRECT pointers — a
 *     faithful analogue of core's ReorderBufferToastReplace(), but sourcing
 *     decrypted chunks instead of core's toast_hash and operating on the
 *     already-decrypted main tuple.  pgoutput then serializes the full value.
 *   - tde_toast_store_reset() frees a transaction's captured chunks (called by
 *     the output plugin at commit/begin).
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */

#include "postgres.h"

#include "access/detoast.h"         /* INDIRECT_POINTER_SIZE */
#include "access/heapam.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include "access/hio.h"
#include "access/visibilitymap.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "access/xloginsert.h"
#include "access/xlog_internal.h"
#include "access/xlogreader.h"
#include "catalog/catalog.h"        /* IsToastRelation */
#include "lib/ilist.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"              /* START/END_CRIT_SECTION */
#include "replication/decode.h"     /* XLogRecordBuffer */
#include "replication/logical.h"    /* LogicalDecodingContext */
#include "replication/reorderbuffer.h"
#include "replication/snapbuild.h"  /* SnapBuild* */
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "storage/predicate.h"      /* CheckForSerializableConflictIn */
#include "storage/relfilelocator.h"
#include "utils/hsearch.h"
#include "utils/inval.h"            /* CacheInvalidateHeapTuple */
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/relcache.h"         /* RelationIdGetRelation */
#include "varatt.h"
#include "pgstat.h"

#include "src/include/pg_vault_tde_rmgr.h"
#include "src/include/pg_vault_tde_tam.h"   /* tde_decrypt_heap_tuple */

/* ------------------------------------------------------------------------
 * Per-transaction capture store
 *
 * During decode we cannot touch the catalog (no historic snapshot), so we
 * stash the RAW encrypted chunk tuples keyed by xid and defer all decryption
 * and reassembly to stitch time (change_cb, snapshot active).
 * ------------------------------------------------------------------------ */

/* one captured (encrypted) toast chunk tuple */
typedef struct TdeCapturedChunk
{
    dlist_node      node;
    RelFileLocator  rlocator;   /* toast relation that owns this chunk */
    HeapTupleData   tup;        /* t_data points to a separate palloc'd buffer */
} TdeCapturedChunk;

/* one transaction's worth of captured chunks */
typedef struct TdeToastTxn
{
    TransactionId   xid;        /* hash key */
    dlist_head      chunks;
} TdeToastTxn;

static HTAB        *tde_toast_store = NULL;
static MemoryContext tde_toast_cxt = NULL;

static void
tde_toast_store_init(void)
{
    HASHCTL hash_ctl;

    if (tde_toast_store != NULL)
        return;

    tde_toast_cxt = AllocSetContextCreate(TopMemoryContext,
                                          "pg_vault_tde toast capture",
                                          ALLOCSET_DEFAULT_SIZES);

    MemSet(&hash_ctl, 0, sizeof(hash_ctl));
    hash_ctl.keysize = sizeof(TransactionId);
    hash_ctl.entrysize = sizeof(TdeToastTxn);
    hash_ctl.hcxt = tde_toast_cxt;
    tde_toast_store = hash_create("pg_vault_tde toast store", 8, &hash_ctl,
                                  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
}

/*
 * Capture one encrypted chunk tuple for xid.  tupledata/datalen are the block-0
 * data of the WAL record (xl_heap_header followed by the tuple body), exactly
 * as DecodeXLogTuple() expects.
 */
static void
tde_toast_capture(TransactionId xid, RelFileLocator *rlocator,
                  char *tupledata, Size datalen)
{
    TdeToastTxn      *txnent;
    TdeCapturedChunk *c;
    bool              found;
    xl_heap_header    xlhdr;
    int               bodylen = (int) datalen - SizeOfHeapHeader;

    if (bodylen < 0)
        return;

    tde_toast_store_init();

    txnent = (TdeToastTxn *) hash_search(tde_toast_store, &xid,
                                         HASH_ENTER, &found);
    if (!found)
        dlist_init(&txnent->chunks);

    c = (TdeCapturedChunk *) MemoryContextAllocZero(tde_toast_cxt,
                                                    sizeof(TdeCapturedChunk));
    c->rlocator = *rlocator;
    c->tup.t_len = SizeofHeapTupleHeader + bodylen;
    c->tup.t_tableOid = InvalidOid;
    ItemPointerSetInvalid(&c->tup.t_self);
    c->tup.t_data = (HeapTupleHeader)
        MemoryContextAllocZero(tde_toast_cxt, c->tup.t_len);

    /* reconstruct the tuple header + body (cf. DecodeXLogTuple) */
    memcpy(&xlhdr, tupledata, SizeOfHeapHeader);
    memcpy((char *) c->tup.t_data + SizeofHeapTupleHeader,
           tupledata + SizeOfHeapHeader, bodylen);
    c->tup.t_data->t_infomask = xlhdr.t_infomask;
    c->tup.t_data->t_infomask2 = xlhdr.t_infomask2;
    c->tup.t_data->t_hoff = xlhdr.t_hoff;

    dlist_push_tail(&txnent->chunks, &c->node);
}

void
tde_toast_store_reset(TransactionId xid)
{
    TdeToastTxn *txnent;

    if (tde_toast_store == NULL)
        return;

    txnent = (TdeToastTxn *) hash_search(tde_toast_store, &xid,
                                         HASH_FIND, NULL);
    if (txnent == NULL)
        return;

    {
        dlist_mutable_iter it;

        dlist_foreach_modify(it, &txnent->chunks)
        {
            TdeCapturedChunk *c = dlist_container(TdeCapturedChunk, node, it.cur);

            dlist_delete(&c->node);
            pfree(c->tup.t_data);
            pfree(c);
        }
    }

    hash_search(tde_toast_store, &xid, HASH_REMOVE, NULL);
}

/* ------------------------------------------------------------------------
 * Stitch — reconstruct plaintext TOAST values into the decrypted main tuple
 *
 * Faithful analogue of ReorderBufferToastReplace() (reorderbuffer.c), but:
 *   - chunks come from our per-txn capture store (decrypted here), not from
 *     core's toast_hash;
 *   - the main tuple has already been decrypted by the output plugin;
 *   - we build the result as a fresh HeapTuple (the decrypted tuple was sized
 *     for inline toast pointers and may be too small for indirect pointers),
 *     then copy it back into the existing newtuple buffer.
 * ------------------------------------------------------------------------ */

/*
 * Reconstructed TOAST values live in this context, NOT in the per-change
 * CurrentMemoryContext: the main tuple points at them through in-memory
 * INDIRECT pointers, and the output plugin reads them when it serializes the
 * change.  They must therefore outlive tde_toast_stitch() but be freed once the
 * change has been emitted — exactly core's ReorderBufferToastReset() lifecycle.
 * The output plugin calls tde_toast_stitch_reset() right after delegating the
 * change to pgoutput, which MemoryContextReset()s this context.  Created lazily
 * and kept (reset, not deleted) across changes.
 */
static MemoryContext tde_stitch_change_cxt = NULL;

/* one toast value-id being reassembled into a single pre-sized buffer */
typedef struct TdeValAccum
{
    Oid             value_id;       /* hash key (toast chunk_id == va_valueid) */
    struct varlena *reconstructed;  /* output buffer, sized up-front (change cxt) */
    int32           data_done;      /* bytes written into reconstructed so far */
    int32           extsize;        /* expected external size (from toast ptr) */
    bool            compressed;     /* on-disk datum was stored compressed */
    int32           last_seq;       /* last chunk_seq seen (ordering check) */
} TdeValAccum;

/*
 * Free the reconstructed TOAST buffers built for the change just emitted.
 * Called by the output plugin after pgoutput has serialized the change — the
 * analogue of core's per-change ReorderBufferToastReset().  No-op if nothing
 * was stitched.
 */
void
tde_toast_stitch_reset(void)
{
    if (tde_stitch_change_cxt != NULL)
        MemoryContextReset(tde_stitch_change_cxt);
}

void
tde_toast_stitch(Relation relation, ReorderBufferChange *change,
                 TransactionId xid)
{
    TdeToastTxn  *txnent;
    HeapTuple     newtup;
    TupleDesc     desc;
    Oid           toast_relid;
    Relation      toast_rel;
    TupleDesc     toast_desc;
    RelFileNumber toast_relfile;
    int           natt;
    bool          any_external = false;
    MemoryContext oldcxt;
    MemoryContext scratch;

    if (tde_toast_store == NULL)
        return;

    /* only INSERT / UPDATE carry a new tuple that can reference toast */
    if (change->action != REORDER_BUFFER_CHANGE_INSERT &&
        change->action != REORDER_BUFFER_CHANGE_UPDATE)
        return;

    newtup = change->data.tp.newtuple;
    if (newtup == NULL)
        return;

    txnent = (TdeToastTxn *) hash_search(tde_toast_store, &xid,
                                         HASH_FIND, NULL);
    if (txnent == NULL)
        return;                 /* no chunks captured for this txn */

    toast_relid = relation->rd_rel->reltoastrelid;
    if (!OidIsValid(toast_relid))
        return;

    desc = RelationGetDescr(relation);

    /* quick scan: does the decrypted tuple actually have an external datum? */
    {
        Datum  *a = palloc0(sizeof(Datum) * desc->natts);
        bool   *n = palloc0(sizeof(bool) * desc->natts);

        heap_deform_tuple(newtup, desc, a, n);
        for (natt = 0; natt < desc->natts; natt++)
        {
            Form_pg_attribute att = TupleDescAttr(desc, natt);

            if (att->attnum < 0 || att->attisdropped || att->attlen != -1)
                continue;
            if (n[natt])
                continue;
            if (VARATT_IS_EXTERNAL((struct varlena *) DatumGetPointer(a[natt])))
            {
                any_external = true;
                break;
            }
        }
        pfree(a);
        pfree(n);
    }
    if (!any_external)
        return;

    toast_rel = RelationIdGetRelation(toast_relid);
    if (!RelationIsValid(toast_rel))
        return;
    toast_desc = RelationGetDescr(toast_rel);
    toast_relfile = toast_rel->rd_locator.relNumber;

    /*
     * Reconstructed values go in tde_stitch_change_cxt (reset per change by the
     * output plugin); everything transient goes in a scratch context we delete
     * on the way out, INCLUDING the error path — so an out-of-sequence chunk
     * neither leaks the scratch nor the toast relcache reference held below.
     */
    if (tde_stitch_change_cxt == NULL)
        tde_stitch_change_cxt =
            AllocSetContextCreate(TopMemoryContext,
                                  "pg_vault_tde stitch values",
                                  ALLOCSET_DEFAULT_SIZES);

    scratch = AllocSetContextCreate(CurrentMemoryContext,
                                    "pg_vault_tde stitch scratch",
                                    ALLOCSET_DEFAULT_SIZES);
    oldcxt = MemoryContextSwitchTo(scratch);

    PG_TRY();
    {
        HASHCTL       hash_ctl;
        HTAB         *valmap;
        Datum        *attrs;
        bool         *isnull;
        HeapTuple     tmphtup;
        dlist_iter    it;

        MemSet(&hash_ctl, 0, sizeof(hash_ctl));
        hash_ctl.keysize = sizeof(Oid);
        hash_ctl.entrysize = sizeof(TdeValAccum);
        hash_ctl.hcxt = scratch;
        valmap = hash_create("pg_vault_tde stitch valmap", 8, &hash_ctl,
                             HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

        /* Pre-size per value (cf. ReorderBufferToastReplace): an accumulator
         * buffer here previously leaked. */
        attrs  = palloc0(sizeof(Datum) * desc->natts);
        isnull = palloc0(sizeof(bool) * desc->natts);
        heap_deform_tuple(newtup, desc, attrs, isnull);

        for (natt = 0; natt < desc->natts; natt++)
        {
            Form_pg_attribute att = TupleDescAttr(desc, natt);
            struct varlena *vl;
            struct varatt_external toast_pointer;
            TdeValAccum *acc;
            bool         found;

            if (att->attnum < 0 || att->attisdropped || att->attlen != -1)
                continue;
            if (isnull[natt])
                continue;
            vl = (struct varlena *) DatumGetPointer(attrs[natt]);
            if (!VARATT_IS_EXTERNAL_ONDISK(vl))
                continue;

            VARATT_EXTERNAL_GET_POINTER(toast_pointer, vl);
            acc = (TdeValAccum *) hash_search(valmap, &toast_pointer.va_valueid,
                                              HASH_ENTER, &found);
            if (!found)
            {
                acc->reconstructed = (struct varlena *)
                    MemoryContextAllocZero(tde_stitch_change_cxt,
                                           toast_pointer.va_rawsize);
                acc->data_done = 0;
                acc->extsize = (int32) VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer);
                /*
                 * Equivalent to VARATT_EXTERNAL_IS_COMPRESSED(), written out to
                 * avoid a uint32/int sign-compare warning under -Wextra
                 * (va_rawsize is int32, the extsize accessor is uint32).
                 */
                acc->compressed =
                    (VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer) <
                     (uint32) (toast_pointer.va_rawsize - VARHDRSZ));
                acc->last_seq = -1;
            }
        }

        dlist_foreach(it, &txnent->chunks)
        {
            TdeCapturedChunk *c = dlist_container(TdeCapturedChunk, node, it.cur);
            HeapTuple   dec;
            Oid         chunk_id;
            int32       chunk_seq;
            Pointer     chunk;
            bool        cisnull;
            int32       chunksize;
            TdeValAccum *acc;

            if (c->rlocator.relNumber != toast_relfile)
                continue;       /* belongs to a different toast relation */

            dec = tde_decrypt_heap_tuple(&c->tup, toast_relid, toast_desc);

            chunk_id  = DatumGetObjectId(fastgetattr(dec, 1, toast_desc, &cisnull));
            chunk_seq = DatumGetInt32(fastgetattr(dec, 2, toast_desc, &cisnull));
            chunk     = DatumGetPointer(fastgetattr(dec, 3, toast_desc, &cisnull));

            acc = (TdeValAccum *) hash_search(valmap, &chunk_id, HASH_FIND, NULL);
            if (acc == NULL)
            {
                pfree(dec);     /* chunk for a value this tuple doesn't reference */
                continue;
            }

            if (!VARATT_IS_EXTENDED(chunk))
                chunksize = VARSIZE(chunk) - VARHDRSZ;
            else if (VARATT_IS_SHORT(chunk))
                chunksize = VARSIZE_SHORT(chunk) - VARHDRSZ_SHORT;
            else
                elog(ERROR, "pg_vault_tde: unexpected type of toast chunk");

            if (chunk_seq != acc->last_seq + 1)
                elog(ERROR,
                     "pg_vault_tde: got sequence entry %d for toast chunk %u instead of %d",
                     chunk_seq, chunk_id, acc->last_seq + 1);
            acc->last_seq = chunk_seq;

            memcpy(VARDATA(acc->reconstructed) + acc->data_done,
                   VARDATA_ANY(chunk), chunksize);
            acc->data_done += chunksize;
            pfree(dec);
        }

        for (natt = 0; natt < desc->natts; natt++)
        {
            Form_pg_attribute att = TupleDescAttr(desc, natt);
            struct varlena *vl;
            struct varatt_external toast_pointer;
            struct varatt_indirect redirect_pointer;
            struct varlena *new_datum;
            TdeValAccum *acc;

            if (att->attnum < 0 || att->attisdropped || att->attlen != -1)
                continue;
            if (isnull[natt])
                continue;
            vl = (struct varlena *) DatumGetPointer(attrs[natt]);
            if (!VARATT_IS_EXTERNAL_ONDISK(vl))
                continue;

            VARATT_EXTERNAL_GET_POINTER(toast_pointer, vl);
            acc = (TdeValAccum *) hash_search(valmap, &toast_pointer.va_valueid,
                                              HASH_FIND, NULL);
            if (acc == NULL)
                continue;       /* unchanged toast — leave on-disk ('u') */

            Assert(acc->data_done == acc->extsize);

            if (acc->compressed)
                SET_VARSIZE_COMPRESSED(acc->reconstructed, acc->data_done + VARHDRSZ);
            else
                SET_VARSIZE(acc->reconstructed, acc->data_done + VARHDRSZ);

            new_datum = (struct varlena *) palloc0(INDIRECT_POINTER_SIZE);
            memset(&redirect_pointer, 0, sizeof(redirect_pointer));
            redirect_pointer.pointer = acc->reconstructed;
            SET_VARTAG_EXTERNAL(new_datum, VARTAG_INDIRECT);
            memcpy(VARDATA_EXTERNAL(new_datum), &redirect_pointer,
                   sizeof(redirect_pointer));

            attrs[natt] = PointerGetDatum(new_datum);
        }

        /*
         * Build the reformed tuple in the OUTER context and copy it back into
         * the reorder buffer's own newtuple buffer, keeping the same pointer —
         * do NOT swap in tmphtup.  `newtup` is the reorder buffer's tuple buffer
         * (decrypted in place by the output plugin) and is freed later, OUTSIDE
         * this callback's context; a tmphtup swapped in would be freed from
         * under that later pfree (intermittent "pfree invalid pointer" /
         * segfault under streaming).  The INDIRECT pointers are smaller than the
         * on-disk external pointers they replace, so the reformed tuple fits.
         * Mirrors core's ReorderBufferToastReplace().
         *
         * DO NOT remove the copy-back in favour of a pointer swap: it is the fix
         * for an intermittent walsender crash under streaming (multiple TOAST
         * txns in a burst).  See doc/logical_decoding_research.md.
         */
        MemoryContextSwitchTo(oldcxt);
        tmphtup = heap_form_tuple(desc, attrs, isnull);
        Assert(tmphtup->t_len <= newtup->t_len);
        memcpy(newtup->t_data, tmphtup->t_data, tmphtup->t_len);
        newtup->t_len = tmphtup->t_len;
        pfree(tmphtup);
    }
    PG_CATCH();
    {
        MemoryContextSwitchTo(oldcxt);
        MemoryContextDelete(scratch);
        MemoryContextReset(tde_stitch_change_cxt);
        RelationClose(toast_rel);
        PG_RE_THROW();
    }
    PG_END_TRY();

    /* reconstructed buffers must outlive this call (the row is serialized after
     * we return) — freed per-change by tde_toast_stitch_reset(), not here. */
    MemoryContextDelete(scratch);
    RelationClose(toast_rel);
}

/* ------------------------------------------------------------------------
 * Resource manager callbacks
 * ------------------------------------------------------------------------ */

static void
tde_rmgr_redo(XLogReaderState *record)
{
    heap_redo(record);
}

static void
tde_rmgr_desc(StringInfo buf, XLogReaderState *record)
{
    /* Payload is the standard heap-insert format; reuse heap's descriptor. */
    heap_desc(buf, record);
}

static const char *
tde_rmgr_identify(uint8 info)
{
    switch (info & XLOG_HEAP_OPMASK)
    {
        case XLOG_HEAP_INSERT:
            return (info & XLOG_HEAP_INIT_PAGE) ? "TOAST_INSERT+INIT"
                                                : "TOAST_INSERT";
        default:
            return NULL;
    }
}

/*
 * rm_decode — capture encrypted toast chunks for later stitching.
 *
 * Mirrors heap_decode()/DecodeInsert()'s gating so we only capture once a
 * consistent snapshot exists and the change is relevant; the chunk tuple is
 * stashed raw (encrypted) into our per-txn store — no catalog access here.
 */
static void
tde_rmgr_decode(LogicalDecodingContext *ctx, XLogRecordBuffer *buf)
{
    XLogReaderState *r = buf->record;
    uint8       info = XLogRecGetInfo(r) & XLOG_HEAP_OPMASK;
    TransactionId xid = XLogRecGetXid(r);
    SnapBuild  *builder = ctx->snapshot_builder;
    xl_heap_insert *xlrec;
    RelFileLocator target_locator;
    char       *tupledata;
    Size        datalen;

    ReorderBufferProcessXid(ctx->reorder, xid, buf->origptr);

    if (info != XLOG_HEAP_INSERT)
        return;                 /* our rmgr only ever logs toast inserts */

    if (SnapBuildCurrentState(builder) < SNAPBUILD_FULL_SNAPSHOT)
        return;

    xlrec = (xl_heap_insert *) XLogRecGetData(r);

    if (!(xlrec->flags & XLH_INSERT_CONTAINS_NEW_TUPLE))
        return;

    /* only our database */
    XLogRecGetBlockTag(r, 0, &target_locator, NULL, NULL);
    if (target_locator.dbOid != ctx->slot->data.database)
        return;

    /*
     * NB: origin filtering (core's static FilterByOrigin) is intentionally
     * not replicated here — it is not exported.  Capturing chunks for an
     * origin-filtered txn is harmless: the main change is filtered out and the
     * captured chunks are freed by tde_toast_store_reset at commit.
     */
    if (!SnapBuildProcessChange(builder, xid, buf->origptr) || ctx->fast_forward)
        return;

    tupledata = XLogRecGetBlockData(r, 0, &datalen);
    tde_toast_capture(xid, &target_locator, tupledata, datalen);
}

static const RmgrData tde_rmgr = {
    .rm_name     = "pg_vault_tde",
    .rm_redo     = tde_rmgr_redo,
    .rm_desc     = tde_rmgr_desc,
    .rm_identify = tde_rmgr_identify,
    .rm_startup  = NULL,
    .rm_cleanup  = NULL,
    .rm_mask     = NULL,
    .rm_decode   = tde_rmgr_decode,
};

void
tde_rmgr_register(void)
{
    RegisterCustomRmgr(TDE_RMGR_ID, &tde_rmgr);
}

/* ------------------------------------------------------------------------
 * Write path — faithful heap_insert() replica, logged under TDE_RMGR_ID
 *
 * This function is a deliberate, near-byte-identical clone of the core
 * heap_insert() (src/backend/access/heap/heapam.c).  Keep it faithful to the
 * upstream function: the ONLY intended deviations are the final XLogInsert()
 * resource manager id (TDE_RMGR_ID) and the inlined header-stamping (the toast/
 * compress branch of heap_prepare_insert is unreachable for a chunk tuple).
 * When porting to a new major PostgreSQL release, diff this against that
 * release's heap_insert() and re-sync (see copilot § 0.5 version audit).
 *
 * Tracked against PG 18.4 (the validated baseline).  Known upstream changes a
 * future audit must fold in:
 *   - PG 18 / earlier (matched here): the clone omits the "XXX Should we set
 *     PageSetPrunable" hint (18.x only carries the comment, no call) and does
 *     NOT call AssertHasSnapshotForToast() (not present before PG 19).
 *   - PG 19+: heap_insert() gained AssertHasSnapshotForToast(relation) after
 *     header stamping and a PageSetPrunable(page, xid) call (guarded by
 *     TransactionIdIsNormal(xid) && !HEAP_INSERT_FROZEN) between the
 *     visibility-map clear and MarkBufferDirty.  Add both, under
 *     #if PG_VERSION_NUM >= 190000, when porting to PG 19.
 *
 * PG17 vs PG18: only the XLogRegisterData/XLogRegisterBufData parameter
 * const-ness differs (PG17 char *, PG18 const void *); the explicit (char *)
 * casts below compile cleanly on both.
 * ------------------------------------------------------------------------ */

void
tde_toast_wal_insert(Relation relation, HeapTuple tup, CommandId cid,
                     int options, BulkInsertState bistate)
{
    TransactionId xid = GetCurrentTransactionId();
    Buffer      buffer;
    Buffer      vmbuffer = InvalidBuffer;
    bool        all_visible_cleared = false;

    /* Caller hands us a toast chunk tuple — never externally toasted. */
    Assert(HeapTupleHeaderGetNatts(tup->t_data) <=
           RelationGetNumberOfAttributes(relation));

    /*
     * Inline of the static heap_prepare_insert(): header stamping only.  The
     * tuple IS a toast chunk, so the toast/compress branch of the original is
     * unreachable and omitted; we keep the header logic byte-for-byte.
     */
    tup->t_data->t_infomask &= ~(HEAP_XACT_MASK);
    tup->t_data->t_infomask2 &= ~(HEAP2_XACT_MASK);
    tup->t_data->t_infomask |= HEAP_XMAX_INVALID;
    HeapTupleHeaderSetXmin(tup->t_data, xid);
    if (options & HEAP_INSERT_FROZEN)
        HeapTupleHeaderSetXminFrozen(tup->t_data);
    HeapTupleHeaderSetCmin(tup->t_data, cid);
    HeapTupleHeaderSetXmax(tup->t_data, 0);     /* for cleanliness */
    tup->t_tableOid = RelationGetRelid(relation);

    Assert(!HeapTupleHasExternal(tup));

    /*
     * Find buffer to insert this tuple into.  Same call heap_insert makes.
     */
    buffer = RelationGetBufferForTuple(relation, tup->t_len,
                                       InvalidBuffer, options, bistate,
                                       &vmbuffer, NULL, 0);

    CheckForSerializableConflictIn(relation, NULL, InvalidBlockNumber);

    /* NO EREPORT(ERROR) FROM HERE TILL CHANGES ARE LOGGED */
    START_CRIT_SECTION();

    RelationPutHeapTuple(relation, buffer, tup,
                         (options & HEAP_INSERT_SPECULATIVE) != 0);

    if (PageIsAllVisible(BufferGetPage(buffer)))
    {
        all_visible_cleared = true;
        PageClearAllVisible(BufferGetPage(buffer));
        visibilitymap_clear(relation,
                            ItemPointerGetBlockNumber(&(tup->t_self)),
                            vmbuffer, VISIBILITYMAP_VALID_BITS);
    }

    MarkBufferDirty(buffer);

    /* XLOG stuff */
    if (RelationNeedsWAL(relation))
    {
        xl_heap_insert xlrec;
        xl_heap_header xlhdr;
        XLogRecPtr  recptr;
        Page        page = BufferGetPage(buffer);
        uint8       info = XLOG_HEAP_INSERT;
        int         bufflags = 0;

        /*
         * heap_insert would call log_heap_new_cid() here for catalog tables.
         * TOAST relations of user tables are never accessible in logical
         * decoding, so this path is unreachable in our use; guard defensively.
         */
        if (RelationIsAccessibleInLogicalDecoding(relation))
            ereport(ERROR,
                    (errmsg("pg_vault_tde: custom TOAST rmgr does not support "
                            "relations accessible in logical decoding")));

        /*
         * If this is the single and first tuple on page, re-initialize the
         * page from scratch during replay.
         */
        if (ItemPointerGetOffsetNumber(&(tup->t_self)) == FirstOffsetNumber &&
            PageGetMaxOffsetNumber(page) == FirstOffsetNumber)
        {
            info |= XLOG_HEAP_INIT_PAGE;
            bufflags |= REGBUF_WILL_INIT;
        }

        xlrec.offnum = ItemPointerGetOffsetNumber(&tup->t_self);
        xlrec.flags = 0;
        if (all_visible_cleared)
            xlrec.flags |= XLH_INSERT_ALL_VISIBLE_CLEARED;
        if (options & HEAP_INSERT_SPECULATIVE)
            xlrec.flags |= XLH_INSERT_IS_SPECULATIVE;
        Assert(ItemPointerGetBlockNumber(&tup->t_self) == BufferGetBlockNumber(buffer));

        /*
         * For logical decoding, we need the tuple even if we're doing a full
         * page write, so make sure it's included with the WAL record.  We do
         * keep XLH_INSERT_ON_TOAST_RELATION (this IS a toast relation) for WAL
         * byte-identity with heap_insert; the custom rmid — not this flag — is
         * what keeps the chunk out of the reorder buffer's toast_hash.
         */
        if (RelationIsLogicallyLogged(relation) &&
            !(options & HEAP_INSERT_NO_LOGICAL))
        {
            xlrec.flags |= XLH_INSERT_CONTAINS_NEW_TUPLE;
            bufflags |= REGBUF_KEEP_DATA;

            if (IsToastRelation(relation))
                xlrec.flags |= XLH_INSERT_ON_TOAST_RELATION;
        }

        XLogBeginInsert();
        /* (char *) cast: PG18 takes const void*, PG17 takes char* — portable on both */
        XLogRegisterData((char *) &xlrec, SizeOfHeapInsert);

        xlhdr.t_infomask2 = tup->t_data->t_infomask2;
        xlhdr.t_infomask = tup->t_data->t_infomask;
        xlhdr.t_hoff = tup->t_data->t_hoff;

        /*
         * note we mark xlhdr as belonging to buffer; if XLogInsert decides to
         * write the whole page to the xlog, we don't need to store
         * xl_heap_header in the xlog.
         */
        XLogRegisterBuffer(0, buffer, REGBUF_STANDARD | bufflags);
        XLogRegisterBufData(0, (char *) &xlhdr, SizeOfHeapHeader);
        /* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
        XLogRegisterBufData(0,
                            (char *) tup->t_data + SizeofHeapTupleHeader,
                            tup->t_len - SizeofHeapTupleHeader);

        /* filtering by origin on each row is too fine-grained */
        XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

        /* ONLY deviation from heap_insert: route to our custom resource mgr. */
        recptr = XLogInsert(TDE_RMGR_ID, info);

        PageSetLSN(page, recptr);
    }

    END_CRIT_SECTION();

    UnlockReleaseBuffer(buffer);
    if (vmbuffer != InvalidBuffer)
        ReleaseBuffer(vmbuffer);

    /*
     * If tuple is cachable, mark it for invalidation from the caches in case
     * we abort.  Note it is OK to do this after releasing the buffer, because
     * the tup is private to this backend (no other backend can see it).
     */
    CacheInvalidateHeapTuple(relation, tup, NULL);

    /* Note: speculative insertions are counted too, even if aborted later */
    pgstat_count_heap_insert(relation, 1);
}
