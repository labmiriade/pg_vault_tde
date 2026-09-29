/*
 * pg_vault_tde_tam.c - Table Access Method (TAM) handler for pg_vault_tde
 *
 * Architecture: mutable copy of heapam's TableAmRoutine, initialised by
 * pg_vault_tde_tam_init() called from _PG_init.  Four write + seven read
 * callbacks are overridden; every structural callback (VACUUM, ANALYZE, HOT,
 * CLUSTER, index build, truncate ...) delegates unchanged to heapam.
 *
 * Wire format on disk (per tuple), v5 structure-preserving:
 *   [HeapTupleHeader (t_hoff bytes, PLAINTEXT - MVCC fields)]
 *   [attributes at their normal offsets, value bytes encrypted (N bytes)]
 *   [IV(12) | GCM TAG(16) | VERSION(1) | GENERATION(8)]
 *
 * Overhead vs. plain heap: TDE_V4_OVERHEAD (37) bytes/tuple, unchanged from
 * v4.  v4 tuples (whole user-data region as one opaque blob) are still read;
 * see the comment above tde_encrypt_heap_tuple() for why the layout moved.
 *
 * Copyright (c) 2026 Miriade S.r.l.  
 * Licensed under the PostgreSQL License.
 */
#include "postgres.h"
#include "access/heapam.h"          /* heap_insert, heap_update, heap_multi_insert,
                                       heap_getnextslot */
#include "access/heaptoast.h"       /* TOAST_TUPLE_THRESHOLD, TOAST_MAX_CHUNK_SIZE */
#include "access/toast_internals.h" /* TOAST_TUPLE_THRESHOLD */
#include "access/detoast.h"         /* detoast_external_attr */
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
#include "access/xact.h"           /* RegisterXactCallback (impersonation check) */
#include "utils/memutils.h"
#include "utils/tuplesort.h"        /* tuplesort_getdatum (index_validate_scan)*/
#include "utils/snapmgr.h"          /* GetLatestSnapshot, RegisterSnapshot,
                                       UnregisterSnapshot */
#include "miscadmin.h"              /* CHECK_FOR_INTERRUPTS */
#include "storage/lmgr.h"            /* XactLockTableWait */
#include "storage/procarray.h"       /* GetOldestNonRemovableTransactionId */
#include "varatt.h"                 /* VARSIZE_ANY_EXHDR, VARATT_IS_EXTERNAL,
                                       SET_VARSIZE_COMPRESSED, VARHDRSZ_COMPRESSED */

#include "access/rewriteheap.h"
#include "commands/progress.h"       /* PROGRESS_CLUSTER_* */
#include "pgstat.h"                   /* pgstat_progress_update_param */
#include "commands/vacuum.h"

#include "access/toast_compression.h" /* TOAST_PGLZ_COMPRESSION_ID */
#include "src/include/pg_vault_tde_crypto.h"  /* tde_gcm_encrypt, tde_gcm_decrypt,
                                                  TDE_V4_OVERHEAD */
#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_guc.h"      /* pg_vault_tde_enabled */
#include "src/include/pg_vault_tde_iam.h"      /* tde_iam_is_tde_btree_index,
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
 *  - scan_getnextslot              : sequential scan
 *  - scan_getnextslot_tidrange     : Tid range scan
 *  - index_fetch_tuple             : index scan (CRITICAL — was missing)
 *  - scan_bitmap_next_tuple        : bitmap heap scan (BitmapHeapScan nodes)
 *  - scan_analyze_next_tuple       : ANALYZE statistics collection
 *  - scan_sample_next_tuple        : TABLESAMPLE clauses
 *  - tuple_fetch_row_version       : direct TID fetch (TidScan, lock recheck)
 *  - tuple_lock                    : SELECT FOR UPDATE / FOR SHARE
 *
 * Write paths call heap_insert / heap_update / heap_multi_insert directly.
 */
static bool       (*heapam_scan_getnextslot_cb)(TableScanDesc, ScanDirection,
                                                 TupleTableSlot *);
static bool       (*heapam_scan_getnextslot_tidrange_cb)(TableScanDesc, ScanDirection,
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
static void       (*heapam_tuple_complete_speculative_cb)(Relation,
                                                          TupleTableSlot *,
                                                          uint32, bool);
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
static bool tde_tuple_has_external_desc(HeapTuple tup, TupleDesc tupdesc);

static HeapTuple tde_prepare_encrypt_tuple(Relation rel, HeapTuple plain, HeapTuple old, HeapTuple volatile *toasted_out, int options);

static inline void tde_release_plain(HeapTuple plain)
{
    Size hdr = plain->t_data->t_hoff;
    OPENSSL_cleanse((char *) plain->t_data + hdr, plain->t_len - hdr);
    pfree(plain);
}

static HeapTuple tde_prepare_encrypt_tuple(Relation rel, HeapTuple plain, HeapTuple old, HeapTuple volatile *toasted_out, int options)
{
    HeapTuple toasted = pg_vault_tde_toast_insert_or_update(rel, plain, old, options);
    HeapTuple enc;

    /*
     * Publish `toasted` to the caller BEFORE encrypting.  tde_encrypt_heap_tuple
     * can ereport(ERROR), and the caller's PG_CATCH can only free what it can
     * already see through toasted_out.
     */
    *toasted_out = toasted;

    enc = tde_encrypt_heap_tuple(toasted, RelationGetRelid(rel),
                                 RelationGetDescr(rel));
    enc->t_data->t_infomask &= ~HEAP_HASEXTERNAL;
    enc->t_tableOid = plain->t_tableOid;
    

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
 * On-disk layout of the user-data region — v5, structure preserving.
 *
 * v4 replaced the whole user-data region with one opaque blob:
 *     [ IV(12) | CIPHERTEXT(N) | TAG(16) | VERSION(1) | GENERATION(8) ]
 * The header was copied verbatim, so the tuple still advertised natts
 * attributes laid out per the tuple descriptor while the data area was not
 * laid out that way at all.  Any core code that deforms an on-disk tuple then
 * walks ciphertext as if it were a tuple — and heap_update() does exactly
 * that, reading the indexed attributes straight off the page to decide HOT
 * and which indexes to maintain.  When the attribute's offset is not cached
 * (i.e. anything after the first variable-length column) nocachegetattr()
 * reads a varlena length header out of ciphertext, gets a length of up to
 * 1 GB, and the cursor leaves the page: SIGSEGV (PSQLE-165).  When it happens
 * to stay on the page it silently compares garbage instead, and can declare
 * an updated indexed column unchanged.  Any index on such a column is enough,
 * including tde_btree — the trigger is the index attribute bitmap, not the
 * access method.
 *
 * v5 keeps the tuple physically valid: every attribute stays at its own
 * offset with its own length, and only the VALUE bytes are replaced by
 * ciphertext.  Varlena length headers, the external-datum tag and alignment
 * padding stay in clear — that is what makes the tuple walkable, and it is
 * the price of the format: the exact byte length of every variable-length
 * column becomes visible on disk (the row length and the null bitmap already
 * were).  Fixed-length columns leak nothing, their length is in the catalog.
 *
 *   [ attribute layout, value bytes encrypted (D bytes) ]
 *   [ IV(12) | TAG(16) | VERSION(1 = 0x05) | GENERATION(8) ]
 *
 * D is the plaintext data length, so a v5 tuple is exactly as long as the v4
 * tuple for the same row (TDE_V4_OVERHEAD over the plaintext region): the
 * TOAST threshold arithmetic elsewhere in this file is unchanged.
 *
 * The AEAD is untouched.  The value bytes are gathered into one buffer, handed
 * to tde_gcm_encrypt() and scattered back, so ciphertext, tag and AAD are
 * bit-identical to what v4 produced for the same input; only the framing moved.
 *
 * v4 tuples stay readable — the version byte sits at the same offset from the
 * end in both formats — but they keep their original layout.  An existing
 * table is only immune once its rows have been rewritten (VACUUM FULL).
 */
typedef struct tde_vrange
{
    uint32      off;            /* offset into the user-data region */
    uint32      len;
} tde_vrange;

/*
 * tde_value_ranges
 *
 * Collect the byte ranges of the user-data region that hold attribute VALUES,
 * mirroring heap_deform_tuple()'s walk exactly — same alignment rules, same
 * natts bound, same null bitmap.  Structural bytes (varlena length headers,
 * the external-datum tag, alignment padding) are deliberately left out: they
 * stay in clear so that walk keeps working on the encrypted tuple.
 *
 * `ranges` must have room for tupdesc->natts entries.  Returns the total
 * number of value bytes; *end_off receives the offset one past the last
 * attribute, which the caller checks against the region length.
 *
 * ON-DISK CONTRACT — READ BEFORE TOUCHING THIS FUNCTION.
 *
 * The ranges are not stored anywhere: they define the order in which the value
 * bytes are concatenated into the single AEAD message, and the reader has to
 * reproduce that order exactly or the tag check fails on every v5 tuple already
 * written.  Which bytes are covered is as much a part of the wire format as the
 * trailer is, even though nothing about the layout moves.
 *
 * That makes the obvious optimisation a breaking change.  Coalescing adjacent
 * ranges would be correct in isolation — alignment padding that precedes a
 * FIXED-length attribute is computed arithmetically by att_align_nominal() and
 * never read, so it could be folded into a neighbouring range, and a row of
 * only fixed-width columns would collapse to one range, removing the gather and
 * scatter entirely.  (Padding before a varlena could not: att_align_pointer()
 * reads that byte and treats a non-zero value as "no padding here".)  But doing
 * it after v5 ships means old tuples gather in one order and new code in
 * another.  Same failure mode as the 1.7.1 AAD change — see tde_compute_aad()
 * in src/crypto/pg_vault_tde_crypto.c.
 *
 * Unlike that one, though, the fix is cheap: the physical layout does not move,
 * only which bytes enter the AEAD, so a v6 that coalesces would read v5 tuples
 * by dispatching on the trailer's version byte and asking for the v5 ranges.
 * No rewrite, no VACUUM FULL, nothing for an operator to do.  Which is why this
 * is written down rather than rushed in: do it when something else is already
 * bumping the layout, and give it its own version byte when you do.
 */
static Size
tde_value_ranges(HeapTupleHeader td, TupleDesc tupdesc, Size data_len,
                 tde_vrange *ranges, int *nranges, Size *end_off)
{
    int         natts    = HeapTupleHeaderGetNatts(td);
    bool        hasnulls = ((td->t_infomask & HEAP_HASNULL) != 0);
    bits8      *bp       = td->t_bits;
    char       *tp       = (char *) td + td->t_hoff;
    long        off      = 0;
    Size        total    = 0;
    int         n        = 0;
    int         i;

    if (natts > tupdesc->natts)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("pg_vault_tde: tuple has %d attributes, descriptor has %d",
                        natts, tupdesc->natts)));

    for (i = 0; i < natts; i++)
    {
        Form_pg_attribute att = TupleDescAttr(tupdesc, i);
        Size        hdrsz;
        Size        fullsz;

        if (hasnulls && att_isnull(i, bp))
            continue;

        if (att->attlen == -1)
        {
            /*
             * att_align_pointer() peeks at the byte under the cursor to decide
             * whether a short varlena skips the alignment padding.  That byte
             * is a length header, which v5 keeps in clear, so the decision is
             * the same on the encrypted and on the plaintext tuple.
             */
            if ((Size) off >= data_len)
                break;
            off = att_align_pointer(off, att->attalign, -1, tp + off);
            if ((Size) off >= data_len)
                break;

            if (VARATT_IS_1B_E(tp + off))
                hdrsz = VARHDRSZ_EXTERNAL;   /* 1 length byte + 1 tag byte */
            else if (VARATT_IS_1B(tp + off))
                hdrsz = VARHDRSZ_SHORT;
            else
                hdrsz = VARHDRSZ;
            fullsz = VARSIZE_ANY(tp + off);
        }
        else if (att->attlen > 0)
        {
            off = att_align_nominal(off, att->attalign);
            hdrsz = 0;
            fullsz = (Size) att->attlen;
        }
        else
        {
            /*
             * attlen == -2 (null-terminated cstring): encrypting the bytes
             * would destroy the terminator the walk needs.  No such type can
             * be a column of a heap relation, so this is unreachable — fail
             * closed rather than silently store one attribute in clear.
             */
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("pg_vault_tde: attribute %d has unsupported length %d",
                            i + 1, att->attlen)));
        }

        if (fullsz < hdrsz || (Size) off + fullsz > data_len)
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_CORRUPTED),
                     errmsg("pg_vault_tde: attribute %d runs past the tuple "
                            "(offset %ld, length %zu, region %zu bytes)",
                            i + 1, off, fullsz, data_len)));

        if (fullsz > hdrsz)
        {
            ranges[n].off = (uint32) (off + hdrsz);
            ranges[n].len = (uint32) (fullsz - hdrsz);
            total += ranges[n].len;
            n++;
        }
        off += fullsz;
    }

    *nranges = n;
    *end_off = (Size) off;
    return total;
}

/*
 * tde_encrypt_heap_tuple
 *
 * Returns a palloc'd HeapTuple in the v5 on-disk layout described above.
 *
 * Header bytes [0 .. t_hoff) are copied verbatim (plaintext) because MVCC
 * fields (xmin, xmax, ctid, infomask, null bitmap) must remain readable by
 * heapam without decryption.
 *
 * tupdesc is the row type of `plain`: it drives the attribute walk, so it must
 * be the descriptor of the relation the tuple is being written to.
 *
 * Caller must pfree the returned tuple; OPENSSL_cleanse is NOT required
 * on the returned tuple because it contains only ciphertext and structure.
 */
HeapTuple
tde_encrypt_heap_tuple(HeapTuple plain, Oid relid, TupleDesc tupdesc)
{
    Size        hdr_len   = plain->t_data->t_hoff;
    char       *user_data = (char *) plain->t_data + hdr_len;
    Size        user_len  = plain->t_len - hdr_len;
    tde_vrange *ranges;
    int         nranges   = 0;
    Size        end_off   = 0;
    Size        val_len;
    Size        blob_len  = 0;
    char       *val_buf;
    char       *blob;
    char       *dst;
    HeapTuple   enc;
    Size        pos;
    int         i;

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

    ranges = (tde_vrange *) palloc(sizeof(tde_vrange) * (tupdesc->natts + 1));
    val_len = tde_value_ranges(plain->t_data, tupdesc, user_len,
                               ranges, &nranges, &end_off);

    /*
     * heap_fill_tuple() sizes the data region by the very same walk, so the
     * walk must consume it whole.  If it does not, some plaintext byte is not
     * covered by any range and would be written to disk in clear: refuse.
     */
    if (end_off != user_len)
    {
        pfree(ranges);
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("pg_vault_tde: attribute walk covered %zu of %zu data bytes",
                        end_off, user_len)));
    }

    /* Gather the value bytes, encrypt them as one AEAD message. */
    val_buf = (char *) palloc(val_len > 0 ? val_len : 1);
    for (i = 0, pos = 0; i < nranges; i++)
    {
        memcpy(val_buf + pos, user_data + ranges[i].off, ranges[i].len);
        pos += ranges[i].len;
    }

    blob = tde_gcm_encrypt(relid, val_buf, val_len, &blob_len);
    OPENSSL_cleanse(val_buf, val_len);
    pfree(val_buf);
    Assert(blob_len == val_len + TDE_V4_OVERHEAD);

    enc = (HeapTuple) palloc0(HEAPTUPLESIZE + hdr_len + user_len + TDE_V4_OVERHEAD);
    enc->t_len      = (uint32) (hdr_len + user_len + TDE_V4_OVERHEAD);
    enc->t_self     = plain->t_self;
    enc->t_tableOid = plain->t_tableOid;
    enc->t_data     = (HeapTupleHeader) ((char *) enc + HEAPTUPLESIZE);

    /* Header and attribute layout verbatim; value bytes overwritten below. */
    memcpy(enc->t_data, plain->t_data, hdr_len + user_len);
    dst = (char *) enc->t_data + hdr_len;

    for (i = 0, pos = 0; i < nranges; i++)
    {
        memcpy(dst + ranges[i].off, blob + TDE_GCM_IV_LEN + pos, ranges[i].len);
        pos += ranges[i].len;
    }
    pfree(ranges);

    /* Trailer: IV | TAG | VERSION | GENERATION. */
    memcpy(dst + user_len, blob, TDE_GCM_IV_LEN);
    memcpy(dst + user_len + TDE_GCM_IV_LEN,
           blob + TDE_GCM_IV_LEN + val_len,
           TDE_GCM_TAG_LEN + 1 + TDE_V4_GEN_LEN);
    dst[user_len + TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN] = (char) TDE_TUPLE_V5_VERSION_BYTE;
    pfree(blob);  /* ciphertext - no need to cleanse */

    /*
     * Clear HEAP_HASEXTERNAL on the encrypted tuple.  From the core's point of
     * view the encrypted tuple has no external columns — the TOAST pointer's
     * payload is ciphertext, so nothing may dereference it.  Leaving the bit
     * set makes core touch it as if it were a live pointer; in particular
     * ExtractReplicaIdentity() (heap_delete/heap_update) runs
     * toast_flatten_tuple()/heap_deform_tuple() on it and logs a garbage
     * replica identity, breaking logical UPDATE/DELETE.  TOAST lifecycle is
     * driven by the TAM itself (per-attribute VARATT scan on the decrypted
     * tuple, tde_tuple_has_external_slow), not this bit — and VACUUM FULL
     * already writes encrypted tuples with this bit cleared, so the codebase
     * copes.
     */
    enc->t_data->t_infomask &= ~HEAP_HASEXTERNAL;

    return enc;
}
/*
 * tde_decrypt_heap_tuple
 *
 * Takes an on-disk HeapTuple (header plain, user-data encrypted) and returns
 * a palloc'd HeapTuple with the user-data portion decrypted.  Both layouts are
 * accepted: the version byte sits at the same offset from the end in v4 and
 * v5, so a table written before the v5 upgrade keeps reading.
 * GCM tag verification is performed inside tde_gcm_decrypt; bad tags cause
 * ereport(ERROR) — tampered tuples never return data to the caller.
 *
 * Caller must OPENSSL_cleanse + pfree the returned tuple after use,
 * OR pass it to ExecForceStoreHeapTuple with shouldFree=true.
 *
 * Exported (non-static) so the logical decoding output plugin can decrypt
 * WAL-sourced tuples from encrypted_heap relations.
 *
 * tupdesc is the row type of `enc`.  v5 needs it to walk the attributes; both
 * versions need it to recompute HEAP_HASEXTERNAL on the returned tuple.
 * tde_encrypt_heap_tuple() deliberately CLEARS that bit on the on-disk
 * (encrypted) representation so core never tries to dereference a TOAST
 * pointer inside ciphertext; the memcpy() below copies that (now-stale)
 * header verbatim, so the bit is WRONG on the decrypted tuple whenever the
 * attribute genuinely is an out-of-line TOAST pointer. Most callers in this
 * file already work around that locally via tde_tuple_has_external() before
 * deciding whether to re-toast — but ANY consumer of a decrypted tuple that
 * instead trusts the header bit (e.g. ExecFetchSlotHeapTuple's fast path,
 * taken when the slot's own get_heap_tuple callback just hands back the
 * existing tuple rather than rebuilding it via heap_form_tuple — exactly
 * what CREATE TABLE AS SELECT / INSERT ... SELECT do) silently skips
 * re-externalizing the value. The row then keeps pointing at the SOURCE
 * relation's TOAST table, which breaks ("could not open relation" / "missing
 * chunk") the moment that source is later altered/rewritten/dropped, even
 * though the destination itself was never touched. Fixing the bit once here
 * — the single choke point every decrypted tuple passes through — means
 * every downstream consumer sees a truthful tuple, instead of requiring each
 * one to remember to re-derive it.
 */
HeapTuple
tde_decrypt_heap_tuple(HeapTuple enc, Oid relid, TupleDesc tupdesc)
{
    Size        hdr_len   = enc->t_data->t_hoff;
    char       *enc_data  = (char *) enc->t_data + hdr_len;
    Size        enc_len   = enc->t_len - hdr_len;
    Size        pt_len    = enc_len - TDE_V4_OVERHEAD;
    unsigned char version;
    HeapTuple   plain;
    /* Pass-through mode: stored tuple is plaintext — return a copy. */
    if (!pg_vault_tde_enabled)
        return heap_copytuple(enc);
    /* Every tuple carries TDE_V4_OVERHEAD bytes; shorter means corrupt. */
    if (hdr_len > enc->t_len || enc_len < (Size) TDE_V4_OVERHEAD)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("pg_vault_tde: encrypted tuple too short (%zu bytes)",
                        enc_len)));
    /* Allocate once, copy header, then decrypt into the user-data region. */
    plain = (HeapTuple) palloc0(HEAPTUPLESIZE + hdr_len + pt_len);
    plain->t_data = (HeapTupleHeader) ((char *) plain + HEAPTUPLESIZE);
    memcpy(plain->t_data, enc->t_data, hdr_len);

    version = (unsigned char) enc_data[enc_len - TDE_V4_GEN_LEN - 1];

    if (version == TDE_TUPLE_V5_VERSION_BYTE)
    {
        tde_vrange *ranges;
        int         nranges = 0;
        Size        end_off = 0;
        Size        val_len;
        Size        out_len;
        char       *blob;
        char       *val_buf;
        char       *dst = (char *) plain->t_data + hdr_len;
        Size        pos;
        int         i;

        /*
         * Copy the layout first: the structural bytes are already in clear and
         * the walk below needs them.  The value bytes land encrypted and are
         * overwritten in place once the AEAD has verified them.
         */
        memcpy(dst, enc_data, pt_len);

        ranges = (tde_vrange *) palloc(sizeof(tde_vrange) * (tupdesc->natts + 1));
        val_len = tde_value_ranges(plain->t_data, tupdesc, pt_len,
                                   ranges, &nranges, &end_off);
        if (end_off != pt_len)
        {
            pfree(ranges);
            pfree(plain);
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_CORRUPTED),
                     errmsg("pg_vault_tde: attribute walk covered %zu of %zu data bytes",
                            end_off, pt_len)));
        }

        /*
         * Rebuild the contiguous AEAD message the crypto layer speaks: the
         * scattered ciphertext between the IV and the trailer, with the
         * framing byte set back to the crypto wire version (the 0x05 on disk
         * versions the tuple LAYOUT, not the cipher, and is outside the tag).
         */
        blob = (char *) palloc(val_len + TDE_V4_OVERHEAD);
        memcpy(blob, enc_data + pt_len, TDE_GCM_IV_LEN);
        for (i = 0, pos = 0; i < nranges; i++)
        {
            memcpy(blob + TDE_GCM_IV_LEN + pos,
                   enc_data + ranges[i].off, ranges[i].len);
            pos += ranges[i].len;
        }
        memcpy(blob + TDE_GCM_IV_LEN + val_len,
               enc_data + pt_len + TDE_GCM_IV_LEN,
               TDE_GCM_TAG_LEN + 1 + TDE_V4_GEN_LEN);
        blob[TDE_GCM_IV_LEN + val_len + TDE_GCM_TAG_LEN] = (char) TDE_V4_VERSION_BYTE;

        val_buf = (char *) palloc(val_len > 0 ? val_len : 1);
        out_len = val_len;
        if (!tde_gcm_decrypt(relid, blob, val_len + TDE_V4_OVERHEAD,
                             val_buf, &out_len))
        {
            pfree(blob);
            pfree(val_buf);
            pfree(ranges);
            pfree(plain);
            ereport(ERROR,
                        (errmsg("pg_vault_tde: decryption failed")));
        }
        pfree(blob);

        for (i = 0, pos = 0; i < nranges; i++)
        {
            memcpy(dst + ranges[i].off, val_buf + pos, ranges[i].len);
            pos += ranges[i].len;
        }
        OPENSSL_cleanse(val_buf, val_len);
        pfree(val_buf);
        pfree(ranges);
    }
    else
    {
        /* Legacy v4: the whole user-data region is one opaque blob. */
        /* GCM auth failure ereports inside; returns false only on a bad version byte. */
        if (!tde_gcm_decrypt(relid, enc_data, enc_len,
                             (char *) plain->t_data + hdr_len, &pt_len))
        {
            pfree(plain);
            ereport(ERROR,
                        (errmsg("pg_vault_tde: decryption failed")));
        }
    }

    plain->t_len      = (uint32) (hdr_len + pt_len);
    plain->t_self     = enc->t_self;
    plain->t_tableOid = enc->t_tableOid;

    /* Restore a truthful HEAP_HASEXTERNAL — see comment above. */
    if (tde_tuple_has_external_desc(plain, tupdesc))
        plain->t_data->t_infomask |= HEAP_HASEXTERNAL;
    else
        plain->t_data->t_infomask &= ~HEAP_HASEXTERNAL;

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
    plain = tde_decrypt_heap_tuple(bslot->base.tuple, saved_tableoid,
                                    slot->tts_tupleDescriptor);


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
/* ---- Sequential scan (SeqScan) ---- */
/*
 * pg_vault_tde_scan_getnextslot
 *
 * SeqScan read path.  Delegates to heapam which fills the
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
 * pg_vault_tde_scan_getnextslot_tidrange
 *
 * TidRangeScan read path.  scan_getnextslot_tidrange is a
 * SEPARATE TableAmRoutine callback from scan_getnextslot — it is not
 * covered by overriding scan_getnextslot alone.  Without this wrapper,
 * queries planned as "Tid Range Scan" (e.g. WHERE ctid BETWEEN ...)
 * read raw ciphertext from the page into the slot, undecrypted.
 *
 * Same delegate-then-decode pattern as pg_vault_tde_scan_getnextslot.
 */

static bool 
pg_vault_tde_scan_getnextslot_tidrange(TableScanDesc scan, ScanDirection direction,
                                            TupleTableSlot *slot)
{
    if(!heapam_scan_getnextslot_tidrange_cb(scan, direction, slot))
        return false;
    if(!TupIsNull(slot))
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
 *
 * v1.6: TOAST chunks are now encrypted.  We decrypt after the delegate call
 * using automatic routing (tde_decrypt_heap_tuple → pg_vault_tde_kms_get_rel_dek
 * handles TOAST relid → parent_relid mapping).
 */
/*
 * Impersonation depth — development-build accounting, see make ci-cassert.
 *
 * Three functions in this file temporarily point rel->rd_tableam at stock
 * heapam so that core's identity checks pass, and must restore it on every
 * exit path including the error one.
 *
 * A leak here is the worst failure this file can produce, and the quietest.
 * rd_tableam is the pointer core dispatches through:
 *
 *     rel->rd_tableam->tuple_insert(...)        tableam.h:1370
 *
 * so a leaked impersonation corrupts nothing and crashes nothing — it simply
 * routes every later write on that relation to heapam, and the table silently
 * stops being encrypted.  No memory checker, sanitizer or static analyser can
 * see that: the state is valid, the behaviour is defined, the branch is
 * reachable.  It is only wrong against a rule of ours.
 *
 * That same dispatch is why an Assert at the top of our own callbacks would be
 * useless: after a leak they are no longer dispatched, so they never run to
 * notice.  Counting enter/exit and checking the balance at end of transaction
 * does not depend on dispatch, and reports in the very transaction that leaked.
 *
 * Expands to nothing without --enable-cassert.
 */
#ifdef USE_ASSERT_CHECKING
static int tde_impersonation_depth = 0;
#define TDE_IMPERSONATE_ENTER()  (tde_impersonation_depth++)
#define TDE_IMPERSONATE_EXIT()   (tde_impersonation_depth--)

static void
tde_impersonation_xact_check(XactEvent event, void *arg)
{
    if (event == XACT_EVENT_COMMIT || event == XACT_EVENT_ABORT)
        Assert(tde_impersonation_depth == 0);
}
#else
#define TDE_IMPERSONATE_ENTER()  ((void) 0)
#define TDE_IMPERSONATE_EXIT()   ((void) 0)
#endif

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
    TDE_IMPERSONATE_ENTER();
    *rdam  = GetHeapamTableAmRoutine();
    PG_TRY();
    {
        result = heapam_index_fetch_tuple_cb(scan, tid, snapshot, slot,
                                             call_again, all_dead);
    }
    PG_CATCH();
    {
        *rdam = saved_am;
        TDE_IMPERSONATE_EXIT();
        PG_RE_THROW();
    }
    PG_END_TRY();
    *rdam  = saved_am;
    TDE_IMPERSONATE_EXIT();
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
 * tde_decrypt_for_index — the decrypted copy of a raw tuple the build scan is
 * about to index, allocated in CurrentMemoryContext.
 *
 * A tuple no snapshot but an old one can see (RECENTLY_DEAD, and the like)
 * may be under a DEK generation the catalog and the cache no longer hold —
 * two rotations while that snapshot stayed open.  Such a tuple cannot be
 * indexed, so NULL is returned and the caller marks the index unusable for
 * old snapshots, the fallback core itself uses for broken HOT chains.  A live
 * tuple that does not decrypt is an error, as everywhere else.
 * tde_decrypt_heap_tuple() holds no resource, so the error can be caught
 * without a subtransaction (as in verify_integrity()).
 */
static HeapTuple
tde_decrypt_for_index(HeapTuple raw, Relation heap_rel, bool alive)
{
    MemoryContext      cxt = CurrentMemoryContext;
    HeapTuple volatile plain = NULL;

    if (alive)
        return tde_decrypt_heap_tuple(raw, RelationGetRelid(heap_rel),
                                      RelationGetDescr(heap_rel));

    PG_TRY();
    {
        plain = tde_decrypt_heap_tuple(raw, RelationGetRelid(heap_rel),
                                       RelationGetDescr(heap_rel));
    }
    PG_CATCH();
    {
        MemoryContextSwitchTo(cxt);
        FlushErrorState();
        plain = NULL;
    }
    PG_END_TRY();

    return plain;
}

/*
 * tde_index_build_heap_scan — heapam_index_build_range_scan
 * (access/heap/heapam_handler.c, the same in PG 17 and 18), with each tuple
 * it indexes decrypted first and the keys of a tde_btree index encrypted.
 * Must run with heap_rel impersonating heapam: heap_getnext() checks.
 *
 * Which tuples reach the index is heapam's decision, unchanged: a serial,
 * non-concurrent build scans with SnapshotAny and HeapTupleSatisfiesVacuum,
 * indexes RECENTLY_DEAD tuples — older snapshots may still need them — sets
 * ii_BrokenHotChain when only the live end of a HOT chain can be indexed,
 * and waits for in-progress writers when checking uniqueness; a concurrent
 * build indexes what an MVCC snapshot sees.  Then the partial-index predicate
 * and the HOT root TID.  Block progress is not reported: heapam's helper for
 * it is static.
 */
static double
tde_index_build_heap_scan(Relation heap_rel,
                          Relation index_rel,
                          struct IndexInfo *index_info,
                          bool allow_sync,
                          bool anyvisible,
                          BlockNumber start_blockno,
                          BlockNumber numblocks,
                          IndexBuildCallback callback,
                          void *callback_state,
                          TableScanDesc scan)
{
    HeapScanDesc    hscan;
    bool            is_system_catalog = IsSystemRelation(heap_rel);
    bool            checking_uniqueness = (index_info->ii_Unique ||
                                           index_info->ii_ExclusionOps != NULL);
    HeapTuple       heapTuple;
    Datum           values[INDEX_MAX_KEYS];
    bool            isnull[INDEX_MAX_KEYS];
    double          reltuples = 0;
    ExprState      *predicate;
    TupleTableSlot *slot;
    EState         *estate;
    ExprContext    *econtext;
    Snapshot        snapshot;
    bool            need_unregister_snapshot = false;
    TransactionId   OldestXmin = InvalidTransactionId;
    BlockNumber     root_blkno = InvalidBlockNumber;
    OffsetNumber    root_offsets[MaxHeapTuplesPerPage];

    Assert(OidIsValid(index_rel->rd_rel->relam));
    Assert(!(anyvisible && checking_uniqueness));
    Assert(heap_rel->rd_tableam == GetHeapamTableAmRoutine());

    /*
     * The tuple under test is the decrypted copy, in a plain heap-tuple slot:
     * the raw one in the buffer is ciphertext.
     */
    estate = CreateExecutorState();
    econtext = GetPerTupleExprContext(estate);
    slot = MakeSingleTupleTableSlot(RelationGetDescr(heap_rel), &TTSOpsHeapTuple);
    econtext->ecxt_scantuple = slot;

    /* A partial index takes only the rows its predicate admits (PSQLE-198). */
    predicate = ExecPrepareQual(index_info->ii_Predicate, estate);

    if (!IsBootstrapProcessingMode() && !index_info->ii_Concurrent)
        OldestXmin = GetOldestNonRemovableTransactionId(heap_rel);

    if (!scan)
    {
        if (!TransactionIdIsValid(OldestXmin))
        {
            snapshot = RegisterSnapshot(GetTransactionSnapshot());
            need_unregister_snapshot = true;
        }
        else
            snapshot = SnapshotAny;

        scan = table_beginscan_strat(heap_rel, snapshot, 0, NULL,
                                     true, allow_sync);
    }
    else
    {
        /* Parallel build: the leader chose the snapshot on the same terms. */
        Assert(!IsBootstrapProcessingMode());
        Assert(allow_sync);
        snapshot = scan->rs_snapshot;
    }

    hscan = (HeapScanDesc) scan;

    Assert(snapshot == SnapshotAny || IsMVCCSnapshot(snapshot));
    Assert(snapshot == SnapshotAny ? TransactionIdIsValid(OldestXmin) :
           !TransactionIdIsValid(OldestXmin));
    Assert(snapshot == SnapshotAny || !anyvisible);

    if (!allow_sync)
        heap_setscanlimits(scan, start_blockno, numblocks);
    else
    {
        Assert(start_blockno == 0);
        Assert(numblocks == InvalidBlockNumber);
    }

    while ((heapTuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
    {
        bool            tupleIsAlive;
        HeapTuple       plain;
        ItemPointerData tid;
        MemoryContext   oldcxt;

        CHECK_FOR_INTERRUPTS();

        /* Root offsets of the page's HOT chains; see heapam for why this is safe. */
        if (hscan->rs_cblock != root_blkno)
        {
            Page        page = BufferGetPage(hscan->rs_cbuf);

            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_SHARE);
            heap_get_root_tuples(page, root_offsets);
            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_UNLOCK);

            root_blkno = hscan->rs_cblock;
        }

        if (snapshot == SnapshotAny)
        {
            bool            indexIt;
            TransactionId   xwait;

    recheck:
            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_SHARE);

            switch (HeapTupleSatisfiesVacuum(heapTuple, OldestXmin,
                                             hscan->rs_cbuf))
            {
                case HEAPTUPLE_DEAD:
                    indexIt = false;
                    tupleIsAlive = false;
                    break;
                case HEAPTUPLE_LIVE:
                    indexIt = true;
                    tupleIsAlive = true;
                    reltuples += 1;
                    break;
                case HEAPTUPLE_RECENTLY_DEAD:
                    /*
                     * Indexed anyway, for pre-existing snapshots — unless it
                     * was HOT-updated: then only the live end of the chain is,
                     * and the index is marked unsafe for old snapshots.
                     */
                    if (HeapTupleIsHotUpdated(heapTuple))
                    {
                        indexIt = false;
                        index_info->ii_BrokenHotChain = true;
                    }
                    else
                        indexIt = true;
                    tupleIsAlive = false;
                    break;
                case HEAPTUPLE_INSERT_IN_PROGRESS:
                    if (anyvisible)
                    {
                        indexIt = true;
                        tupleIsAlive = true;
                        reltuples += 1;
                        break;
                    }

                    xwait = HeapTupleHeaderGetXmin(heapTuple->t_data);
                    if (!TransactionIdIsCurrentTransactionId(xwait))
                    {
                        if (!is_system_catalog)
                            elog(WARNING, "concurrent insert in progress within table \"%s\"",
                                 RelationGetRelationName(heap_rel));

                        if (checking_uniqueness)
                        {
                            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_UNLOCK);
                            XactLockTableWait(xwait, heap_rel,
                                              &heapTuple->t_self,
                                              XLTW_InsertIndexUnique);
                            CHECK_FOR_INTERRUPTS();
                            goto recheck;
                        }
                    }
                    else
                        reltuples += 1;

                    indexIt = true;
                    tupleIsAlive = true;
                    break;
                case HEAPTUPLE_DELETE_IN_PROGRESS:
                    if (anyvisible)
                    {
                        indexIt = true;
                        tupleIsAlive = false;
                        reltuples += 1;
                        break;
                    }

                    xwait = HeapTupleHeaderGetUpdateXid(heapTuple->t_data);
                    if (!TransactionIdIsCurrentTransactionId(xwait))
                    {
                        if (!is_system_catalog)
                            elog(WARNING, "concurrent delete in progress within table \"%s\"",
                                 RelationGetRelationName(heap_rel));

                        if (checking_uniqueness ||
                            HeapTupleIsHotUpdated(heapTuple))
                        {
                            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_UNLOCK);
                            XactLockTableWait(xwait, heap_rel,
                                              &heapTuple->t_self,
                                              XLTW_InsertIndexUnique);
                            CHECK_FOR_INTERRUPTS();
                            goto recheck;
                        }

                        indexIt = true;
                        reltuples += 1;
                    }
                    else if (HeapTupleIsHotUpdated(heapTuple))
                    {
                        indexIt = false;
                        index_info->ii_BrokenHotChain = true;
                    }
                    else
                        indexIt = true;
                    tupleIsAlive = false;
                    break;
                default:
                    elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
                    indexIt = tupleIsAlive = false; /* keep compiler quiet */
                    break;
            }

            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_UNLOCK);

            if (!indexIt)
                continue;
        }
        else
        {
            /* heap_getnext did the time qual check */
            tupleIsAlive = true;
            reltuples += 1;
        }

        /* The previous row's decrypted copy and index temporaries go here. */
        ExecClearTuple(slot);
        MemoryContextReset(econtext->ecxt_per_tuple_memory);

        oldcxt = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);
        plain = tde_decrypt_for_index(heapTuple, heap_rel, tupleIsAlive);
        MemoryContextSwitchTo(oldcxt);
        if (plain == NULL)
        {
            index_info->ii_BrokenHotChain = true;
            continue;
        }
        ExecStoreHeapTuple(plain, slot, false);

        if (predicate != NULL && !ExecQual(predicate, econtext))
            continue;

        oldcxt = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);
        FormIndexDatum(index_info, slot, estate, values, isnull);

        /* A heap-only tuple is indexed under the TID of its chain's root. */
        tid = heapTuple->t_self;
        if (HeapTupleIsHeapOnly(heapTuple))
        {
            OffsetNumber offnum = ItemPointerGetOffsetNumber(&heapTuple->t_self);

            if (root_offsets[offnum - 1] == InvalidOffsetNumber)
            {
                Page        page = BufferGetPage(hscan->rs_cbuf);

                LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_SHARE);
                heap_get_root_tuples(page, root_offsets);
                LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_UNLOCK);
            }

            if (!OffsetNumberIsValid(root_offsets[offnum - 1]))
                ereport(ERROR,
                        (errcode(ERRCODE_DATA_CORRUPTED),
                         errmsg_internal("failed to find parent tuple for heap-only tuple at (%u,%u) in table \"%s\"",
                                         ItemPointerGetBlockNumber(&heapTuple->t_self),
                                         offnum,
                                         RelationGetRelationName(heap_rel))));

            ItemPointerSet(&tid, ItemPointerGetBlockNumber(&heapTuple->t_self),
                           root_offsets[offnum - 1]);
        }

            if (tde_iam_is_tde_btree_index(index_rel))
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
                callback(index_rel, &tid, enc_values, enc_isnull,
                         tupleIsAlive, callback_state);
            }
            else
            {
                MemoryContextSwitchTo(oldcxt);
                callback(index_rel, &tid, values, isnull,
                         tupleIsAlive, callback_state);
            }
    }

    table_endscan(scan);

    if (need_unregister_snapshot)
        UnregisterSnapshot(snapshot);

    ExecDropSingleTupleTableSlot(slot);
    FreeExecutorState(estate);

    /* These pointed into the now-gone estate. */
    index_info->ii_ExpressionsState = NIL;
    index_info->ii_PredicateState = NULL;

    return reltuples;
}

/*
 * pg_vault_tde_index_build_range_scan
 *
 * CREATE INDEX / REINDEX on an encrypted_heap table (its TOAST relation
 * included).  heapam's own scan would compute the keys from ciphertext, so
 * tde_index_build_heap_scan() runs heapam's logic on decrypted copies.  Up to
 * 1.7.2 this was a simplified loop over a fresh MVCC snapshot: it skipped
 * recently dead tuples and never set ii_BrokenHotChain, so a transaction
 * whose snapshot predated the index missed rows through it, or got rows whose
 * visible version does not satisfy its quals (PSQLE-201).
 *
 * heap_getnext() insists on rd_tableam being heapam's, so the relation
 * impersonates heapam for the scan, as in relation_copy_for_cluster.
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
    const TableAmRoutine  *saved_am = heap_rel->rd_tableam;
    const TableAmRoutine **rdam = (const TableAmRoutine **) (void *) &heap_rel->rd_tableam;
    double volatile        reltuples = 0;

    (void) progress;

    TDE_IMPERSONATE_ENTER();
    *rdam = GetHeapamTableAmRoutine();

    PG_TRY();
    {
        reltuples = tde_index_build_heap_scan(heap_rel, index_rel, index_info,
                                              allow_sync, anyvisible,
                                              start_blockno, numblocks,
                                              callback, callback_state, scan);
    }
    PG_CATCH();
    {
        *rdam = saved_am;
        TDE_IMPERSONATE_EXIT();
        PG_RE_THROW();
    }
    PG_END_TRY();

    *rdam = saved_am;
    TDE_IMPERSONATE_EXIT();

    return reltuples;
}

/* ---- Index validation (CREATE INDEX CONCURRENTLY / REINDEX CONCURRENTLY) ---- */
/*
* pg_vault_tde_index_validate_scan
*
* Why a custom scan instead of delegating to heapam_index_validate_scan (as
* index_fetch_tuple does by impersonating heapam): heapam scans with
* heap_getnext(), which trips the rd_tableam == GetHeapamTableAmRoutine()
* guard and, even with impersonation, would feed FormIndexDatum raw ciphertext
* -- silently indexing garbage keys for concurrently-inserted rows.
*
* Why no key pre-encryption here (unlike pg_vault_tde_index_build_range_scan):
* validation inserts via index_insert -> pg_vault_tde_aminsert, which owns
* the AES-256-SIV encryption -- exactly like a runtime INSERT.
*/
static void
pg_vault_tde_index_validate_scan(Relation heap_rel,
                                Relation index_rel,
                                struct IndexInfo *index_info,
                                Snapshot snapshot,
                                struct ValidateIndexState *state)
{   
    TableScanDesc   scan;
    HeapScanDesc    hscan;
    EState         *estate;
    ExprContext    *econtext;
    TupleTableSlot *slot;
    ExprState      *predicate;
    Datum           values[INDEX_MAX_KEYS];
    bool            isnull[INDEX_MAX_KEYS];
    OffsetNumber    root_offsets[MaxHeapTuplesPerPage];
    bool            in_index[MaxHeapTuplesPerPage];
    BlockNumber     root_blkno = InvalidBlockNumber;
    ItemPointer     indexcursor = NULL;
    ItemPointerData decoded;
    bool            tuplesort_empty = false;
    MemoryContext   scan_mcxt;

    estate   = CreateExecutorState();
    econtext = GetPerTupleExprContext(estate);
    slot     = table_slot_create(heap_rel, NULL);
    econtext->ecxt_scantuple = slot;
    predicate = ExecPrepareQual(index_info->ii_Predicate, estate);

    scan  = table_beginscan_strat(heap_rel, snapshot, 0, NULL, true, false);
    hscan = (HeapScanDesc) scan;

    /*
    * decode_slot's decrypted tuple must outlive the per-tuple context we reset
    * each iteration, or it would be freed under the slot (see
    * pg_vault_tde_index_build_range_scan).
    */ 
    scan_mcxt = CurrentMemoryContext;
    for (;;)
    {   
        HeapTuple       heapTuple;
        ItemPointerData rootTuple;
        OffsetNumber    root_offnum;
        MemoryContext   oldcxt;

        CHECK_FOR_INTERRUPTS();

        ResetExprContext(econtext);
        ExecClearTuple(slot);
        
        oldcxt = MemoryContextSwitchTo(scan_mcxt);
        if (!table_scan_getnextslot(scan, ForwardScanDirection, slot))
        {
            MemoryContextSwitchTo(oldcxt);
            break;
        }
        MemoryContextSwitchTo(oldcxt);

        state->htups += 1;
        heapTuple = ExecFetchSlotHeapTuple(slot, false, NULL);

        /*
        * On each new heap page rebuild the root-offset map and clear in_index[]:
        * we visit tuples by offset but compare against HOT root offsets, so a
        * page's index TIDs may be consumed out of order and must be remembered.
        */
        if (hscan->rs_cblock != root_blkno)
        {
            Page page = BufferGetPage(hscan->rs_cbuf);
            
            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_SHARE);
            heap_get_root_tuples(page, root_offsets);
            LockBuffer(hscan->rs_cbuf, BUFFER_LOCK_UNLOCK);
        
            memset(in_index, 0, sizeof(in_index));
            root_blkno = hscan->rs_cblock;
        }
        
        /* Index HOT-chain members under their root line pointer. */
        rootTuple   = heapTuple->t_self;
        root_offnum = ItemPointerGetOffsetNumber(&heapTuple->t_self);
        if (HeapTupleIsHeapOnly(heapTuple))
        {
            root_offnum = root_offsets[root_offnum - 1];
            if (!OffsetNumberIsValid(root_offnum))
                ereport(ERROR,
                        (errcode(ERRCODE_DATA_CORRUPTED),
                        errmsg_internal("failed to find parent tuple for heap-only tuple at (%u,%u) in table \"%s\"",
                                        ItemPointerGetBlockNumber(&heapTuple->t_self),
                                        ItemPointerGetOffsetNumber(&heapTuple->t_self),
                                        RelationGetRelationName(heap_rel))));
            ItemPointerSetOffsetNumber(&rootTuple, root_offnum);
        }                                
            
        while (!tuplesort_empty &&       
                (indexcursor == NULL ||
                ItemPointerCompare(indexcursor, &rootTuple) < 0))
        {
            Datum ts_val;
            bool  ts_isnull;
            
            /* Remember index TIDs already passed over on the current page. */
            if (indexcursor != NULL &&
                ItemPointerGetBlockNumber(indexcursor) == root_blkno)
                in_index[ItemPointerGetOffsetNumber(indexcursor) - 1] = true;
                
            tuplesort_empty = !tuplesort_getdatum(state->tuplesort, true, false,
                                                &ts_val, &ts_isnull, NULL);
            Assert(tuplesort_empty || !ts_isnull);
            if (!tuplesort_empty)
            {
                itemptr_decode(&decoded, DatumGetInt64(ts_val));
                indexcursor = &decoded;
            }   
            else
                indexcursor = NULL;
        }   
            
        if ((tuplesort_empty ||
            ItemPointerCompare(indexcursor, &rootTuple) > 0) &&
            !in_index[root_offnum - 1])
        {    
            oldcxt = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);
        
            /* Partial index: skip tuples failing the predicate. */
            if (predicate != NULL && !ExecQual(predicate, econtext))
            {
                MemoryContextSwitchTo(oldcxt);
                continue;
            }   
            
            FormIndexDatum(index_info, slot, estate, values, isnull);
            
            index_insert(index_rel, values, isnull, &rootTuple,
                        heap_rel,
                        index_info->ii_Unique ? UNIQUE_CHECK_YES
                                                : UNIQUE_CHECK_NO,
                        false,          /* indexUnchanged */
                        index_info);
                        
            state->tups_inserted += 1;
            MemoryContextSwitchTo(oldcxt);
        }   
    }       
        
    table_endscan(scan);
    ExecDropSingleTupleTableSlot(slot);
    FreeExecutorState(estate);

    /* estate is gone; drop the expression states that pointed into it. */
    index_info->ii_ExpressionsState = NIL;
    index_info->ii_PredicateState = NULL;
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
 * If the tuple fits within TOAST_TUPLE_THRESHOLD, has no already-external
 * attribute, or the relation has no TOAST table, the original tuple is
 * returned unchanged (no allocation).
 *
 * The HeapTupleHasExternal(tup) check mirrors stock heap_prepare_insert()
 * (heapam.c): a tuple can be small (small t_len) yet still carry an
 * out-of-line pointer belonging to a DIFFERENT relation's TOAST table — e.g.
 * a row copied row-by-row by ATRewriteTable() when a plain heap table with
 * pre-existing out-of-line values is converted via ALTER TABLE ... SET
 * ACCESS METHOD encrypted_heap.  Skipping pg_vault_tde_toast_tuple() (and
 * thus toast_tuple_init()'s foreign-pointer detection) in that case leaves
 * the stale pointer in place; once the source table/toast is dropped at the
 * end of the rewrite, the pointer dangles and any later read/update/delete
 * of that row fails with "could not open relation with OID ...".
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
    /*
     * Test the threshold against the tuple CORE will see, not this one.
     *
     * heap_prepare_insert (heapam.c:2334) re-tests
     *     HeapTupleHasExternal(tup) || tup->t_len > TOAST_TUPLE_THRESHOLD
     * on the tuple we hand to heap_insert/heap_update/heap_multi_insert, which
     * is this one plus TDE_V4_OVERHEAD bytes of AES-GCM wire overhead.  Note
     * that core's test does NOT consult reltoastrelid, so clearing that field
     * cannot keep core out of its TOAST path; the only way is to make sure the
     * encrypted tuple stays under the threshold.
     *
     * Declining to pre-TOAST a tuple that will cross the threshold once
     * encrypted is what let core deform ciphertext as varlena attributes and
     * segfault in toast_save_datum().  See TEST 153.
     */
    if (OidIsValid(rel->rd_rel->reltoastrelid) &&
        (HeapTupleHasExternal(tup) ||
         tup->t_len + TDE_V4_OVERHEAD > TOAST_TUPLE_THRESHOLD))
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
 * After pre-TOAST + encryption the tuple is below TOAST_TUPLE_THRESHOLD, so
 * heap_insert has nothing left to TOAST.  That guarantee is produced by two
 * places acting together: the gate in pg_vault_tde_toast_insert_or_update
 * tests the threshold against the ENCRYPTED length, and the writer in
 * pg_vault_tde_toast.c reserves TDE_V4_OVERHEAD in its target.
 *
 * Note that clearing reltoastrelid would NOT achieve this: heap_prepare_insert
 * (heapam.c:2334) tests only HeapTupleHasExternal() and t_len, never the toast
 * relation.  An earlier version of this file did clear it and the comments
 * survived the removal, which cost real time to unpick; see TEST 153.
 */
static void
pg_vault_tde_tuple_insert(Relation rel, TupleTableSlot *slot,
                           CommandId cid, int options,
                           struct BulkInsertStateData *bistate)
{
    bool       shouldFree = true;
    HeapTuple  plain = NULL;
    HeapTuple  volatile toasted = NULL;
    HeapTuple  volatile enc = NULL;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);
    /*
     * The PG_TRY wraps the entire encrypt → heap_insert pipeline so errors
     * also perform local cleanup (OPENSSL_cleanse, pfree).
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
    HeapTuple  volatile toasted = NULL;
    HeapTuple  volatile enc = NULL;

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
 *   Phase 2 — Call heap_multi_insert with the
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
     * OPENSSL_cleanses the plaintext intermediates.
    * TOAST writes in the custom path are expected to be transactional.
     */
    PG_TRY();
    {
        for (i = 0; i < nslots; i++)
        {
            HeapTuple  plain;
            bool       sf = true;
            plain = ExecFetchSlotHeapTuple(slots[i], true, &sf);
            plain->t_tableOid = table_oid;
            
            /* Track in-flight pointers for the cleanup path */
            plain_inflight = plain;
            plain_inflight_owned = sf;
            toasted_inflight = NULL;
            
            enc_tuples[i] = tde_prepare_encrypt_tuple(rel, plain, NULL, &toasted_inflight, options);

            /* Create a temporary slot and store the encrypted tuple in it */
            enc_slots[i] = MakeSingleTupleTableSlot(tupdesc,
                                                     &TTSOpsHeapTuple);
            ExecForceStoreHeapTuple(enc_tuples[i], enc_slots[i], false);
            encrypted_count = i + 1;
            /* Free intermediates eagerly */
            if (toasted_inflight != NULL && toasted_inflight != plain_inflight)
                pfree(toasted_inflight);
            toasted_inflight = NULL;
            if (sf)
                tde_release_plain(plain);
            /* Iteration completed cleanly — clear in-flight tracking */
            plain_inflight = NULL;
            plain_inflight_owned = false;
        }
        /*
         * Phase 2: batched heap insert with TOAST suppressed.
         *
         * heap_multi_insert has nothing left to TOAST: the encrypted tuples
         * are already under TOAST_TUPLE_THRESHOLD, because the gate and the
         * writer both account for TDE_V4_OVERHEAD.  Were one of them to stop
         * doing so, core would deform ciphertext as varlena and segfault.
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
        /* toasted_inflight aliases plain_inflight when the row needed no
         * TOASTing — tde_release_plain above already freed it. */
        if (toasted_inflight != NULL && toasted_inflight != plain_inflight)
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
 * tde_toast_delete_unshared — delete the out-of-line values of doomed that
 * kept (may be NULL) does not reference in the same column.
 *
 * Both are plaintext tuples of rel.  Dropped columns count: their chunks stay
 * until something deletes them.  With speculative the chunks must have been
 * inserted by this transaction, and are killed outright
 * (heap_abort_speculative), as core does for a failed INSERT ... ON CONFLICT.
 */
static void
tde_toast_delete_unshared(Relation rel, HeapTuple doomed, HeapTuple kept,
                          bool speculative)
{
    TupleDesc desc = RelationGetDescr(rel);
    int       natts = desc->natts;
    Datum    *dvals;
    bool     *dnull;
    Datum    *kvals = NULL;
    bool     *knull = NULL;

    Assert(doomed != NULL && doomed != kept);

    /* No TOAST relation, no out-of-line value: every UPDATE comes through. */
    if (!OidIsValid(rel->rd_rel->reltoastrelid))
        return;

    dvals = palloc(natts * sizeof(Datum));
    dnull = palloc(natts * sizeof(bool));
    heap_deform_tuple(doomed, desc, dvals, dnull);

    for (int i = 0; i < natts; i++)
    {
        struct varlena *d = (struct varlena *) DatumGetPointer(dvals[i]);

        if (dnull[i] || TupleDescAttr(desc, i)->attlen != -1 ||
            !VARATT_IS_EXTERNAL_ONDISK(d))
            continue;

        if (kept != NULL && kvals == NULL)
        {
            kvals = palloc(natts * sizeof(Datum));
            knull = palloc(natts * sizeof(bool));
            heap_deform_tuple(kept, desc, kvals, knull);
        }

        if (kept != NULL && !knull[i])
        {
            struct varlena *k = (struct varlena *) DatumGetPointer(kvals[i]);

            if (VARATT_IS_EXTERNAL_ONDISK(k) &&
                memcmp(d, k, VARSIZE_EXTERNAL(d)) == 0)
                continue;
        }

        toast_delete_datum(rel, dvals[i], speculative);
    }

    pfree(dvals);
    pfree(dnull);
    if (kvals != NULL)
    {
        pfree(kvals);
        pfree(knull);
    }
}

/*
 * pg_vault_tde_tuple_update
 *
 * UPDATE path: pre-TOASTs the plaintext, encrypts the (now-small) tuple,
 * then delegates to heap_update with TOAST suppressed.  heap_update may
 * return TM_Updated or other non-Ok results on concurrent modification;
 * we only propagate the new ctid to the slot on TM_Ok.
 *
 * The TOAST bookkeeping core does inside heap_update() happens here around
 * it, and only after it has answered (PSQLE-193): on TM_Ok the old row's
 * values the new one no longer references are deleted; otherwise the chunks
 * this call inserted are, since the executor may skip the row or retry on a
 * newer version that still points at the old ones.
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
    HeapTuple  volatile old_tuple = NULL;
    HeapTuple  volatile toasted = NULL;
    HeapTuple  volatile enc = NULL;
    TM_Result  result;
   
    TupleTableSlot *slot_old = NULL;

    plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
    plain->t_tableOid = RelationGetRelid(rel);

    slot_old = table_slot_create(rel, NULL);

    PG_TRY();
    {
        /*
         * The version heap_update() will look at, visible to this statement's
         * snapshot or not: after an EvalPlanQual recheck otid is a version
         * committed after it was taken.
         */
        if (pg_vault_tde_tuple_fetch_row_version(rel, otid, SnapshotAny, slot_old))
            old_tuple = ExecFetchSlotHeapTuple(slot_old, false, NULL);

        /*
         * The executor hands us the TID of a tuple it has just read or locked,
         * which cannot have been pruned since.  Without it the old values
         * could not be deleted below, only leaked.
         */
        Assert(old_tuple != NULL);

        enc = tde_prepare_encrypt_tuple(rel, plain, old_tuple, &toasted, 0);

        result = heap_update(rel, otid, enc, cid, crosscheck, wait,
                             tmfd, lockmode, update_indexes);

        /* toasted, not enc: enc is ciphertext. */
        if (result == TM_Ok)
        {
            ItemPointerCopy(&enc->t_self, &slot->tts_tid);
            slot->tts_tableOid = enc->t_tableOid;

            if (old_tuple != NULL)
                tde_toast_delete_unshared(rel, old_tuple, toasted, false);
        }
        else
            tde_toast_delete_unshared(rel, toasted, old_tuple, true);
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
 * tde_tuple_has_external_desc
 *
 * Per-attribute scan for VARATT_IS_EXTERNAL varlenas on a decrypted heap
 * tuple, given its TupleDesc directly (no Relation needed). This is
 * necessary because flag HEAP_HASEXTERNAL is cleansed in insert before
 * calling heap_insert(), otherwise it will call heap_toast_insert_or_update.
 * Shared by tde_tuple_has_external() (Relation-based callers) and
 * tde_decrypt_heap_tuple() (which only has a TupleDesc on hand).
 *
 * Dropped columns are skipped on purpose: a VACUUM FULL up to 1.7.1 left
 * their pointers dangling, and a HEAP_HASEXTERNAL set for them would make core
 * follow them (heap_copy_tuple_as_datum flattens a flagged tuple).  Deleting
 * their chunks does not go through here — see tde_toast_delete_unshared().
*/
static bool
tde_tuple_has_external_desc(HeapTuple tup, TupleDesc tupdesc)
{
    int natts = tupdesc->natts;
    Datum stack_values[MAX_STACK_ATTRS];
    bool  stack_isnull[MAX_STACK_ATTRS];

    Datum *values = stack_values;
    bool  *isnull = stack_isnull;
    bool  has_ext = false;

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
 * tde_tuple_has_external
 *
 * Relation-based wrapper around tde_tuple_has_external_desc(): skips the
 * scan entirely when the relation has no TOAST table at all.
*/
static bool
tde_tuple_has_external(HeapTuple tup, Relation rel)
{
    if (!OidIsValid(rel->rd_rel->reltoastrelid))
        return false;

    return tde_tuple_has_external_desc(tup, RelationGetDescr(rel));
}

/*
 * pg_vault_tde_tuple_complete_speculative
 *
 * An INSERT ... ON CONFLICT that lost the race: heapam kills the row with
 * heap_abort_speculative(), which deletes its TOAST chunks only when the
 * on-disk tuple carries HEAP_HASEXTERNAL — and an encrypted tuple never does
 * (see tde_encrypt_heap_tuple).  So kill the chunks first, from the decrypted
 * row; they were inserted by this transaction a moment ago, which is what
 * heap_abort_speculative() requires of them (PSQLE-197).
 */
static void
pg_vault_tde_tuple_complete_speculative(Relation rel, TupleTableSlot *slot,
                                        uint32 specToken, bool succeeded)
{
    if (!succeeded && OidIsValid(rel->rd_rel->reltoastrelid))
    {
        TupleTableSlot   *own = table_slot_create(rel, NULL);
        HeapTuple volatile plain = NULL;
        bool              shouldFree = false;

        Assert(ItemPointerIsValid(&slot->tts_tid));

        if (pg_vault_tde_tuple_fetch_row_version(rel, &slot->tts_tid,
                                                 SnapshotAny, own))
            plain = ExecFetchSlotHeapTuple(own, true, &shouldFree);

        /* Our own speculative insert, which nothing can have pruned. */
        Assert(plain != NULL);

        PG_TRY();
        {
            if (plain != NULL)
                tde_toast_delete_unshared(rel, plain, NULL, true);
        }
        PG_CATCH();
        {
            if (shouldFree && plain != NULL)
                tde_release_plain(plain);
            ExecDropSingleTupleTableSlot(own);
            PG_RE_THROW();
        }
        PG_END_TRY();

        if (shouldFree && plain != NULL)
            tde_release_plain(plain);
        ExecDropSingleTupleTableSlot(own);
    }

    heapam_tuple_complete_speculative_cb(rel, slot, specToken, succeeded);
}

/*
 * pg_vault_tde_tuple_delete
 *
 * DELETE path.  Delegates the physical row removal to heapam's tuple_delete,
 * then cleans up any TOAST chunks that belong to the deleted row.
 *
 * heap_delete() would do that itself, but the on-disk tuple never carries
 * HEAP_HASEXTERNAL (see tde_encrypt_heap_tuple), so the row is fetched and
 * decrypted first and, once TM_Ok is confirmed, tde_toast_delete_unshared()
 * deletes every out-of-line value in it — dropped columns included, whose
 * chunks nothing else ever deletes (PSQLE-192).
 *
 * The row is read with SnapshotAny: after an EvalPlanQual recheck tid is a
 * version committed after the statement's snapshot was taken, which that
 * snapshot does not see, and its values were left behind.
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
    bool shouldFree = false;

    slot = table_slot_create(rel, NULL);

    if (pg_vault_tde_tuple_fetch_row_version(rel, tid, SnapshotAny, slot))
        plain = ExecFetchSlotHeapTuple(slot, true, &shouldFree);

    /* As in tuple_update: a TID the executor just read or locked. */
    Assert(plain != NULL);

    PG_TRY();
    {
        result = heapam_tuple_delete_cb(rel, tid, cid, snapshot, crosscheck, wait, tmfd, changingPart);

        if (result == TM_Ok && plain != NULL)
            tde_toast_delete_unshared(rel, plain, NULL, false);
    }
    PG_CATCH();
    {
        if (shouldFree && plain != NULL)
            tde_release_plain(plain);

        if (slot != NULL)
            ExecDropSingleTupleTableSlot(slot);

        PG_RE_THROW();
    }
    PG_END_TRY();

    if (shouldFree && plain != NULL)
        tde_release_plain(plain);
    
    if (slot != NULL)
        ExecDropSingleTupleTableSlot(slot);

    return result;
}


static bool
tde_desc_has_dropped(TupleDesc desc)
{
    for (int i = 0; i < desc->natts; i++)
    {
        if (TupleDescAttr(desc, i)->attisdropped)
            return true;
    }
    return false;
}

/*
 * tde_without_dropped — plain with its dropped columns set to NULL, as a new
 * palloc'd tuple; core's reform_and_rewrite_tuple() does the same on every
 * rewrite.  The header is fresh: rewrite_heap_tuple() copies the visibility
 * fields over from the old tuple.
 */
static HeapTuple
tde_without_dropped(HeapTuple plain, TupleDesc desc)
{
    Datum    *values = palloc(desc->natts * sizeof(Datum));
    bool     *isnull = palloc(desc->natts * sizeof(bool));
    HeapTuple out;

    heap_deform_tuple(plain, desc, values, isnull);
    for (int i = 0; i < desc->natts; i++)
    {
        if (TupleDescAttr(desc, i)->attisdropped)
            isnull[i] = true;
    }

    out = heap_form_tuple(desc, values, isnull);
    out->t_self = plain->t_self;
    out->t_tableOid = plain->t_tableOid;

    pfree(values);
    pfree(isnull);
    return out;
}

/* A plaintext copy the CLUSTER path owns: cleansed, then freed. */
static void
tde_cluster_release(HeapTuple tup)
{
    if (tup != NULL)
    {
        Size hdr = tup->t_data->t_hoff;

        OPENSSL_cleanse((char *) tup->t_data + hdr, tup->t_len - hdr);
        pfree(tup);
    }
}

/*
 * tde_cluster_write_tuple — heapam's reform_and_rewrite_tuple() for
 * encrypted_heap.
 *
 * plain is the decrypted copy of a tuple the rewrite keeps.  It carries the
 * original's header (tde_decrypt_heap_tuple() copies it), so it is also the
 * "old" tuple rewrite_heap_tuple() maps update chains from.  Dropped columns
 * become NULL, as core does (PSQLE-192); out-of-line values move into
 * NewTable's TOAST relation — fetched through the TAM, stored again
 * encrypted; a row that would cross TOAST_TUPLE_THRESHOLD once encrypted is
 * toasted first (rewriteheap.c re-tests the threshold on what it is handed);
 * the row is encrypted under OldTable's DEK, which is the one its relid keeps
 * after finish_heap_swap.  Every plaintext copy made here is cleansed; plain
 * stays the caller's.
 */
static void
tde_cluster_write_tuple(RewriteState rwstate, Relation OldTable,
                        Relation NewTable, HeapTuple plain, bool has_dropped)
{
    TupleDesc          tupdesc = RelationGetDescr(OldTable);
    HeapTuple volatile reformed = NULL;
    HeapTuple volatile flat = NULL;
    HeapTuple volatile toasted = NULL;
    HeapTuple volatile enc_new = NULL;

    PG_TRY();
    {
        HeapTuple row = plain;

        if (has_dropped)
            row = reformed = tde_without_dropped(plain, tupdesc);

        /* The on-disk bit is always clear: scan the plaintext. */
        if (tde_tuple_has_external(row, OldTable))
        {
            flat = toast_flatten_tuple(row, tupdesc);
            row = toasted = pg_vault_tde_toast_tuple(NewTable, flat, NULL, 0);
            if (toasted == flat)
                toasted = NULL;
        }
        else if (row->t_len + TDE_V4_OVERHEAD > TOAST_TUPLE_THRESHOLD)
        {
            HeapTuple small = pg_vault_tde_toast_tuple(NewTable, row, NULL, 0);

            if (small != row)
                row = toasted = small;
        }

        enc_new = tde_encrypt_heap_tuple(row, RelationGetRelid(OldTable), tupdesc);

        /*
         * rewrite_heap_tuple asserts !HeapTupleHasExternal(new).  The bit is
         * about the plaintext; enc_new's data is ciphertext, with nothing in
         * it for rewriteheap.c to dereference.
         */
        enc_new->t_data->t_infomask &= ~HEAP_HASEXTERNAL;

        rewrite_heap_tuple(rwstate, plain, enc_new);
    }
    PG_CATCH();
    {
        tde_cluster_release(toasted);
        tde_cluster_release(flat);
        tde_cluster_release(reformed);
        if (enc_new != NULL)
            pfree(enc_new);
        PG_RE_THROW();
    }
    PG_END_TRY();

    tde_cluster_release(toasted);
    tde_cluster_release(flat);
    tde_cluster_release(reformed);
    pfree(enc_new);
}

/*
 * tde_cluster_copy — heapam_relation_copy_for_cluster (heapam_handler.c,
 * the same in PG 17 and 18 but for index_beginscan's signature) on decrypted
 * copies.  Must run with OldTable impersonating heapam: the scans, the slot
 * and the index fetch then read raw tuples with their buffer pinned, which
 * HeapTupleSatisfiesVacuum needs.
 *
 * Which tuples are kept, and in what order, is heapam's decision, unchanged:
 * SnapshotAny and HeapTupleSatisfiesVacuum, rewrite_heap_dead_tuple() for the
 * dead ones, then either an index scan in OldIndex order, a sort on OldIndex's
 * keys (use_sort), or — VACUUM FULL — the physical order.  Up to 1.7.2's fix
 * the TAM always read sequentially: CLUSTER compacted but did not order
 * (PSQLE-204).  Each kept tuple is decrypted before it is sorted or written,
 * since the sort computes the index keys from it.  Like any sort of
 * decrypted rows, one that outgrows maintenance_work_mem spills them to
 * temporary files in plaintext.
 */
static void
tde_cluster_copy(Relation OldTable, Relation NewTable, Relation OldIndex,
                 bool use_sort, TransactionId OldestXmin,
                 TransactionId *xid_cutoff, MultiXactId *multi_cutoff,
                 double *num_tuples, double *tups_vacuumed,
                 double *tups_recently_dead)
{
    RewriteState    rwstate;
    IndexScanDesc   indexScan;
    TableScanDesc   tableScan;
    HeapScanDesc    heapScan;
    bool            is_system_catalog = IsSystemRelation(OldTable);
    Tuplesortstate *tuplesort;
    TupleDesc       oldTupDesc = RelationGetDescr(OldTable);
    const bool      has_dropped = tde_desc_has_dropped(oldTupDesc);
    TupleTableSlot *slot;
    BufferHeapTupleTableSlot *hslot;
    BlockNumber     prev_cblock = InvalidBlockNumber;

    Assert(OldTable->rd_tableam == GetHeapamTableAmRoutine());
    Assert(RelationGetTargetBlock(NewTable) == InvalidBlockNumber);

    rwstate = begin_heap_rewrite(OldTable, NewTable, OldestXmin, *xid_cutoff,
                                 *multi_cutoff);

    if (use_sort)
        tuplesort = tuplesort_begin_cluster(oldTupDesc, OldIndex,
                                            maintenance_work_mem,
                                            NULL, TUPLESORT_NONE);
    else
        tuplesort = NULL;

    if (OldIndex != NULL && !use_sort)
    {
        const int   ci_index[] = {
            PROGRESS_CLUSTER_PHASE,
            PROGRESS_CLUSTER_INDEX_RELID
        };
        int64       ci_val[2];

        ci_val[0] = PROGRESS_CLUSTER_PHASE_INDEX_SCAN_HEAP;
        ci_val[1] = RelationGetRelid(OldIndex);
        pgstat_progress_update_multi_param(2, ci_index, ci_val);

        tableScan = NULL;
        heapScan = NULL;
#if PG_VERSION_NUM >= 180000
        indexScan = index_beginscan(OldTable, OldIndex, SnapshotAny, NULL, 0, 0);
#else
        indexScan = index_beginscan(OldTable, OldIndex, SnapshotAny, 0, 0);
#endif
        index_rescan(indexScan, NULL, 0, NULL, 0);
    }
    else
    {
        pgstat_progress_update_param(PROGRESS_CLUSTER_PHASE,
                                     PROGRESS_CLUSTER_PHASE_SEQ_SCAN_HEAP);

        tableScan = table_beginscan(OldTable, SnapshotAny, 0, (ScanKey) NULL);
        heapScan = (HeapScanDesc) tableScan;
        indexScan = NULL;

        pgstat_progress_update_param(PROGRESS_CLUSTER_TOTAL_HEAP_BLKS,
                                     heapScan->rs_nblocks);
    }

    slot = table_slot_create(OldTable, NULL);
    hslot = (BufferHeapTupleTableSlot *) slot;

    for (;;)
    {
        HeapTuple   tuple;
        HeapTuple   plain;
        Buffer      buf;
        bool        isdead;

        CHECK_FOR_INTERRUPTS();

        if (indexScan != NULL)
        {
            if (!index_getnext_slot(indexScan, ForwardScanDirection, slot))
                break;

            if (indexScan->xs_recheck)
                elog(ERROR, "CLUSTER does not support lossy index conditions");
        }
        else
        {
            /* One of the two scans is always open. */
            if (heapScan == NULL)
                elog(ERROR, "tde_cluster_copy: no scan open");

            if (!table_scan_getnextslot(tableScan, ForwardScanDirection, slot))
            {
                pgstat_progress_update_param(PROGRESS_CLUSTER_HEAP_BLKS_SCANNED,
                                             heapScan->rs_nblocks);
                break;
            }

            if (prev_cblock != heapScan->rs_cblock)
            {
                pgstat_progress_update_param(PROGRESS_CLUSTER_HEAP_BLKS_SCANNED,
                                             (heapScan->rs_cblock +
                                              heapScan->rs_nblocks -
                                              heapScan->rs_startblock
                                              ) % heapScan->rs_nblocks + 1);
                prev_cblock = heapScan->rs_cblock;
            }
        }

        tuple = ExecFetchSlotHeapTuple(slot, false, NULL);
        buf = hslot->buffer;

        LockBuffer(buf, BUFFER_LOCK_SHARE);

        switch (HeapTupleSatisfiesVacuum(tuple, OldestXmin, buf))
        {
            case HEAPTUPLE_DEAD:
                isdead = true;
                break;
            case HEAPTUPLE_RECENTLY_DEAD:
                *tups_recently_dead += 1;
                /* fall through */
            case HEAPTUPLE_LIVE:
                isdead = false;
                break;
            case HEAPTUPLE_INSERT_IN_PROGRESS:
                if (!is_system_catalog &&
                    !TransactionIdIsCurrentTransactionId(HeapTupleHeaderGetXmin(tuple->t_data)))
                    elog(WARNING, "concurrent insert in progress within table \"%s\"",
                         RelationGetRelationName(OldTable));
                isdead = false;
                break;
            case HEAPTUPLE_DELETE_IN_PROGRESS:
                if (!is_system_catalog &&
                    !TransactionIdIsCurrentTransactionId(HeapTupleHeaderGetUpdateXid(tuple->t_data)))
                    elog(WARNING, "concurrent delete in progress within table \"%s\"",
                         RelationGetRelationName(OldTable));
                *tups_recently_dead += 1;
                isdead = false;
                break;
            default:
                elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
                isdead = false; /* keep compiler quiet */
                break;
        }

        LockBuffer(buf, BUFFER_LOCK_UNLOCK);

        if (isdead)
        {
            *tups_vacuumed += 1;
            /* heap rewrite module still needs to see it... */
            if (rewrite_heap_dead_tuple(rwstate, tuple))
            {
                /* A previous recently-dead tuple is now known dead */
                *tups_vacuumed += 1;
                *tups_recently_dead -= 1;
            }
            continue;
        }

        *num_tuples += 1;

        plain = tde_decrypt_heap_tuple(tuple, RelationGetRelid(OldTable), oldTupDesc);
        if (tuplesort != NULL)
        {
            /* The sort copies it and computes OldIndex's keys from it. */
            tuplesort_putheaptuple(tuplesort, plain);
            pgstat_progress_update_param(PROGRESS_CLUSTER_HEAP_TUPLES_SCANNED,
                                         *num_tuples);
        }
        else
        {
            const int   ct_index[] = {
                PROGRESS_CLUSTER_HEAP_TUPLES_SCANNED,
                PROGRESS_CLUSTER_HEAP_TUPLES_WRITTEN
            };
            int64       ct_val[2];

            tde_cluster_write_tuple(rwstate, OldTable, NewTable, plain, has_dropped);

            ct_val[0] = *num_tuples;
            ct_val[1] = *num_tuples;
            pgstat_progress_update_multi_param(2, ct_index, ct_val);
        }
        tde_cluster_release(plain);
    }

    if (indexScan != NULL)
        index_endscan(indexScan);
    if (tableScan != NULL)
        table_endscan(tableScan);
    ExecDropSingleTupleTableSlot(slot);

    if (tuplesort != NULL)
    {
        double      n_tuples = 0;

        pgstat_progress_update_param(PROGRESS_CLUSTER_PHASE,
                                     PROGRESS_CLUSTER_PHASE_SORT_TUPLES);

        tuplesort_performsort(tuplesort);

        pgstat_progress_update_param(PROGRESS_CLUSTER_PHASE,
                                     PROGRESS_CLUSTER_PHASE_WRITE_NEW_HEAP);

        for (;;)
        {
            HeapTuple   plain;

            CHECK_FOR_INTERRUPTS();

            /*
             * The sort's own copy, with the original header: it stays in the
             * sort's memory (the argument is "forward", not "copy"), so it
             * is cleansed in place, not freed.
             */
            plain = tuplesort_getheaptuple(tuplesort, true);
            if (plain == NULL)
                break;

            n_tuples += 1;
            tde_cluster_write_tuple(rwstate, OldTable, NewTable, plain, has_dropped);
            OPENSSL_cleanse((char *) plain->t_data + plain->t_data->t_hoff,
                            plain->t_len - plain->t_data->t_hoff);
            pgstat_progress_update_param(PROGRESS_CLUSTER_HEAP_TUPLES_WRITTEN,
                                         n_tuples);
        }

        tuplesort_end(tuplesort);
    }

    end_heap_rewrite(rwstate);
}

/*
 * pg_vault_tde_relation_copy_for_cluster
 *
 * VACUUM FULL and CLUSTER.  heapam's own function cannot run on
 * encrypted_heap: our scans decrypt and drop the buffer pin
 * HeapTupleSatisfiesVacuum needs, and it would flatten TOAST pointers out of
 * ciphertext.  So tde_cluster_copy() runs heapam's logic on decrypted
 * copies, with OldTable impersonating heapam for the scans (heap_getnext()
 * checks rd_tableam) — as in pg_vault_tde_index_build_range_scan().
 *
 * A tde_btree index is ordered by the ciphertext of its keys, which says
 * nothing about their values: CLUSTER on one is refused rather than done in
 * that order.  core accepts it because tde_btree inherits btree's
 * amclusterable, which it cannot drop (see pg_vault_tde_iam.c).
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
    const TableAmRoutine  *saved_am = OldTable->rd_tableam;
    const TableAmRoutine **rdam = (const TableAmRoutine **) (void *) &OldTable->rd_tableam;

    if (OldIndex != NULL && tde_iam_is_tde_btree_index(OldIndex))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("cannot cluster table \"%s\" on tde_btree index \"%s\"",
                        RelationGetRelationName(OldTable),
                        RelationGetRelationName(OldIndex)),
                 errdetail("A tde_btree index is ordered by the ciphertext of its keys, not by their values."),
                 errhint("Use VACUUM FULL to compact the table, or CLUSTER on a plain btree index; "
                         "ALTER TABLE ... SET WITHOUT CLUSTER clears a tde_btree clustering index.")));

    TDE_IMPERSONATE_ENTER();
    *rdam = GetHeapamTableAmRoutine();

    PG_TRY();
    {
        tde_cluster_copy(OldTable, NewTable, OldIndex, use_sort, OldestXmin,
                         xid_cutoff, multi_cutoff,
                         num_tuples, tups_vacuumed, tups_recently_dead);
    }
    PG_CATCH();
    {
        *rdam = saved_am;
        TDE_IMPERSONATE_EXIT();
        PG_RE_THROW();
    }
    PG_END_TRY();

    *rdam = saved_am;
    TDE_IMPERSONATE_EXIT();
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
#ifdef USE_ASSERT_CHECKING
    /* Fires at the end of the very transaction that leaked an impersonation. */
    RegisterXactCallback(tde_impersonation_xact_check, NULL);
#endif

    const TableAmRoutine *heapam = GetHeapamTableAmRoutine();
    memcpy(&tde_methods, heapam, sizeof(TableAmRoutine));
    /* --- Save originals for every read path we wrap --- */
    heapam_scan_getnextslot_cb              = heapam->scan_getnextslot;
    heapam_scan_getnextslot_tidrange_cb     = heapam->scan_getnextslot_tidrange;
    heapam_index_fetch_tuple_cb             = heapam->index_fetch_tuple;
    heapam_scan_bitmap_next_tuple_cb        = heapam->scan_bitmap_next_tuple;
    heapam_scan_analyze_next_tuple_cb       = heapam->scan_analyze_next_tuple;
    heapam_scan_sample_next_tuple_cb        = heapam->scan_sample_next_tuple;
    heapam_tuple_fetch_row_version_cb       = heapam->tuple_fetch_row_version;
    heapam_tuple_lock_cb                    = heapam->tuple_lock;
    heapam_tuple_satisfies_snapshot_cb      = heapam->tuple_satisfies_snapshot;
    heapam_tuple_delete_cb                  = heapam->tuple_delete;
    heapam_tuple_complete_speculative_cb    = heapam->tuple_complete_speculative;
    /* --- Install encrypt/decrypt wrappers --- */
    /* Slot type: always buffer-backed (needed for decode_slot cast) */
    tde_methods.slot_callbacks              = pg_vault_tde_slot_callbacks;
    /* Write paths: encrypt before calling heapam storage layer */
    tde_methods.tuple_insert                = pg_vault_tde_tuple_insert;
    tde_methods.tuple_insert_speculative    = pg_vault_tde_tuple_insert_speculative;
    tde_methods.tuple_complete_speculative  = pg_vault_tde_tuple_complete_speculative;
    tde_methods.multi_insert                = pg_vault_tde_multi_insert;
    tde_methods.tuple_update                = pg_vault_tde_tuple_update;
    tde_methods.tuple_delete                = pg_vault_tde_tuple_delete;
    /* Read paths: delegate to heapam then decrypt the returned slot */
    tde_methods.scan_getnextslot            = pg_vault_tde_scan_getnextslot;
    tde_methods.scan_getnextslot_tidrange   = pg_vault_tde_scan_getnextslot_tidrange;
    tde_methods.index_fetch_tuple           = pg_vault_tde_index_fetch_tuple;
    tde_methods.scan_bitmap_next_tuple      = pg_vault_tde_scan_bitmap_next_tuple;
    tde_methods.scan_analyze_next_tuple     = pg_vault_tde_scan_analyze_next_tuple;
    tde_methods.scan_sample_next_tuple      = pg_vault_tde_scan_sample_next_tuple;
    tde_methods.tuple_fetch_row_version     = pg_vault_tde_tuple_fetch_row_version;
    tde_methods.tuple_lock                  = pg_vault_tde_tuple_lock;
    /* Visibility recheck (RI FK triggers): tolerate decrypted, unpinned slots */
    tde_methods.tuple_satisfies_snapshot    = pg_vault_tde_tuple_satisfies_snapshot;
    /* Index build: bypass rd_tableam identity check inside heap_getnext */
    tde_methods.index_validate_scan         = pg_vault_tde_index_validate_scan;
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
    /* All other callbacks (scan_begin/end/rescan,
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
 *      writes new tuples (encrypted with current DEK) and new TOAST
 *      chunks for their out-of-line values, and
 *      rebuilds any tde_btree indexes (SIV keys are DEK-bound)
 *   3. KMS provider wipes prev_dek after re-encryption completes
 *
 * Why tde_btree indexes must be rebuilt:
 *   AES-256-SIV is deterministic under a fixed DEK: same plaintext + same DEK
 *   → same ciphertext.  After DEK rotation the SIV ciphertexts stored in
 *   the index no longer match what aminsert would produce with the new DEK,
 *   so equality lookups silently return empty results.  REINDEX re-encrypts
 *   every key datum with the current DEK, restoring correctness.
 *   Every other index gets an entry for each new row version as the rows are
 *   rewritten, as an UPDATE's would (PSQLE-194).
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

/*
 * tde_fetch_back_external — src's row in dst, with out-of-line values fetched
 * back from the TOAST relation (still compressed, if they were).
 *
 * Handed the scanned row as it is, tuple_update()'s pre-TOAST sees each
 * external pointer unchanged and reuses it: the row is re-encrypted, its
 * TOAST chunks keep the old DEK, and once that key has left the cache the
 * values are unreadable (PSQLE-189).  A fetched-back value differs from the
 * old pointer, so toast_tuple_init() stores it again under the current key
 * and pg_vault_tde_tuple_update() deletes the old chunks.  Dropped columns
 * become NULL, as in any UPDATE, and their chunks are deleted with the rest:
 * fetching them back would follow pointers that a VACUUM FULL up to 1.7.1
 * left dangling (PSQLE-192).  Allocates in cxt.
 */
static void
tde_fetch_back_external(TupleTableSlot *src, TupleTableSlot *dst,
                        MemoryContext cxt)
{
    TupleDesc     desc = src->tts_tupleDescriptor;
    MemoryContext oldcxt = MemoryContextSwitchTo(cxt);

    slot_getallattrs(src);
    ExecClearTuple(dst);

    Assert(dst->tts_tupleDescriptor->natts == desc->natts);

    for (int i = 0; i < desc->natts; i++)
    {
        Form_pg_attribute att = TupleDescAttr(desc, i);
        Datum             value = src->tts_values[i];
        bool              isnull = src->tts_isnull[i] || att->attisdropped;

        if (!isnull && att->attlen == -1 &&
            VARATT_IS_EXTERNAL_ONDISK(DatumGetPointer(value)))
            value = PointerGetDatum(
                detoast_external_attr((struct varlena *) DatumGetPointer(value)));

        dst->tts_values[i] = isnull ? (Datum) 0 : value;
        dst->tts_isnull[i] = isnull;
    }

    ExecStoreVirtualTuple(dst);
    MemoryContextSwitchTo(oldcxt);
}

int64 pg_vault_tde_reencrypt_table(Oid relid)
{    
    Relation rel;
    TableScanDesc       scan;
    TupleTableSlot     *slot;
    TupleTableSlot     *upd_slot = NULL;
    MemoryContext       row_cxt = NULL;
    EState             *estate = NULL;
    ResultRelInfo      *rri = NULL;
    CommandId           cid;
    TU_UpdateIndexes    update_idxs;
    LockTupleMode       lock_mode;
    List               *tde_index_oids = NIL;
    Oid                 tde_btree_amoid;
    int64               tuples_done = 0;

    rel = table_open(relid, RowExclusiveLock);
    slot = table_slot_create(rel, NULL);

    /* Out-of-line values are rewritten too; see tde_fetch_back_external(). */
    if (OidIsValid(rel->rd_rel->reltoastrelid))
    {
        upd_slot = MakeSingleTupleTableSlot(RelationGetDescr(rel), &TTSOpsVirtual);
        row_cxt = AllocSetContextCreate(CurrentMemoryContext,
                                        "pg_vault_tde reencrypt row",
                                        ALLOCSET_DEFAULT_SIZES);
    }

    /*
     * Index entries for the new versions.  tuple_update() is heap_update()
     * underneath, which leaves that to its caller: a rewrite that cannot stay
     * HOT puts the new version on another page, and without an entry every
     * index but the tde_btree ones rebuilt below keeps pointing at the
     * retired version only — no index scan finds the row, and PRIMARY KEY
     * and UNIQUE stop holding (PSQLE-194).  Inserted as the executor's UPDATE
     * does, so partial and expression indexes and uniqueness behave alike.
     */
    if (rel->rd_rel->relhasindex)
    {
        estate = CreateExecutorState();
        rri = makeNode(ResultRelInfo);
        InitResultRelInfo(rri, rel, 0, NULL, 0);
        ExecOpenIndices(rri, false);
    }

    cid = GetCurrentCommandId(true);
    lock_mode = LockTupleExclusive;

    scan = table_beginscan(rel, GetActiveSnapshot(), 0, NULL);

    while (table_scan_getnextslot(scan, ForwardScanDirection, slot))
    {
        ItemPointerData otid = slot->tts_tid;
        TM_FailureData  tmfd;
        TM_Result       result;

        CHECK_FOR_INTERRUPTS();

        if (upd_slot)
            tde_fetch_back_external(slot, upd_slot, row_cxt);

        result = pg_vault_tde_tuple_update(rel,
                                           &otid,
                                           upd_slot ? upd_slot : slot,
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

        /*
         * tuple_update() left the new TID in the slot it was given.  Not an
         * UPDATE for the "index unchanged" hint: that needs a range table this
         * call does not have, and it only steers bottom-up deletion.
         */
        if (rri != NULL && update_idxs != TU_None)
        {
            MemoryContext oldcxt = MemoryContextSwitchTo(GetPerTupleMemoryContext(estate));

            (void) ExecInsertIndexTuples(rri, upd_slot ? upd_slot : slot, estate,
                                         false, false, NULL, NIL,
                                         update_idxs == TU_Summarizing);
            MemoryContextSwitchTo(oldcxt);
            ResetPerTupleExprContext(estate);
        }

        if (upd_slot)
        {
            ExecClearTuple(upd_slot);
            MemoryContextReset(row_cxt);
        }
    }

    /*
     * Collect OIDs of tde_btree indexes before releasing the relation.
     * We must rebuild them because AES-256-SIV key material is DEK-bound:
     * after rotation the stored ciphertexts no longer match lookups under
     * the new DEK.  Every other index got its entries in the loop above.
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
    if (upd_slot)
    {
        ExecDropSingleTupleTableSlot(upd_slot);
        MemoryContextDelete(row_cxt);
    }
    if (rri != NULL)
    {
        ExecCloseIndices(rri);
        FreeExecutorState(estate);
    }
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
 * tde_value_fetches — whether one on-disk out-of-line value can be fetched:
 * every chunk present and decrypting.
 *
 * In its own subtransaction: an error halfway through a TOAST read leaves
 * buffer pins and locks behind that only an abort releases.  Allocates in
 * CurrentMemoryContext, which the caller resets.
 */
static bool
tde_value_fetches(Datum value)
{
    MemoryContext   cxt = CurrentMemoryContext;
    ResourceOwner   owner = CurrentResourceOwner;
    volatile bool   ok = true;

    BeginInternalSubTransaction(NULL);
    MemoryContextSwitchTo(cxt);

    PG_TRY();
    {
        (void) detoast_external_attr((struct varlena *) DatumGetPointer(value));
        ReleaseCurrentSubTransaction();
    }
    PG_CATCH();
    {
        MemoryContextSwitchTo(cxt);
        FlushErrorState();
        RollbackAndReleaseCurrentSubTransaction();
        ok = false;
    }
    PG_END_TRY();

    MemoryContextSwitchTo(cxt);
    CurrentResourceOwner = owner;
    return ok;
}

/*
 * tde_row_toast_readable — whether every out-of-line value of the decrypted
 * row plain can be fetched.  Dropped columns are skipped: nothing reads them,
 * and a VACUUM FULL up to 1.7.1 may have left their pointers dangling
 * (PSQLE-192).  Allocates in cxt, which the caller resets.
 */
static bool
tde_row_toast_readable(HeapTuple plain, TupleDesc desc, MemoryContext cxt)
{
    MemoryContext oldcxt = MemoryContextSwitchTo(cxt);
    Datum        *values = palloc(desc->natts * sizeof(Datum));
    bool         *isnull = palloc(desc->natts * sizeof(bool));
    bool          ok = true;

    heap_deform_tuple(plain, desc, values, isnull);

    for (int i = 0; i < desc->natts && ok; i++)
    {
        Form_pg_attribute att = TupleDescAttr(desc, i);

        if (!isnull[i] && !att->attisdropped && att->attlen == -1 &&
            VARATT_IS_EXTERNAL_ONDISK(DatumGetPointer(values[i])))
            ok = tde_value_fetches(values[i]);
    }

    MemoryContextSwitchTo(oldcxt);
    return ok;
}

/*
 * pg_vault_tde_verify_integrity(regclass)
 *   → (total_tuples bigint, failed_tuples bigint)
 *
 * Scans all live tuples in a raw heapam scan (bypassing TAM decrypt) and
 * manually attempts GCM decryption on each.  Catches per-tuple failures
 * via PG_TRY/PG_CATCH so a single corrupted row does not abort the scan.
 *
 * A row also fails when one of its out-of-line values cannot be fetched —
 * a missing chunk, or one that does not decrypt: the row's own tag says
 * nothing about its TOAST chunks (PSQLE-196).  That reads every out-of-line
 * value of the table.
 *
 * Returns a composite with the total tuple count and the number of rows that
 * failed either check; the total stays a row count.
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
    MemoryContext volatile toast_cxt = NULL;
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
    if (OidIsValid(rel->rd_rel->reltoastrelid))
        toast_cxt = AllocSetContextCreate(CurrentMemoryContext,
                                          "pg_vault_tde verify toast",
                                          ALLOCSET_DEFAULT_SIZES);
    /*
     * Swap rd_tableam to heapam so the scan returns raw encrypted tuples
     * without triggering our decrypt-on-read wrappers.
     */
    saved_am = rel->rd_tableam;
    {
        const TableAmRoutine **rdam = (const TableAmRoutine **)(void *)&rel->rd_tableam;
        TDE_IMPERSONATE_ENTER();
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
                                                          RelationGetRelid(rel),
                                                          RelationGetDescr(rel));

                if (toast_cxt != NULL)
                {
                    if (!tde_row_toast_readable(plain, RelationGetDescr(rel), toast_cxt))
                        failed++;
                    MemoryContextReset(toast_cxt);
                }
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
        TDE_IMPERSONATE_EXIT();
        PG_RE_THROW();
    }
    PG_END_TRY();
    {
        const TableAmRoutine **rdam = (const TableAmRoutine **)(void *)&rel->rd_tableam;
        *rdam = saved_am;
        TDE_IMPERSONATE_EXIT();
    }
    table_close(rel, AccessShareLock);
    if (toast_cxt != NULL)
        MemoryContextDelete(toast_cxt);
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
 * Uses direct api to count live rows (which also validates readability).
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_encrypted_size);
PGDLLEXPORT Datum
pg_vault_tde_encrypted_size(PG_FUNCTION_ARGS)
{
    Oid             relid = PG_GETARG_OID(0);
    char           *relname;
    Relation        rel;
    TupleTableSlot *slot;
    TableScanDesc   scan;
    int64           total = 0;
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

    rel = table_open(relid, AccessShareLock);
    slot = table_slot_create(rel, NULL);
    scan = table_beginscan(rel, GetActiveSnapshot(), 0, NULL);

    while (table_scan_getnextslot(scan, ForwardScanDirection, slot))
        total++;

    table_endscan(scan);
    ExecDropSingleTupleTableSlot(slot);
    table_close(rel, AccessShareLock);

    /* Each encrypted tuple carries TDE_V4_OVERHEAD bytes of overhead. */
    values[0] = Int64GetDatum(total);
    values[1] = Int64GetDatum(total * (int64) TDE_V4_OVERHEAD);
    result_tup = heap_form_tuple(tupdesc, values, nulls);
    PG_RETURN_DATUM(HeapTupleGetDatum(result_tup));
}
