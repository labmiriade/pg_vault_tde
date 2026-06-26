/*
 * pg_vault_tde_pgoutput.c — Logical decoding output plugin (pgoutput wrapper).
 *
 * The WAL sender reads raw WAL records whose tuple bodies are ciphertext for
 * encrypted_heap tables (the TAM decrypt-on-read callbacks are NOT invoked in
 * the logical decoding path).  Without intervention, a subscriber receives
 * garbage.
 *
 * Approach — wrap the built-in pgoutput (same technique Citus uses for its CDC
 * decoder, see citus src/backend/distributed/cdc/cdc_decoder.c):
 *   1. _PG_output_plugin_init loads pgoutput via load_external_function() and
 *      lets it populate ALL callbacks (startup/begin/commit/change/truncate/
 *      stream_*).  This gives us pgoutput's exact wire protocol and option
 *      handling (proto_version, publication_names, output_type, ...).
 *   2. We save pgoutput's change_cb / stream_change_cb and override them with
 *      thin wrappers that DECRYPT the tuple in place (via tde_decrypt_heap_tuple)
 *      and then DELEGATE to the saved pgoutput callback, which deforms the
 *      now-plaintext tuple and serializes it normally.
 *   3. All other callbacks remain pgoutput's untouched.
 *
 * Because we emit the exact pgoutput protocol, this works both with the manual
 * CDC interface (pg_recvlogical / pg_logical_slot_get_*_changes) and, when the
 * subscription is pointed at a slot created with this plugin, with native
 * CREATE SUBSCRIPTION.
 *
 * The plugin lives in the SAME shared library as the main extension
 * (pg_vault_tde.so), so it shares the shmem DEK cache and crypto primitives.
 *
 * TOAST columns:
 *   - Supported when pg_vault_tde.toast_custom_rmgr is enabled.  The encrypted
 *     chunks are WAL-logged under the custom rmgr (pg_vault_tde_rmgr.c) and so
 *     bypass the reorder buffer's toast_hash; rm_decode captures them and
 *     tde_toast_stitch() (called from our change wrappers) reconstructs the
 *     plaintext value into the decrypted main tuple before pgoutput serializes.
 *   - With the GUC off, externally-TOASTed columns are NOT supported:
 *     ReorderBufferToastReplace() heap_deform's the still-encrypted tuple
 *     BEFORE any output-plugin callback runs, so it garbles/crashes before we
 *     get control.  There is no extension hook earlier than this.
 *
 * UPDATE / DELETE require the table to have a primary key and REPLICA IDENTITY
 * FULL: with DEFAULT, the core extracts the replica identity from the encrypted
 * tuple (reading ciphertext as if it were the key) before any hook runs.  See
 * doc/logical_decoding_research.md.
 *
 * PG17 / PG18: the logical decoding output-plugin API is identical here, so no
 * version guards are needed in this file.
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */

#include "postgres.h"

#include "access/tableam.h"         /* relation->rd_rel->relam */
#include "catalog/pg_am.h"
#include "commands/defrem.h"        /* get_table_am_oid */
#include "fmgr.h"                   /* load_external_function */
#include "replication/logical.h"    /* LogicalDecodingContext */
#include "replication/output_plugin.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"

#include "src/include/pg_vault_tde_tam.h"     /* tde_decrypt_heap_tuple */
#include "src/include/pg_vault_tde_crypto.h"  /* TDE_V2_OVERHEAD, version bytes */
#include "src/include/pg_vault_tde_rmgr.h"    /* tde_toast_stitch / store_reset */

/*
 * Cached OID of the encrypted_heap access method (resolved lazily on first use).
 */
static Oid encrypted_heap_am_oid = InvalidOid;

/*
 * pgoutput's original callbacks, saved at init time.  Our wrappers decrypt /
 * stitch / clean up and then delegate to these for the actual protocol
 * serialization.
 */
static LogicalDecodeChangeCB        pgoutput_change_cb = NULL;
static LogicalDecodeStreamChangeCB  pgoutput_stream_change_cb = NULL;
static LogicalDecodeCommitCB        pgoutput_commit_cb = NULL;
static LogicalDecodeStreamCommitCB  pgoutput_stream_commit_cb = NULL;
static LogicalDecodeStreamAbortCB   pgoutput_stream_abort_cb = NULL;

/* Forward declarations */
static void tde_output_change_cb(LogicalDecodingContext *ctx,
                                 ReorderBufferTXN *txn,
                                 Relation relation,
                                 ReorderBufferChange *change);
static void tde_output_stream_change_cb(LogicalDecodingContext *ctx,
                                        ReorderBufferTXN *txn,
                                        Relation relation,
                                        ReorderBufferChange *change);
static void tde_output_commit_cb(LogicalDecodingContext *ctx,
                                 ReorderBufferTXN *txn,
                                 XLogRecPtr commit_lsn);
static void tde_output_stream_commit_cb(LogicalDecodingContext *ctx,
                                        ReorderBufferTXN *txn,
                                        XLogRecPtr commit_lsn);
static void tde_output_stream_abort_cb(LogicalDecodingContext *ctx,
                                       ReorderBufferTXN *txn,
                                       XLogRecPtr abort_lsn);

/*
 * tde_tuple_looks_encrypted — defensive check before attempting to decrypt.
 *
 * In logical decoding we receive two kinds of tuples for an encrypted_heap
 * relation:
 *   - full tuples (INSERT/UPDATE newtuple, or the old tuple under
 *     REPLICA IDENTITY FULL): the user-data region IS our wire format
 *     [VER(1)|GEN(8)|IV(12)|CT|TAG(16)], >= TDE_V2_OVERHEAD bytes.
 *   - the REPLICA IDENTITY DEFAULT old tuple: only the key column(s), e.g. a
 *     4-byte int4 key.  This is NOT in our wire format; blindly decrypting it
 *     errors ("encrypted tuple too short") or reads out of bounds.
 *
 * We only decrypt tuples that are plausibly in our format: at least
 * TDE_V2_OVERHEAD bytes of user data AND a recognized version byte (0x02/0x03).
 * Anything else is passed through untouched.
 */
static bool
tde_tuple_looks_encrypted(HeapTuple tup)
{
    Size            hdr_len;
    Size            data_len;
    unsigned char   ver;

    if (tup == NULL || tup->t_data == NULL)
        return false;

    hdr_len = tup->t_data->t_hoff;
    if (tup->t_len <= hdr_len)
        return false;

    data_len = tup->t_len - hdr_len;
    if (data_len < (Size) TDE_V2_OVERHEAD)
        return false;           /* too short to be a v2/v3 encrypted region */

    ver = *((unsigned char *) tup->t_data + hdr_len);
    return (ver == TDE_V2_VERSION_BYTE || ver == TDE_V3_VERSION_BYTE);
}

/*
 * tde_maybe_decrypt — decrypt a change tuple if it is in our wire format.
 *
 * Returns `tup` with its content decrypted IN PLACE (same pointer), or the
 * tuple unchanged when it is not one of ours (e.g. a replica-identity key).
 */
static HeapTuple
tde_maybe_decrypt(HeapTuple tup, Oid relid, const char *which)
{
    HeapTuple plain;

    if (!tde_tuple_looks_encrypted(tup))
    {
        ereport(DEBUG1,
                (errmsg("pg_vault_tde: logical decoding: %s tuple not in "
                        "encrypted format (t_len=%u) — passing through",
                        which, tup ? tup->t_len : 0)));
        return tup;             /* leave as-is */
    }

    /*
     * Decrypt into a temporary tuple, then copy the plaintext content BACK
     * into the reorder buffer's own tuple buffer (`tup`), keeping the same
     * pointer.  The reorder buffer allocated `tup` from its tup_context and
     * frees it later (ReorderBufferFreeChange -> pfree) OUTSIDE this callback's
     * memory context; replacing the pointer with a CurrentMemoryContext tuple
     * would make that later pfree hit freed memory (intermittent
     * "pfree invalid pointer" / segfault under streaming).  The decrypted
     * content is always <= the encrypted content (shorter by TDE_V2_OVERHEAD),
     * so it always fits.  Mirrors core's ReorderBufferToastReplace() copy-back.
     */
    plain = tde_decrypt_heap_tuple(tup, relid);
    Assert(plain->t_len <= tup->t_len);
    memcpy(tup->t_data, plain->t_data, plain->t_len);
    tup->t_len = plain->t_len;
    pfree(plain);
    return tup;
}

/*
 * tde_decrypt_change — decrypt the tuple(s) in a change record in place.
 *
 * Only acts on encrypted_heap relations (detected via relam OID); everything
 * else is left untouched so non-encrypted tables pass straight through to
 * pgoutput.  The per-table DEK is selected by the source relation OID.
 */
static void
tde_decrypt_change(Relation relation, ReorderBufferChange *change,
                   TransactionId xid)
{
    Oid src_relid;

    if (!OidIsValid(encrypted_heap_am_oid))
    {
        encrypted_heap_am_oid = get_table_am_oid("encrypted_heap", true);
        if (!OidIsValid(encrypted_heap_am_oid))
            return;             /* extension AM not registered — nothing to do */
    }

    if (relation->rd_rel->relam != encrypted_heap_am_oid)
        return;                 /* not an encrypted table */

    src_relid = RelationGetRelid(relation);

    switch (change->action)
    {
        case REORDER_BUFFER_CHANGE_INSERT:
            if (change->data.tp.newtuple != NULL)
            {
                change->data.tp.newtuple =
                    tde_maybe_decrypt(change->data.tp.newtuple, src_relid, "new");
                /* splice plaintext TOAST values back into the tuple */
                tde_toast_stitch(relation, change, xid);
            }
            break;

        case REORDER_BUFFER_CHANGE_UPDATE:
            if (change->data.tp.newtuple != NULL)
            {
                change->data.tp.newtuple =
                    tde_maybe_decrypt(change->data.tp.newtuple, src_relid, "new");
                tde_toast_stitch(relation, change, xid);
            }
            if (change->data.tp.oldtuple != NULL)
                change->data.tp.oldtuple =
                    tde_maybe_decrypt(change->data.tp.oldtuple, src_relid, "old");
            break;

        case REORDER_BUFFER_CHANGE_DELETE:
            if (change->data.tp.oldtuple != NULL)
                change->data.tp.oldtuple =
                    tde_maybe_decrypt(change->data.tp.oldtuple, src_relid, "old");
            break;

        default:
            /* Other change types carry no encrypted tuple data */
            break;
    }
}

/*
 * tde_output_change_cb — decrypt (+ stitch TOAST) then delegate to pgoutput.
 */
static void
tde_output_change_cb(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                     Relation relation, ReorderBufferChange *change)
{
    tde_decrypt_change(relation, change, txn->xid);

    if (pgoutput_change_cb != NULL)
        pgoutput_change_cb(ctx, txn, relation, change);

    /* pgoutput has serialized the row; free any reconstructed TOAST values */
    tde_toast_stitch_reset();
}

/*
 * tde_output_stream_change_cb — same as above for streamed in-progress txns.
 */
static void
tde_output_stream_change_cb(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                            Relation relation, ReorderBufferChange *change)
{
    tde_decrypt_change(relation, change, txn->xid);

    if (pgoutput_stream_change_cb != NULL)
        pgoutput_stream_change_cb(ctx, txn, relation, change);

    /* pgoutput has serialized the row; free any reconstructed TOAST values */
    tde_toast_stitch_reset();
}

/*
 * Commit / abort wrappers: delegate to pgoutput, then free the transaction's
 * captured TOAST chunks (tde_toast_store_reset).  These three callbacks cover
 * every txn that produces output, so committed and streamed-then-aborted txns
 * are always reclaimed promptly.
 *
 * KNOWN LIMITATION: a txn that wrote TOAST under our rmgr, reached a full
 * snapshot (so rm_decode captured its chunks), and then aborted WITHOUT being
 * streamed never reaches any output callback — core discards it via
 * ReorderBufferAbort()/ReorderBufferCleanupTXN(), which we cannot hook from an
 * output plugin.  Its captured chunks therefore stay in the capture context
 * until the decoding process exits.  This is a slow leak proportional to the
 * number of such aborted toast-writing txns, not a per-row leak; documented as
 * a structural limit of the custom-rmgr approach (see doc/).
 */
static void
tde_output_commit_cb(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                     XLogRecPtr commit_lsn)
{
    if (pgoutput_commit_cb != NULL)
        pgoutput_commit_cb(ctx, txn, commit_lsn);
    tde_toast_store_reset(txn->xid);
}

static void
tde_output_stream_commit_cb(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                            XLogRecPtr commit_lsn)
{
    if (pgoutput_stream_commit_cb != NULL)
        pgoutput_stream_commit_cb(ctx, txn, commit_lsn);
    tde_toast_store_reset(txn->xid);
}

static void
tde_output_stream_abort_cb(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                           XLogRecPtr abort_lsn)
{
    if (pgoutput_stream_abort_cb != NULL)
        pgoutput_stream_abort_cb(ctx, txn, abort_lsn);
    tde_toast_store_reset(txn->xid);
}

/*
 * _PG_output_plugin_init — entry point for the logical decoding infrastructure.
 *
 * Loads the built-in pgoutput, lets it fill all callbacks, then wraps the
 * change callbacks so we decrypt before pgoutput serializes.
 */
void
_PG_output_plugin_init(OutputPluginCallbacks *cb)
{
    LogicalOutputPluginInit pgoutput_init;

    AssertVariableIsOfType(&_PG_output_plugin_init, LogicalOutputPluginInit);

    /* Load pgoutput and let it populate every callback + option handling. */
    pgoutput_init = (LogicalOutputPluginInit) (void *)
        load_external_function("pgoutput", "_PG_output_plugin_init", true, NULL);
    pgoutput_init(cb);

    /* Wrap change_cb: decrypt in place, then delegate to pgoutput. */
    pgoutput_change_cb = cb->change_cb;
    cb->change_cb = tde_output_change_cb;

    /* Same for the streaming path, if pgoutput provides it. */
    pgoutput_stream_change_cb = cb->stream_change_cb;
    if (pgoutput_stream_change_cb != NULL)
        cb->stream_change_cb = tde_output_stream_change_cb;

    /*
     * Wrap commit / stream-commit / stream-abort so we can free a
     * transaction's captured TOAST chunks once it is fully processed.
     * We still delegate to pgoutput first, so the wire format is unchanged.
     */
    pgoutput_commit_cb = cb->commit_cb;
    cb->commit_cb = tde_output_commit_cb;

    pgoutput_stream_commit_cb = cb->stream_commit_cb;
    if (pgoutput_stream_commit_cb != NULL)
        cb->stream_commit_cb = tde_output_stream_commit_cb;

    pgoutput_stream_abort_cb = cb->stream_abort_cb;
    if (pgoutput_stream_abort_cb != NULL)
        cb->stream_abort_cb = tde_output_stream_abort_cb;

    /*
     * startup_cb, begin_cb, truncate_cb, and the remaining stream_* callbacks
     * stay pgoutput's untouched — so the emitted wire format is exactly the
     * pgoutput protocol the subscriber expects.
     */
}
