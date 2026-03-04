/*
 * pg_vault_tde_pgoutput.c — Logical decoding output plugin (v1.2)
 *
 * Intercepts the change_cb callback to decrypt ciphertext tuples from WAL
 * before they are sent to logical replication subscribers.  Without this
 * plugin, subscribers receive raw ciphertext because the WAL sender reads
 * pages directly (bypassing the TAM decrypt-on-read callbacks).
 *
 * Architecture:
 *   - _PG_output_plugin_init() is the standard entry point discovered by
 *     the logical replication infrastructure when CREATE PUBLICATION
 *     uses this plugin.
 *   - begin_cb / commit_cb are pass-through (no-op).
 *   - change_cb detects encrypted_heap relations via relam OID and
 *     decrypts newtuple / oldtuple in-place using tde_decrypt_heap_tuple().
 *   - The output plugin lives in the SAME shared library as the main
 *     extension (pg_vault_tde.so), so it shares the shmem DEK cache
 *     and all crypto primitives — no separate .so needed.
 *
 * Limitations:
 *   - Tables with TOAST columns: ReorderBufferToastReplace() calls
 *     heap_deform_tuple() BEFORE the output plugin sees the tuple.
 *     Because the tuple user data is still encrypted at that point,
 *     heap_deform_tuple() produces garbage and may crash.
 *     THEREFORE: only tables WITHOUT externally-toasted columns are
 *     supported for logical decoding.  This is a documented v1.2
 *     limitation.
 *   - PG17/PG18: the logical decoding API is IDENTICAL — no version
 *     guards are required.
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */

#include "postgres.h"

#include "access/tableam.h"         /* relation->rd_rel->relam */
#include "catalog/pg_am.h"          /* get_am_oid */
#include "commands/defrem.h"        /* get_table_am_oid */
#include "replication/logical.h"    /* LogicalDecodingContext */
#include "replication/output_plugin.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"

#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_crypto.h"

#include <openssl/crypto.h>         /* OPENSSL_cleanse */

/*
 * Cached OID of the encrypted_heap access method.
 * Looked up once on first change_cb invocation to avoid repeated catalog hits.
 */
static Oid   encrypted_heap_am_oid = InvalidOid;

/* Forward declarations */
static void tde_output_begin_cb(LogicalDecodingContext *ctx,
                                ReorderBufferTXN *txn);
static void tde_output_commit_cb(LogicalDecodingContext *ctx,
                                 ReorderBufferTXN *txn,
                                 XLogRecPtr commit_lsn);
static void tde_output_change_cb(LogicalDecodingContext *ctx,
                                 ReorderBufferTXN *txn,
                                 Relation relation,
                                 ReorderBufferChange *change);

/*
 * _PG_output_plugin_init — standard entry point for output plugins.
 *
 * Multiple _PG_xxx_init functions can coexist in the same .so file:
 * _PG_init is for shared_preload_libraries, _PG_output_plugin_init
 * is for the logical decoding infrastructure.  PostgreSQL calls the
 * correct one based on context.
 */
void
_PG_output_plugin_init(OutputPluginCallbacks *cb)
{
    AssertVariableIsOfType(&_PG_output_plugin_init, LogicalOutputPluginInit);

    cb->begin_cb  = tde_output_begin_cb;
    cb->commit_cb = tde_output_commit_cb;
    cb->change_cb = tde_output_change_cb;
}

/*
 * tde_output_begin_cb — begin transaction callback (no-op).
 *
 * We don't need per-transaction state for decryption.  The DEK is
 * fetched from shmem on each decrypt call automatically.
 */
static void
tde_output_begin_cb(LogicalDecodingContext *ctx, ReorderBufferTXN *txn)
{
    /* nothing to do */
}

/*
 * tde_output_commit_cb — commit transaction callback (no-op).
 */
static void
tde_output_commit_cb(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                     XLogRecPtr commit_lsn)
{
    /* nothing to do */
}

/*
 * tde_output_change_cb — per-row change callback.
 *
 * Checks whether the relation uses encrypted_heap AM.  If so, decrypts
 * newtuple and/or oldtuple before the downstream output plugin (pgoutput)
 * serializes them to the wire protocol.
 *
 * Critical invariant: the HeapTupleData inside ReorderBufferTupleBuf is
 * the actual tuple that downstream will read.  We replace its contents
 * with decrypted data.
 */
static void
tde_output_change_cb(LogicalDecodingContext *ctx,
                     ReorderBufferTXN *txn,
                     Relation relation,
                     ReorderBufferChange *change)
{
    bool        is_encrypted;

    /*
     * Cache the encrypted_heap AM OID on first call.
     * get_table_am_oid returns InvalidOid if the AM doesn't exist,
     * which means the extension isn't installed (shouldn't happen if
     * we're loaded via shared_preload_libraries).
     */
    if (!OidIsValid(encrypted_heap_am_oid))
    {
        encrypted_heap_am_oid = get_table_am_oid("encrypted_heap", true);
        if (!OidIsValid(encrypted_heap_am_oid))
            return;     /* AM not registered — pass through unchanged */
    }

    /* Check if this relation uses our encrypted AM */
    is_encrypted = (relation->rd_rel->relam == encrypted_heap_am_oid);

    if (!is_encrypted)
        return;     /* Not an encrypted table — nothing to do */

    /*
     * Decrypt tuples in the change record.
     *
     * In PG17+, change->data.tp.newtuple / oldtuple are HeapTuple pointers.
     * We decrypt and replace the pointer so downstream consumers see
     * plaintext data.
     */
    {
        /*
         * Per-table DEK (v1.5): pass the source relation OID so the crypto
         * layer can select the correct DEK from the per-table cache.
         */
        Oid src_relid = RelationGetRelid(relation);

        switch (change->action)
        {
            case REORDER_BUFFER_CHANGE_INSERT:
                if (change->data.tp.newtuple != NULL)
                {
                    HeapTuple plain = tde_decrypt_heap_tuple(change->data.tp.newtuple,
                                                             src_relid);
                    pfree(change->data.tp.newtuple);
                    change->data.tp.newtuple = plain;
                }
                break;

            case REORDER_BUFFER_CHANGE_UPDATE:
                if (change->data.tp.newtuple != NULL)
                {
                    HeapTuple plain = tde_decrypt_heap_tuple(change->data.tp.newtuple,
                                                             src_relid);
                    pfree(change->data.tp.newtuple);
                    change->data.tp.newtuple = plain;
                }
                if (change->data.tp.oldtuple != NULL)
                {
                    HeapTuple plain = tde_decrypt_heap_tuple(change->data.tp.oldtuple,
                                                             src_relid);
                    pfree(change->data.tp.oldtuple);
                    change->data.tp.oldtuple = plain;
                }
                break;

            case REORDER_BUFFER_CHANGE_DELETE:
                if (change->data.tp.oldtuple != NULL)
                {
                    HeapTuple plain = tde_decrypt_heap_tuple(change->data.tp.oldtuple,
                                                             src_relid);
                    pfree(change->data.tp.oldtuple);
                    change->data.tp.oldtuple = plain;
                }
                break;

            default:
                /* Other change types (e.g., TRUNCATE) — nothing to decrypt */
                break;
        }
    }
}
