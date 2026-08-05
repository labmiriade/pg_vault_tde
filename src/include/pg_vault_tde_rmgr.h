/*
 * pg_vault_tde_rmgr.h — Custom WAL resource manager for encrypted TOAST chunks.
 *
 * On encrypted_heap tables the user-data region of every tuple is ciphertext,
 * and the TOAST pointer of an externally-stored value lives INSIDE that
 * ciphertext.  In logical decoding the core reorder buffer reassembles TOAST
 * values by heap_deform_tuple()'ing the chunks and the main tuple (still
 * encrypted) — which produces garbage and crashes ("got sequence entry ... for
 * toast chunk").  There is no extension hook before that point.
 *
 * The lever that does exist is a custom WAL resource manager.  When the GUC
 * pg_vault_tde.toast_custom_rmgr is on, the encrypted TOAST chunks of
 * encrypted_heap relations are WAL-logged under TDE_RMGR_ID instead of
 * RM_HEAP_ID, so that:
 *
 *   - crash recovery still works: rm_redo delegates to heap_redo() (the record
 *     payload is the standard xl_heap_insert format; heap_redo dispatches on
 *     the info bits, not on the rmid);
 *
 *   - logical decoding routes those records to tde_rmgr's rm_decode instead of
 *     heap_decode, so the chunks never enter the reorder buffer's toast_hash
 *     and ReorderBufferToastReplace() does not deform the still-encrypted main
 *     tuple.  rm_decode captures the encrypted chunks per-transaction; the
 *     output plugin stitches the decrypted value back into the (decrypted)
 *     main tuple at change_cb time (see tde_toast_stitch).
 *
 * Activation requires the rmgr to be registered at preload time, hence the GUC
 * is PGC_POSTMASTER and pg_vault_tde must be in shared_preload_libraries.
 *
 * Copyright (c) 2026 Miriade S.r.l.  Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_RMGR_H
#define PG_VAULT_TDE_RMGR_H

#include "access/heapam.h"      /* BulkInsertState, HeapTuple */
#include "access/rmgr.h"        /* RM_EXPERIMENTAL_ID */
#include "replication/reorderbuffer.h"  /* ReorderBufferChange */
#include "utils/rel.h"          /* Relation */

/*
 * Custom resource manager id.
 *
 * RM_EXPERIMENTAL_ID (128) is the first id of the custom-rmgr range
 * (RM_CUSTOM_MIN_ID 128 .. RM_CUSTOM_MAX_ID 255) and is documented for
 * experimentation.  pg_vault_tde keeps it for now: the feature is gated off by
 * default and there is no GA release that pins it yet.
 *
 * TODO(follow-up): before GA, reserve a stable custom rmid for pg_vault_tde and
 * register it on the PostgreSQL "Custom WAL Resource Managers" wiki to avoid
 * collisions with other extensions loaded in the same cluster.  Changing the id
 * is a single edit here — it is the only place the value is defined.
 */
#define TDE_RMGR_ID  RM_EXPERIMENTAL_ID

/* Register the custom rmgr.  MUST be called from _PG_init (preload time). */
extern void tde_rmgr_register(void);

/*
 * Write an (already-encrypted) TOAST chunk tuple, WAL-logging it under
 * TDE_RMGR_ID.  Faithful replica of heap_insert(): the emitted WAL record is
 * byte-identical to heap_insert's except for the resource manager id.
 */
extern void tde_toast_wal_insert(Relation relation, HeapTuple tup,
                                 CommandId cid, int options,
                                 BulkInsertState bistate);

/*
 * Logical decoding delivery of encrypted TOAST values.
 *
 * tde_toast_stitch: called by the output plugin's change_cb AFTER the main
 * tuple has been decrypted (historic snapshot active).  Reconstructs the
 * plaintext value from the chunks captured during decode and rewrites the
 * tuple's external on-disk toast pointers into in-memory indirect pointers,
 * writing the result back into change->data.tp.newtuple.  No-op if nothing was
 * captured for xid or the tuple has no external datum.
 *
 * tde_toast_stitch_reset: frees the reconstructed values built for the change
 * just emitted (call AFTER delegating the change to pgoutput — the analogue of
 * core's per-change ReorderBufferToastReset).
 *
 * tde_toast_store_reset: frees a transaction's captured chunks (call at
 * commit / stream-commit / stream-abort).
 */
extern void tde_toast_stitch(Relation relation, ReorderBufferChange *change,
                             TransactionId xid);
extern void tde_toast_stitch_reset(void);
extern void tde_toast_store_reset(TransactionId xid);

#endif                          /* PG_VAULT_TDE_RMGR_H */
