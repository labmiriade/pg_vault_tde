/*
 * pg_vault_tde_toast.h - TOAST data encryption header
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_TOAST_H
#define PG_VAULT_TDE_TOAST_H

#include "postgres.h"
#include "src/include/pg_vault_tde_crypto.h"
#include "access/toast_helper.h"

/*
 * Encrypt a single TOAST chunk using AES-256-GCM.
 * parent_relid: OID of the heap relation that owns this TOAST table;
 *   used for per-table DEK selection (InvalidOid = unscoped compatibility path).
 * Each chunk gets its own random IV so identical chunks produce different ciphertexts.
 * Returns a palloc'd [VERSION|GEN|IV|CT|TAG] buffer; caller must pfree.
 */
char *tde_toast_encrypt_chunk(Oid parent_relid,
                              const char *chunk_data, Size chunk_len,
                              Size *out_len);

/*
 * Decrypt a previously encrypted TOAST chunk, verifying the GCM tag.
 * parent_relid: OID of the heap relation that owns this TOAST table.
 * Returns palloc'd plaintext; caller must pfree.
 * Aborts via ereport(ERROR) on authentication failure.
 */
char *tde_toast_decrypt_chunk(Oid parent_relid,
                              const char *enc_data, Size enc_len,
                              Size *out_len);

/*
 * pg_vault_tde_toast_tuple_externalize
 *
 * Custom externalize hook called by the TOAST helper infrastructure during
 * attribute compression / external-storage decisions.  Overrides the default
 * heapam implementation so that the data is routed through the encrypted_heap
 * TOAST AM when pg_vault_tde.toast_encryption is on, rather than the standard
 * heap AM.
 *
 * ttc:       Caller-supplied ToastTupleContext describing the in-progress INSERT
 *            or UPDATE and holding references to all oversized attributes.
 * attribute: Zero-based attribute number within the tuple being toasted.
 * options:   HEAP_INSERT_* flags forwarded from the originating write command.
 */
void pg_vault_tde_toast_tuple_externalize(ToastTupleContext *ttc, int attribute, int options);

/*
 * pg_vault_tde_toast_save_datum
 *
 * Stores a single oversized Datum into the TOAST table associated with rel,
 * optionally re-using the existing external pointer from oldexternal when the
 * value has not changed (UPDATE pass-through optimisation).
 *
 * When rel->rd_rel->reltoastrelid references an encrypted_heap TOAST table,
 * each stored chunk passes through tde_toast_encrypt_chunk() so the TOAST
 * relation never contains plaintext.
 *
 * Returns a compressed or external varlena Datum that replaces the original
 * in the main-table tuple; caller owns the result (no explicit pfree needed
 * because it points into the TOAST chunk's on-disk address or a palloc'd
 * TOAST pointer varlena).
 */
Datum pg_vault_tde_toast_save_datum(Relation rel, Datum value,
                                    struct varlena *oldexternal, int options);

/*
 * pg_vault_tde_toast_tuple
 *
 * Main entry point for the TOAST write path within the encrypted_heap TAM.
 * Scans newtup for attributes that exceed TOAST_TUPLE_THRESHOLD, compresses
 * and/or externalises them via pg_vault_tde_toast_tuple_externalize, and
 * returns a new HeapTuple with modified varlena pointers.
 *
 * oldtup may be NULL (INSERT path).  When non-NULL (UPDATE path),
 * pg_vault_tde_toast_save_datum exploits the old external Datum to avoid
 * writing duplicate TOAST chunks for unchanged large values.
 *
 * Called from pg_vault_tde_toast_insert_or_update; never called directly
 * for tuples that already fit within TOAST_TUPLE_THRESHOLD.
 *
 * Returns a palloc'd HeapTuple; the caller (pg_vault_tde_toast_insert_or_update)
 * is responsible for pfree'ing it after tde_encrypt_heap_tuple has finished.
 */
HeapTuple pg_vault_tde_toast_tuple(Relation rel, HeapTuple newtup,
                                   HeapTuple oldtup, int options);


                              

/*
 * TOAST read path: decryption is transparent — no tde_toast_reassemble() is
 * needed.  When the TOAST table uses encrypted_heap AM, heap_fetch_toast_slice
 * internally calls systable_beginscan_ordered → index_getnext_slot →
 * tde_index_fetch_tuple → decode_slot, which decrypts each chunk tuple before
 * fastgetattr extracts chunk_data.  See pg_vault_tde_toast.c for details.
 */

#endif /* PG_VAULT_TDE_TOAST_H */
