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

/*
 * Encrypt a single TOAST chunk using AES-256-GCM.
 * parent_relid: OID of the heap relation that owns this TOAST table;
 *   used for per-table DEK selection (InvalidOid = v1.4 global DEK).
 * Each chunk gets its own random IV so identical chunks produce different ciphertexts.
 * Returns a palloc'd [IV|CT|TAG] buffer; caller must pfree.
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
 * TOAST read path: decryption is transparent — no tde_toast_reassemble() is
 * needed.  When the TOAST table uses encrypted_heap AM, heap_fetch_toast_slice
 * internally calls systable_beginscan_ordered → index_getnext_slot →
 * tde_index_fetch_tuple → decode_slot, which decrypts each chunk tuple before
 * fastgetattr extracts chunk_data.  See pg_vault_tde_toast.c for details.
 */

#endif /* PG_VAULT_TDE_TOAST_H */
