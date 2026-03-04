/*
 * pg_vault_tde_toast.c - TOAST data encryption for pg_vault_tde
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * When a column value exceeds ~2KB, PostgreSQL's TOAST machinery:
 *   1. (Optionally) compresses the datum (pglz or lz4)
 *   2. Splits it into TDE_TOAST_CHUNK_SIZE byte chunks
 *   3. Stores chunks in a side relation (pg_toast_<oid>)
 *   4. Replaces the main tuple column with an "external" varlena pointer
 *
 * The challenge for TDE: by the time our TAM's tuple_insert sees a main-
 * table tuple, the oversized values have ALREADY been processed by the TOAST
 * machinery and are stored (in plaintext) in the TOAST table.  The main
 * tuple contains only a VARATT_IS_EXTERNAL pointer.
 *
 * SOLUTION: We enforce that the TOAST table associated with any TDE-enabled
 * relation ALSO uses the pg_vault_tde Table AM.  PostgreSQL creates TOAST
 * tables via heap_create_with_catalog; we hook this via the
 * relation_set_new_filelocator TAM callback to set the correct AM Oid before
 * the first write.  When TOAST chunks are inserted into the TOAST table they
 * pass through our tuple_insert hook, which calls tde_toast_encrypt_chunk.
 *
 * This approach means:
 *  - TOAST chunk encryption is transparent: no changes to query planner.
 *  - Compression happens BEFORE encryption (by PostgreSQL) \u2014 correct order.
 *  - Each chunk gets its own random GCM IV, so identical chunks produce
 *    different ciphertexts (no information leakage via deduplication).
 *  - The external TOAST pointer in the main table is NOT encrypted (it
 *    contains only an OID + chunk sequence, no payload data).
 */
#include "postgres.h"
#include "access/toast_internals.h"
#include "access/heaptoast.h"
#include "utils/memutils.h"
#include <openssl/crypto.h>

#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_toast.h"

/*
 * tde_toast_encrypt_chunk
 *
 * Encrypts one raw TOAST chunk (up to TDE_TOAST_CHUNK_SIZE bytes) using
 * AES-256-GCM.  Called from the TAM tuple_insert hook when inserting into a
 * TOAST table that has been assigned the pg_vault_tde AM.
 *
 * Each chunk gets a fresh random IV (generated inside tde_gcm_encrypt via
 * pg_strong_random).  This is intentional: even if two chunks contain the
 * same data (unlikely after pglz/lz4, but possible for sparse data), they
 * produce different ciphertexts.
 *
 * @param chunk_data   raw TOAST chunk bytes
 * @param chunk_len    number of bytes in this chunk
 * @param out_len      set to encrypted output length
 * @returns            palloc'd encrypted buffer; caller cleans up
 */
char *
tde_toast_encrypt_chunk(Oid parent_relid, const char *chunk_data, Size chunk_len, Size *out_len)
{
    Assert(chunk_data != NULL);
    Assert(chunk_len > 0 && chunk_len <= TOAST_MAX_CHUNK_SIZE);

    /*
     * Delegate to the shared AES-256-GCM primitive with the parent
     * relation's DEK.  The [VERSION|GEN|IV|CT|TAG] wire format is
     * self-contained: each chunk carries its own IV.
     */
    return tde_gcm_encrypt(parent_relid, chunk_data, chunk_len, out_len);
}

/*
 * tde_toast_decrypt_chunk
 *
 * Decrypts a TOAST chunk previously encrypted by tde_toast_encrypt_chunk.
 * Verifies the GCM authentication tag before returning plaintext; any
 * tampering aborts via ereport(ERROR).
 *
 * @param enc_data     [IV|CT|TAG] encrypted chunk
 * @param enc_len      total encrypted length
 * @param out_len      set to decrypted chunk length
 * @returns            palloc'd plaintext chunk; caller cleans up
 */
char *
tde_toast_decrypt_chunk(Oid parent_relid, const char *enc_data, Size enc_len, Size *out_len)
{
    Assert(enc_data != NULL);
    Assert(enc_len > TDE_GCM_OVERHEAD);

    return tde_gcm_decrypt(parent_relid, enc_data, enc_len, out_len);
}

/*
 * TOAST read path note:
 *
 * An explicit tde_toast_reassemble() function is NOT required.  When the
 * TOAST table uses encrypted_heap AM (pg_vault_tde.toast_encryption = on),
 * the standard PG read path already decrypts chunks transparently:
 *
 *   heap_fetch_toast_slice(toastrel, ...)
 *     └─ systable_beginscan_ordered(toastrel, toastidx, ...)
 *          └─ index_getnext_slot()
 *               └─ table_index_fetch_tuple()          ← dispatches via rd_tableam
 *                    └─ tde_index_fetch_tuple()        ← our TAM override
 *                         └─ decode_slot()             ← decrypts each chunk tuple
 *                              └─ tde_decrypt_heap_tuple(chunk, toastrel_oid)
 *
 * Each TOAST chunk tuple is decrypted before fastgetattr() extracts
 * chunk_data, so heap_fetch_toast_slice reassembles plaintext chunks
 * into the final Datum without any TDE-specific logic at its level.
 */
