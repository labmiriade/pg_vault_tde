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
 * Encrypt a single TOAST chunk using AES-256-GCM.  Each chunk gets its
 * own random IV so identical chunks produce different ciphertexts.
 * Returns a palloc'd [IV|CT|TAG] buffer; caller must pfree.
 */
char *tde_toast_encrypt_chunk(const char *chunk_data, Size chunk_len,
                              Size *out_len);

/*
 * Decrypt a previously encrypted TOAST chunk, verifying the GCM tag.
 * Returns palloc'd plaintext; caller must pfree.
 * Aborts via ereport(ERROR) on authentication failure.
 */
char *tde_toast_decrypt_chunk(const char *enc_data, Size enc_len,
                              Size *out_len);

/*
 * Reassemble an external TOAST value from its encrypted chunks.
 * Replaces toast_fetch_datum() for TDE-encrypted TOAST tables:
 * scans the TOAST relation, decrypts each chunk, and concatenates
 * them into a single palloc'd Datum.  (Currently a skeleton.)
 */
Datum tde_toast_reassemble(varattrib_4b *attr);

#endif /* PG_VAULT_TDE_TOAST_H */
