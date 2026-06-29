/*
 * pg_vault_tde_tam.h - Table Access Method (TAM) handler header
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_TAM_H
#define PG_VAULT_TDE_TAM_H

#include "access/tableam.h"

#define MAX_STACK_ATTRS 64

/*
 * pg_vault_tde_get_tableam_routine
 *
 * Returns a pointer to the module-level mutable copy of heapam's
 * TableAmRoutine.  This copy has 4 write + 7 read callbacks replaced
 * with AES-256-GCM encrypt/decrypt wrappers; all other callbacks
 * (VACUUM, ANALYZE structural work, parallel scan, etc.) delegate
 * unchanged to heapam via the original function pointers.
 *
 * Valid only AFTER pg_vault_tde_tam_init() has been called.
 */
const TableAmRoutine *pg_vault_tde_get_tableam_routine(void);

/*
 * pg_vault_tde_tam_init
 *
 * One-time initialisation called from _PG_init.  Copies heapam's
 * TableAmRoutine into a mutable struct, saves original callback
 * pointers (needed for delegation), and installs encrypted wrappers.
 * Must run AFTER shmem hooks are chained so the DEK store is ready
 * before any actual crypto is attempted.
 */
void pg_vault_tde_tam_init(void);

/*
 * tde_encrypt_heap_tuple - encrypt a HeapTuple payload for on-disk storage.
 *
 * Exported for TOAST chunk write path in pg_vault_tde_toast.c.
 * relid is used for per-table DEK lookup.
 */
HeapTuple tde_encrypt_heap_tuple(HeapTuple plain, Oid relid);
/*
 * tde_decrypt_heap_tuple — decrypt an on-disk encrypted HeapTuple.
 *
 * Exported for use by the logical decoding output plugin (v1.2).
 * The WAL sender reads raw encrypted tuples from WAL; the output
 * plugin calls this to produce plaintext before emitting changes.
 *
 * relid: the OID of the source relation (used for per-table DEK lookup).
 *
 * Returns a palloc'd HeapTuple (caller must pfree after use).
 * Raises ERROR on GCM authentication failure.
 */
HeapTuple tde_decrypt_heap_tuple(HeapTuple enc, Oid relid);

int64 pg_vault_tde_reencrypt_table(Oid relid);

#endif /* PG_VAULT_TDE_TAM_H */
