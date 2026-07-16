/*
 * pg_vault_tde_catalog.h — Per-table DEK catalog + shmem cache (v1.5)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * WHY THIS EXISTS:
 * ----------------
 * Each encrypted_heap relation has its own DEK (v1.5+), fetched from the
 * active KMS provider and cached in a shared-memory hash table (the
 * TdeRelDekMap HTAB, keyed by relid).
 *
 * On-disk persistence: pg_vault_tde_catalog(relid, generation,
 * wrapped_dek, created_at).  The in-memory cache is authoritative at runtime;
 * the catalog is the authoritative source for DEK wrapping/unwrapping at
 * startup and after a server restart.
 *
 * Note: the v1.4 global DEK (TdeShmemData, relid=0 sentinel) was removed
 * in v1.7.  All relations must have a pg_vault_tde_catalog entry.
 *
 * OWNERSHIP: @SecurityKMS (shmem + KMS APIs) and @Architect (catalog SQL
 * and ProcessUtility_hook for DROP TABLE cleanup) share this header.
 */
#ifndef PG_VAULT_TDE_CATALOG_H
#define PG_VAULT_TDE_CATALOG_H

#include "postgres.h"
#include "storage/lwlock.h"
#include "utils/relcache.h"

#include "src/include/pg_vault_tde_kms.h"   /* TDE_DEK_LEN */

/*
 * Maximum number of independently-keyed encrypted relations that may be
 * open simultaneously.  Configurable via pg_vault_tde.max_encrypted_relations
 * (PGC_POSTMASTER, range 64–65536, default 1024).
 *
 * This constant is only used as a compile-time fallback default; the actual
 * size is derived from the GUC at shmem_request time.
 */
#define TDE_REL_DEK_CACHE_DEFAULT  1024
#define TDE_WRAPPED_DEK_MAX_LEN    256

typedef struct TdeRelDekMap
{
    Oid          relid;
    char         dek[TDE_DEK_LEN];     /* current AES-256 DEK, 32 bytes */
    char         prev_dek[TDE_DEK_LEN];/* previous DEK (valid during rotation) */
    uint64       generation;            /* rotation epoch for this relation */
    bool         dek_valid;             /* true iff dek[] holds a live key */
    bool         prev_dek_valid;        /* true iff prev_dek[] is populated */
} TdeRelDekMap;

/*
 * Shared memory management (two-phase protocol):
 *   pg_vault_tde_catalog_shmem_request() from shmem_request_hook
 *   pg_vault_tde_catalog_shmem_init()    from shmem_startup_hook
 */
void pg_vault_tde_catalog_shmem_request(void);
void pg_vault_tde_catalog_shmem_init(void);
bool tde_catalog_cache_entry(Oid relid, TdeRelDekMap* out_entry);
Oid resolve_effective_relid(Oid relid);

/*
 * Per-table DEK accessors.
 *
 * pg_vault_tde_kms_get_rel_dek:
 *   Fill dek_out[dek_len] with the DEK for relation relid.
 *   Checks the in-memory cache first (LW_SHARED).  On cache miss:
 *     1. Reads the wrapped DEK from pg_vault_tde_catalog.
 *     2. Calls tde_active_kms_provider->unwrap_dek().
 *     3. Inserts the plaintext DEK into the shmem cache (LW_EXCLUSIVE).
 *   Returns true on success, false if the relation has no catalog entry
 *   (caller decides error policy).
 *
 * This is the authoritative DEK accessor for all table-level encrypt/decrypt
 * paths (v1.5+).
 *
 * CALLER RESPONSIBILITY: OPENSSL_cleanse(dek_out, dek_len) after use.
 */
bool pg_vault_tde_kms_get_rel_dek(Oid relid,
                                   unsigned char *dek_out, int dek_len);

/*
 * pg_vault_tde_kms_get_rel_prev_dek:
 *   Fill prev_dek_out with the previous DEK for the given relation
 *   (populated during online rotation).  Returns false if none exists.
 */
bool pg_vault_tde_kms_get_rel_prev_dek(Oid relid,
                                        unsigned char *prev_dek_out, int dek_len);

/*
 * pg_vault_tde_catalog_register_rel:
 *   Called from the ProcessUtility_hook on CREATE TABLE USING encrypted_heap
 *   and from the object_access_hook during CTAS.
 *   Idempotent: if a catalog entry for relid already exists, returns immediately
 *   without generating a new DEK (the existing key remains valid).
 */
void pg_vault_tde_catalog_register_rel(Oid relid);

/*
 * pg_vault_tde_catalog_update_rel_dek:
 *   Called by the online rotation BGW to replace the wrapped DEK of an
 *   existing catalog entry.  Generates a fresh DEK, wraps it, and performs
 *   a CatalogTupleUpdate on the existing row.  The caller must have already
 *   zeroed the shmem cache entry (pg_vault_tde_catalog_zero_rel_dek) so that
 *   concurrent readers re-fetch the new key from the catalog.
 *   Raises ERROR if no catalog entry exists for relid.
 */
void pg_vault_tde_catalog_update_rel_dek(Oid relid);

/*
 * pg_vault_tde_catalog_deregister_rel:
 *   Called from DROP TABLE hook.  Evicts the cache entry (with
 *   OPENSSL_cleanse), removes the pg_vault_tde_catalog row, and asks the
 *   KMS to delete the key (provider-specific; best-effort, non-fatal).
 */
void pg_vault_tde_catalog_deregister_rel(Oid relid);

/*
 * pg_vault_tde_catalog_evict_rel:
 *   Evict a cached DEK without removing the catalog entry.
 *   Called after online key rotation completes so the next access reloads
 *   the new DEK via the full unwrap path.
 */
void pg_vault_tde_catalog_evict_rel(Oid relid);

/*
 * pg_vault_tde_catalog_evict_all:
 *   Evict ALL per-table DEK entries from shared memory, OPENSSL_cleanse'ing
 *   every dek[] and prev_dek[] buffer in the process.  The catalog rows are
 *   NOT touched — DEKs are reloaded from the catalog on next access.
 *
 *   Called by pg_vault_tde_wallet_lock() to flush all plaintext key material
 *   from shared memory (effective across ALL backends because the cache lives
 *   in shared memory, not per-backend memory).
 *
 *   Acquires LW_EXCLUSIVE on the cache lock for the duration.
 */
void pg_vault_tde_catalog_evict_all(void);

void pg_vault_tde_catalog_zero_rel_dek(Oid relid);

/*
 * pg_vault_tde_catalog_get_rel_generation:
 *   Return the current rotation epoch for relid from the shmem cache.
 *   Returns 1 for the first (unrotated) generation, higher values after
 *   key rotations.  Returns 0 for InvalidOid (backup path, v2 wire format).
 *   Safe to call from any backend; acquires LW_SHARED briefly.
 */
uint64 pg_vault_tde_catalog_get_rel_generation(Oid relid);

bool pg_vault_tde_catalog_rewrap_all(void);


/*
* Row snapshot used by the physical-backup key sealing (seal/unseal).
* wrapped_dek and kms_provider are palloc'd copies owned by the caller.
*/
typedef struct TdeCatalogSealRow
{
    Oid     relid;
    uint64  generation;
    bytea  *wrapped_dek;
    char   *kms_provider;
} TdeCatalogSealRow;

/*
* pg_vault_tde_catalog_read_all_wrapped:
*   Materialize every catalog row having a non-NULL wrapped_dek, ordered by
*   relid (pkey index order).  Native systable scan — no SQL, no search_path.
*   Returns the row count; *rows_out is a palloc'd array (NULL if count 0).
*/
int pg_vault_tde_catalog_read_all_wrapped(TdeCatalogSealRow **rows_out);

/*
* pg_vault_tde_catalog_upsert_row:
*   Insert or update (by relid) a catalog row with the given generation,
*   wrapped DEK and provider.  Used by unseal_keys to re-import a sealed
*   bundle.  Native CatalogTupleInsert/Update — no SQL, no search_path.
*/
void pg_vault_tde_catalog_upsert_row(Oid relid, uint64 generation,
                                    bytea *wrapped_dek,
                                    const char *kms_provider);


#endif /* PG_VAULT_TDE_CATALOG_H */
