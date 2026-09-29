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
 * TdeRelDekMap HTAB, keyed by (dbid, relid)).
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

/*
 * Cache key: (dbid, relid).
 *
 * relid is unique only WITHIN a database — never across databases, never
 * cluster-wide — while this HTAB lives in shared memory and is read by the
 * backends of every database.  A relid-only key returns one database's DEK to
 * another; because the GCM AAD binds MyDatabaseId, the victim sees an
 * authentication failure on intact data rather than wrong plaintext.
 *
 * dbid is always MyDatabaseId and is filled in by tde_rel_dek_key() in
 * pg_vault_tde_catalog.c, so it is not part of any public signature here.
 *
 * The on-disk side needs no dbid: pg_vault_tde_catalog is an ordinary table
 * created by CREATE EXTENSION, so it already exists once per database.
 */
typedef struct TdeRelDekMapKey
{
    Oid dbid;
    Oid relid;
} TdeRelDekMapKey;

/*
 * INVARIANT: generation is the generation OF dek[], and is only meaningful
 * while dek_valid is true.
 *
 * The authoritative generation is the pg_vault_tde_catalog row, which rolls
 * back with its transaction; this copy lives in shared memory, which does not.
 * The two are therefore only allowed to move together, in
 * tde_rel_dek_cache_store(), where dek[] and generation are written from the
 * same catalog read.  Nothing else may advance it — see the comment in
 * pg_vault_tde_catalog_zero_rel_dek(), which deliberately does not.
 *
 * ROTATION: while rotating is true an online rotation owns the entry.  dek[]
 * is invalid, prev_dek[] holds the outgoing key and generation is ITS
 * generation — the one every transaction but the rotation's own still sees
 * in the catalog.  Nothing may install a key as current meanwhile: the
 * rotating worker encrypts with the key it generated (held in its own memory,
 * never here), and the entry only moves to the new key when that transaction
 * commits, from its commit callback.  See pg_vault_tde_catalog_zero_rel_dek().
 *
 * STANDBY: the commit callback runs on the primary only; a standby learns of a
 * rotation from the replicated catalog row alone.  So a catalog read that shows
 * a newer generation than a valid entry's replaces it (the entry is stale, not
 * the catalog), and an entry stored during recovery is marked
 * loaded_in_recovery: once recovery is over, the first encryption checks it
 * against the catalog before using it (PSQLE-190).
 */
typedef struct TdeRelDekMap
{
    TdeRelDekMapKey key;
    char         dek[TDE_DEK_LEN];     /* current AES-256 DEK, 32 bytes */
    char         prev_dek[TDE_DEK_LEN];/* previous DEK (valid during rotation) */
    uint64       generation;            /* epoch of dek[]; see INVARIANT above */
    bool         dek_valid;             /* true iff dek[] holds a live key */
    bool         prev_dek_valid;        /* true iff prev_dek[] is populated */
    bool         rotating;              /* an online rotation owns the entry */
    bool         loaded_in_recovery;    /* dek[] read during recovery, not yet
                                         * checked since; see STANDBY above */
} TdeRelDekMap;

/*
 * Shared memory management (two-phase protocol):
 *   pg_vault_tde_catalog_shmem_request() from shmem_request_hook
 *   pg_vault_tde_catalog_shmem_init()    from shmem_startup_hook
 */
void pg_vault_tde_catalog_shmem_request(void);
void pg_vault_tde_catalog_shmem_init(void);
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
 * pg_vault_tde_kms_get_rel_dek_gen:
 *   The key to ENCRYPT with, and its generation, read together.  A DEK and a
 *   generation fetched by two separate calls can straddle a rotation and tag
 *   a ciphertext with a generation its key does not have.
 *
 * pg_vault_tde_kms_get_rel_dek_for_gen:
 *   The key that DECRYPTS data tagged with generation gen: the current DEK,
 *   the previous one, or — for the rotating worker only — the key it is
 *   rotating to.  Returns false when no key for gen is available.
 *
 * Both follow pg_vault_tde_kms_get_rel_dek() on a cache miss, and the same
 * CALLER RESPONSIBILITY applies.
 */
bool pg_vault_tde_kms_get_rel_dek_gen(Oid relid, unsigned char *dek_out,
                                      int dek_len, uint64 *gen_out);
bool pg_vault_tde_kms_get_rel_dek_for_gen(Oid relid, uint64 gen,
                                          unsigned char *dek_out, int dek_len);

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
 *   opened the rotation with pg_vault_tde_catalog_zero_rel_dek(); the new key
 *   is handed to that rotation, never to the shared cache.
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
 * pg_vault_tde_catalog_evict_db:
 *   Evict this database's per-table DEK entries from shared memory,
 *   OPENSSL_cleanse'ing every dek[] and prev_dek[] buffer in the process.  The
 *   catalog rows are NOT touched — DEKs are reloaded from the catalog on next
 *   access.  Acquires LW_EXCLUSIVE on the cache lock for the duration, and is
 *   effective across ALL backends of this database, because the cache lives in
 *   shared memory rather than per-backend memory.
 *
 *   Scoped to MyDatabaseId because every caller is: the wallet is per-database
 *   (/var/lib/pg_vault_tde/<db_oid>/wallet.p12) and pg_vault_tde_catalog is a
 *   per-database table, so wallet_lock/_unlock/_change_passphrase,
 *   migrate_vault_to_wallet, unseal_keys and rotate_kek can only ever
 *   invalidate this database's keys.  Entries belonging to other databases are
 *   not stale, and dropping them would just force unrelated backends into a
 *   needless KMS round-trip — or into an outright failure, if their own wallet
 *   happens to be locked.
 *
 *   There is deliberately no cluster-wide variant.  Nothing needs one today,
 *   and an uncalled one would be untested code pretending to be a feature; if
 *   a global flush is ever required, it is this function without the
 *   MyDatabaseId test.
 */
void pg_vault_tde_catalog_evict_db(void);

/*
 * pg_vault_tde_catalog_cache_entries:
 *   How many DEKs are cached right now, across ALL databases — the cache is
 *   one shared segment keyed by (dbid, relid), so its capacity is a
 *   cluster-wide budget.  Compare against
 *   pg_vault_tde.max_encrypted_relations.
 */
long pg_vault_tde_catalog_cache_entries(void);

/*
 * pg_vault_tde_catalog_zero_rel_dek:
 *   Open an online rotation of relid in the current transaction: demote the
 *   current DEK into prev_dek[], mark the entry rotating, and keep the
 *   outgoing key in this backend.  Recovers the outgoing DEK through
 *   pg_vault_tde_kms_get_rel_dek() first, so it works on a cold cache; call it
 *   BEFORE pg_vault_tde_catalog_update_rel_dek() overwrites the catalog row,
 *   which is the last place that DEK still exists.  ereports on failure — a
 *   rotation that cannot preserve the outgoing DEK must not proceed.
 *
 *   The caller must hold a lock that keeps writers out of the relation
 *   (ShareLock on the heap) and take its scan snapshot after acquiring it.
 *   The rotation ends with the transaction: on commit the entry moves to the
 *   new key, on abort back to the outgoing one.
 */
void pg_vault_tde_catalog_zero_rel_dek(Oid relid);

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
