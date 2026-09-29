/*
 * pg_vault_tde_catalog.c — Per-table DEK catalog + shmem cache (v1.5)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * OVERVIEW:
 * ---------
 * This module manages the TdeRelDekMap shared-memory hash table (an HTAB
 * created with ShmemInitHash, keyed by (dbid, relid)) and provides the
 * pg_vault_tde_kms_get_rel_dek() accessor used by all TAM encrypt/decrypt
 * paths in v1.5+.  A single LWLock from the named tranche
 * TDE_REL_DEK_MAP_NAME guards the whole table.
 *
 * HOT PATH:
 * ---------
 * Every call to tde_encrypt_heap_tuple / tde_decrypt_heap_tuple goes through
 * pg_vault_tde_kms_get_rel_dek().  The fast path is:
 *   1. Acquire LW_SHARED on rel_dek_lock
 *   2. hash_search(HASH_FIND) for the (dbid, relid) key (O(1) average)
 *   3. Copy DEK into caller's stack buffer
 *   4. Release LW_SHARED
 *
 * Cache miss (first access after startup, or after key rotation):
 *   1. Read wrapped_dek from pg_vault_tde_catalog via direct catalog scan
 *      (table_open + systable_beginscan — no SPI, safe inside TAM callbacks)
 *   2. Call tde_kms_provider()->unwrap_dek()
 *   3. Acquire LW_EXCLUSIVE; insert or update the cache entry; release
 *
 * DEK HYGIENE:
 * ------------
 * Cache entries containing live DEKs are OPENSSL_cleanse'd before eviction.
 * On process exit, local_shutdown() in the KMS provider wipes any provider
 * state.  The shmem DEK bytes are wiped by pg_vault_tde_catalog_evict_rel()
 * and on DROP TABLE.
 *
 * OWNERSHIP: @SecurityKMS
 */

#include "postgres.h"
#include "fmgr.h"
#include "access/relation.h"
#include "access/table.h"
#include "access/xact.h"        /* RegisterXactCallback */
#include "access/xlog.h"        /* RecoveryInProgress */
#include "miscadmin.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/memutils.h"
#include "utils/builtins.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"     /* get_relname_relid */
#include "catalog/namespace.h"  /* get_namespace_oid */
#include "catalog/pg_class.h"   /* RELKIND_TOASTVALUE — detect TOAST tables */
#include "postmaster/postmaster.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "catalog/indexing.h"
#include "catalog/pg_depend_d.h"	
#include "access/heapam.h"
#include "utils/syscache.h"
#include "commands/extension.h"
#include "catalog/dependency.h"

#include <openssl/crypto.h>     /* OPENSSL_cleanse */

#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_catalog_d.h"
#include "src/include/pg_vault_tde_audit.h"
#include "src/include/pg_vault_tde_guc.h"
#include "src/kms/pg_vault_tde_kms_provider.h"


/* -------------------------------------------------------------------------
 * Module-level shmem pointer
 * -------------------------------------------------------------------------*/
static HTAB     *rel_dek_map    = NULL;
static LWLock   *rel_dek_lock   = NULL;

/*
 * Name of both the shmem HTAB and its LWLock tranche.
 *
 * Both are cluster-wide namespaces shared with every other preloaded
 * extension, and neither reports a clash: GetNamedLWLockTranche() returns the
 * first tranche with a matching name, so two extensions would silently share
 * one lock; ShmemInitHash() finds the name already in ShmemIndex and attaches
 * to the EXISTING table with HASH_ATTACH, so the second would read the first's
 * memory through its own struct layout.  Hence the extension prefix, matching
 * pg_vault_tde_kms_cache and pg_vault_tde_pkcs11_shared.  One constant, so
 * request and lookup cannot drift apart ("requested tranche is not
 * registered").  The C type keeps its TdeRelDekMap name: types do not leave
 * this shared object.
 */
#define TDE_REL_DEK_MAP_NAME    "pg_vault_tde_rel_dek_map"

/* Warn once per backend that the cache is full; see tde_rel_dek_cache_store. */
static bool      cache_full_warned = false;

/*
 * The online rotation this backend is running, if any — only ever the rotation
 * worker.  Both keys live here, in process memory.  The new DEK belongs to a
 * transaction that has not committed, so no other backend may see it; the
 * outgoing one must not depend on a shared entry that an eviction can drop.
 * Opened by pg_vault_tde_catalog_zero_rel_dek(), given its new key by
 * pg_vault_tde_catalog_update_rel_dek(), closed by tde_rotation_xact_callback()
 * when the transaction ends.
 */
typedef struct TdeRotationState
{
    bool          active;
    Oid           relid;                    /* effective relid */
    unsigned char old_dek[TDE_DEK_LEN];
    uint64        old_gen;
    unsigned char new_dek[TDE_DEK_LEN];
    uint64        new_gen;
    bool          new_valid;                /* set once the catalog row is written */
} TdeRotationState;

static TdeRotationState tde_rotation;
static bool             tde_rotation_callback_registered = false;

static bool
tde_rotation_owns(Oid effective_relid)
{
    return tde_rotation.active && tde_rotation.relid == effective_relid;
}

/* -------------------------------------------------------------------------
 * tde_rel_dek_key — build the shmem cache key for a relation
 *
 * The HTAB is one segment shared by the backends of EVERY database, but relid
 * is only unique WITHIN a database — never across databases, never
 * cluster-wide.  CREATE DATABASE physically copies the template's directory,
 * so a clone hands out pg_class OIDs identical to its template's: colliding
 * relids are the normal case, not a corner case.  With a relid-only key the
 * first database to populate an entry hands its DEK to every other database
 * sharing that relid, and a DROP TABLE in one evicts the others' live entry.
 *
 * The damage is loud rather than silent: tde_compute_aad() binds MyDatabaseId
 * into the GCM AAD, so the victim gets "AES-256-GCM authentication FAILED" on
 * intact data — a read outage on one database caused by another's traffic.
 * See tap/21_cache_key_cross_db.t.
 *
 * MyDatabaseId is always the right dbid and is never passed in by callers:
 * every path that reaches the cache runs connected to the database that owns
 * both the relation and its pg_vault_tde_catalog row (regular backend,
 * rotation BGW after BackgroundWorkerInitializeConnectionByOid, walsender
 * during logical decoding).  Deriving it here instead of threading it through
 * eight signatures makes "caller passed the wrong dbid" unrepresentable.
 * -------------------------------------------------------------------------*/
static inline void
tde_rel_dek_key(TdeRelDekMapKey *key, Oid relid)
{
    MemSet(key, 0, sizeof(*key));   /* HASH_BLOBS hashes padding bytes too */
    key->dbid  = MyDatabaseId;
    key->relid = relid;
}

/* -------------------------------------------------------------------------
 * Shmem sizing helpers
 * -------------------------------------------------------------------------*/

/*
 * tde_rel_dek_cache_size — size of the TdeRelDekMap HTAB shmem segment.
 *
 * Delegates to hash_estimate_size() for an HTAB of `capacity` TdeRelDekMap
 * entries.  Called from shmem_request_hook.  At that point the GUC has been
 * read but shmem allocation has not happened yet.
 */
static Size
tde_rel_dek_cache_size(int capacity)
{
    return hash_estimate_size(capacity, sizeof(TdeRelDekMap));
}


/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_shmem_request — reserve shmem space (PG 15+ hook)
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_shmem_request(void)
{
    int capacity = pg_vault_tde_max_encrypted_relations;
    if (capacity < 64)
        capacity = TDE_REL_DEK_CACHE_DEFAULT;

    RequestAddinShmemSpace(tde_rel_dek_cache_size(capacity));
    RequestNamedLWLockTranche(TDE_REL_DEK_MAP_NAME, 1);  /* Lock outside of the map */
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_shmem_init — map shmem and init LWLock
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_shmem_init(void)
{
    HASHCTL info; 
    int capacity = pg_vault_tde_max_encrypted_relations; 

    if(capacity < 64)
        capacity = TDE_REL_DEK_CACHE_DEFAULT;

    rel_dek_lock = &GetNamedLWLockTranche(TDE_REL_DEK_MAP_NAME)[0].lock;

    MemSet(&info, 0, sizeof(info));
    info.keysize = sizeof(TdeRelDekMapKey);
    info.entrysize = sizeof(TdeRelDekMap);

    rel_dek_map = ShmemInitHash(TDE_REL_DEK_MAP_NAME,
                                capacity, 
                                capacity, 
                                &info, 
                                HASH_ELEM | HASH_BLOBS);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_get_parent_relid — map a TOAST table OID to its parent OID
 *
 * v1.6 TOAST encryption: when a tuple is inserted into a TOAST table, we
 * need to retrieve the DEK using the parent table's relid (not the TOAST
 * table's relid).  This function does a reverse lookup on pg_class to find
 * the parent.
 *
 * @param toast_relid   a TOAST table OID (relkind == RELKIND_TOASTVALUE)
 * @returns             parent table OID on success, or InvalidOid if not found
 *                      or if toast_relid is not actually a TOAST table
 *
 * This is called from pg_vault_tde_kms_get_rel_dek() when the relid parameter
 * is detected to be a TOAST table, ensuring that TOAST chunks use the same DEK
 * as their parent table.
 *
 * Caching: candidate for v1.7 is caching reltoastrelid -> parent 
 * with a hash table 
 * -------------------------------------------------------------------------*/
static Oid
pg_vault_tde_get_parent_relid(Oid toast_relid)
{
    Datum         search_datum;
    ScanKeyData   scan_key;
    SysScanDesc   scan;
    HeapTuple     search_tuple;
    Relation      pg_depend_rel;
    bool          isnull;
    char          depType;

    Oid result_oid = InvalidOid;

    if (!OidIsValid(toast_relid))
        return InvalidOid;

    search_datum = ObjectIdGetDatum(toast_relid);

    /*Init of the WHERE condition: WHERE objid = toast_relid*/
    ScanKeyInit(&scan_key, Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, search_datum);

    /* DependRelationId is the OID of pg_depend generated in pg_depend_d.h */
    pg_depend_rel = table_open(DependRelationId, AccessShareLock);

    /*
     * NULL, not GetTransactionSnapshot(): systable_beginscan() then picks the
     * catalog snapshot itself.  A transaction snapshot is neither registered
     * nor active, so HeapTupleSatisfiesVisibility asserts
     * (regd_count > 0 || active_count > 0) on an assert-enabled server and,
     * worse, nothing pins it for the life of the scan.  Core passes NULL for
     * every catalog scan; see make ci-cassert.
     */
    scan = systable_beginscan(pg_depend_rel, DependDependerIndexId, true, NULL, 1, &scan_key);

    while(HeapTupleIsValid(search_tuple = systable_getnext(scan))){

        depType = DatumGetChar(heap_getattr(search_tuple, Anum_pg_depend_deptype, RelationGetDescr(pg_depend_rel), &isnull));
        if(depType != DEPENDENCY_INTERNAL) continue;

        result_oid = DatumGetObjectId(
                            heap_getattr(search_tuple, Anum_pg_depend_refobjid, RelationGetDescr(pg_depend_rel), &isnull)
                    );
        break;
    }

    systable_endscan(scan);
    table_close(pg_depend_rel, AccessShareLock);

    return result_oid;
}

static Oid get_rel_rewrite(Oid relid)
{
    HeapTuple tup;
    Oid rewrite_oid = InvalidOid;

    tup = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
    if(HeapTupleIsValid(tup))
    {
        Form_pg_class class = (Form_pg_class) GETSTRUCT(tup);
        
        rewrite_oid = class->relrewrite;
        ReleaseSysCache(tup);
    }
   
    return rewrite_oid;

}

/* -------------------------------------------------------------------------
 * resolve_effective_relid — map relid to the OID that owns the DEK
 *
 * Applies: TOAST → parent, then relrewrite → base relation (VACUUM FULL).
 * -------------------------------------------------------------------------*/
Oid
resolve_effective_relid(Oid relid)
{
    Oid effective_relid = relid;
    Oid relrewrite;

    if (!OidIsValid(relid))
        return relid;

    if (get_rel_relkind(relid) == RELKIND_TOASTVALUE)
    {
        Oid parent_relid = pg_vault_tde_get_parent_relid(relid);
        if (OidIsValid(parent_relid))
            effective_relid = parent_relid;
    }

    relrewrite = get_rel_rewrite(effective_relid);
    if (relrewrite != InvalidOid)
        effective_relid = relrewrite;

    return effective_relid;
}

/* -------------------------------------------------------------------------
 * tde_catalog_read_row — read one pg_vault_tde_catalog row by relid
 *
 * Resolves the catalog OIDs internally, opens AccessShareLock, scans on the
 * pkey, copies out the needed fields, then closes. Returns false only if the
 * catalog table itself is absent (pre-CREATE EXTENSION); out->found tells
 * whether a matching row existed.
 * -------------------------------------------------------------------------*/
typedef struct TdeCatalogRow
{
    bool          found;
    unsigned char wrapped_dek[512];
    int           wrapped_len;        /* real length even if > buffer; 0 = NULL/absent */
    uint64        generation;
    bool          generation_isnull;
} TdeCatalogRow;

static bool
tde_catalog_read_row(Oid relid, TdeCatalogRow *out)
{
    Oid          ext_ns;
    Oid          catalog_oid;
    Oid          catalog_idx;
    Relation     catalog_rel;
    TupleDesc    tupdesc;
    ScanKeyData  scan_key;
    SysScanDesc  scan;
    HeapTuple    tuple;

    memset(out, 0, sizeof(*out));

    ext_ns = get_extension_schema(
                 get_extension_oid(pg_vault_tde_extension_name, true));
    if (!OidIsValid(ext_ns))
        return false;

    catalog_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);
    if (!OidIsValid(catalog_oid))
        return false;

    catalog_idx = get_relname_relid("pg_vault_tde_catalog_pkey", ext_ns);

    catalog_rel = table_open(catalog_oid, AccessShareLock);
    tupdesc     = RelationGetDescr(catalog_rel);

    ScanKeyInit(&scan_key, Anum_pg_vault_tde_relid, BTEqualStrategyNumber,
                F_OIDEQ, ObjectIdGetDatum(relid));
    scan = systable_beginscan(catalog_rel, catalog_idx, true,
                              NULL, 1, &scan_key);

    if (HeapTupleIsValid(tuple = systable_getnext(scan)))
    {
        Datum d;
        bool  wrapped_isnull;

        out->found = true;

        d = heap_getattr(tuple, Anum_pg_vault_tde_wrapped_dek,
                         tupdesc, &wrapped_isnull);
        if (!wrapped_isnull)
        {
            /* Copy while the buffer page is still pinned by the scan. */
            bytea *b = DatumGetByteaPP(d);
            out->wrapped_len = VARSIZE_ANY_EXHDR(b);
            if (out->wrapped_len <= (int) sizeof(out->wrapped_dek))
                memcpy(out->wrapped_dek, VARDATA_ANY(b), out->wrapped_len);
        }

        d = heap_getattr(tuple, Anum_pg_vault_tde_generation,
                         tupdesc, &out->generation_isnull);
        out->generation = out->generation_isnull ? 0 : DatumGetUInt64(d);
    }

    systable_endscan(scan);
    table_close(catalog_rel, AccessShareLock);
    return true;
}

/* -------------------------------------------------------------------------
 * tde_rel_dek_cache_store — insert an unwrapped DEK into the shmem cache
 *
 * Takes ownership of dek_temp: OPENSSL_cleanse'd before returning in all paths.
 * -------------------------------------------------------------------------*/
static bool
tde_rel_dek_cache_store(Oid relid,
                        unsigned char *dek,
                        uint64 generation)
{
    TdeRelDekMap    *stored_slot = NULL;
    TdeRelDekMapKey  search_key;
    bool             found;

    tde_rel_dek_key(&search_key, relid);

    if(!rel_dek_map) 
        ereport(ERROR, errmsg("pg_vault_tde: error: shmem cache is null, the extension must be loaded via shared_preload_libraries"));

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);

    /*
     * Enforce pg_vault_tde.max_encrypted_relations ourselves, before
     * HASH_ENTER gets the chance to ignore it.
     *
     * The size handed to ShmemInitHash() is not a cap: it sizes the initial
     * allocation and the bucket directory, and once the freelist is empty
     * dynahash keeps allocating elements from the main shared memory segment.
     * HASH_ENTER_NULL therefore only fails when shared memory as a whole is
     * exhausted — by which point the cluster has larger problems — and the
     * table happily grows to many times the configured number in between.
     *
     * That is the wrong shape for this particular cache: it holds plaintext
     * DEKs.  An administrator who budgets 1024 relations is budgeting how much
     * key material sits unencrypted in shared memory, and silently keeping ten
     * times that is not a service.  Bounding it also makes the shmem footprint
     * predictable, which is what the GUC's documentation has always claimed.
     *
     * Only new keys are refused.  An existing entry is always refreshed —
     * declining there would break the refill half of a rotation window, where
     * the entry is already present and merely missing its current DEK.
     */
    if (hash_search(rel_dek_map, &search_key, HASH_FIND, NULL) == NULL &&
        hash_get_num_entries(rel_dek_map) >= pg_vault_tde_max_encrypted_relations)
    {
        LWLockRelease(rel_dek_lock);

        if (!cache_full_warned)
        {
            cache_full_warned = true;
            ereport(WARNING,
                    errmsg("pg_vault_tde: DEK cache is at its configured limit "
                           "of %d relations; further relations are re-unwrapped "
                           "from the KMS on every access",
                           pg_vault_tde_max_encrypted_relations),
                    errhint("Increase pg_vault_tde.max_encrypted_relations and "
                            "restart; the cache costs about 112 bytes per "
                            "relation and the limit is shared by every "
                            "database. Reported once per backend."));
        }

        return false;
    }

    stored_slot = (TdeRelDekMap*) hash_search(rel_dek_map, &search_key, HASH_ENTER_NULL, &found);

    if(!stored_slot){
        LWLockRelease(rel_dek_lock);

        /*
         * Shared memory itself is exhausted — the budget check above already
         * handled the ordinary "cache is full" case.  Still not a reason to
         * fail: by the time this runs the DEK has been unwrapped and handed to
         * the caller (pg_vault_tde_kms_get_rel_dek fills dek_out before
         * calling us), so the request is serviceable and only its memoisation
         * failed.  Raising an ERROR here would make a relation unreadable for
         * a reason that has nothing to do with its key.
         */
        if (!cache_full_warned)
        {
            cache_full_warned = true;
            ereport(WARNING,
                    errmsg("pg_vault_tde: out of shared memory for the DEK "
                           "cache; this relation is re-unwrapped from the KMS "
                           "on every access"),
                    errhint("Reported once per backend."));
        }

        return false;
    }

    /*
     * An online rotation owns this entry until its transaction ends.  The
     * catalog row the caller just read is the one its snapshot sees — the
     * outgoing key, for every transaction but the rotation's own — and
     * installing it as current is what let the rotation worker re-encrypt a
     * whole table with the key it was retiring (PSQLE-184).  The caller already
     * holds the key it asked for; only the memoisation is skipped.
     */
    if(found && stored_slot->rotating)
    {
        LWLockRelease(rel_dek_lock);
        return false;
    }

    if(found && stored_slot->dek_valid)
    {
        /*
         * A valid entry is replaced only when it is stale: the catalog shows a
         * newer generation (a rotation replayed on a standby, or promoted
         * since), or recovery is over and the entry, read during it, differs
         * from the catalog at all.  An older generation during recovery comes
         * from a reader with an older snapshot, and must not win (PSQLE-190).
         */
        bool checked = stored_slot->loaded_in_recovery && !RecoveryInProgress();
        bool stale   = generation > stored_slot->generation ||
                       (checked && generation != stored_slot->generation);

        if (stale)
        {
            /* prev_dek[] is the generation just before, or nothing. */
            if (generation == stored_slot->generation + 1)
            {
                memcpy(stored_slot->prev_dek, stored_slot->dek, TDE_DEK_LEN);
                stored_slot->prev_dek_valid = true;
            }
            else
            {
                OPENSSL_cleanse(stored_slot->prev_dek, TDE_DEK_LEN);
                stored_slot->prev_dek_valid = false;
            }
            memcpy(stored_slot->dek, dek, TDE_DEK_LEN);
            stored_slot->generation = generation;
            stored_slot->loaded_in_recovery = RecoveryInProgress();
        }
        else if (checked)
            stored_slot->loaded_in_recovery = false;

        LWLockRelease(rel_dek_lock);
        return stale;
    }
    else if(found && !stored_slot->dek_valid && stored_slot->prev_dek_valid)
    {
        /*
         * An entry that lost dek[] but kept prev_dek[]: prev_dek[] stays, dek[] comes back.
         * generation moves with dek[] — see the invariant on the struct.
         * Leaving it behind is what let a failed rotation strand the entry a
         * generation ahead of the catalog.
         */
        memcpy(stored_slot->dek, dek, TDE_DEK_LEN);
        stored_slot->dek_valid  = true;
        stored_slot->generation = generation;
        stored_slot->loaded_in_recovery = RecoveryInProgress();

        LWLockRelease(rel_dek_lock);
        return true;
    }


    if(!found)
    {
        stored_slot->prev_dek_valid = false;
        stored_slot->rotating       = false;
        MemSet(stored_slot->prev_dek, 0, TDE_DEK_LEN);
    }

    memcpy(stored_slot->dek, dek, TDE_DEK_LEN);
    stored_slot->dek_valid = true; 
    stored_slot->generation = generation;
    stored_slot->loaded_in_recovery = RecoveryInProgress();

    LWLockRelease(rel_dek_lock);
    return true;
}

/* -------------------------------------------------------------------------
 * tde_rel_dek_load — the slow path: catalog read + KMS unwrap + memoise
 *
 * Returns the key and generation the catalog shows this backend, which for a
 * relation mid-rotation is the outgoing key until the rotation commits, and
 * the new one right after — the catalog snapshot is never older than the
 * statement's.  tde_rel_dek_cache_store() declines to memoise mid-rotation.
 * -------------------------------------------------------------------------*/
static bool
tde_rel_dek_load(Oid effective_relid, unsigned char *dek_out, uint64 *gen_out)
{
    TdeCatalogRow row;
    unsigned char dek_temp[TDE_DEK_LEN];
    bool          unwrap_ok;
    const TdeKmsProvider *kms;

    /* Guard: catalog absent on fresh install before CREATE EXTENSION. */
    if (!tde_catalog_read_row(effective_relid, &row))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: catalog absent — "
                       "no DEK available for relid=%u", effective_relid));
        return false;
    }

    if (!row.found)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: no catalog entry for relid=%u",
                       effective_relid));
        return false;
    }

    if (row.wrapped_len == 0 || row.generation == 0)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wrapped_dek IS NULL for relid=%u",
                       effective_relid));
        return false;
    }

    if (row.wrapped_len > (int) sizeof(row.wrapped_dek))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: wrapped_dek too large (%d bytes) "
                       "for relid=%u", row.wrapped_len, effective_relid));
        return false;
    }

    kms = tde_kms_provider();

    if (!kms || !kms->unwrap_dek)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: no active KMS provider for "
                       "unwrap_dek (relid=%u)", effective_relid));
        return false;
    }

    {
        int dek_temp_len = TDE_DEK_LEN;
        unwrap_ok = kms->unwrap_dek(
                        row.wrapped_dek, row.wrapped_len, dek_temp, &dek_temp_len);
    }

    OPENSSL_cleanse(row.wrapped_dek, sizeof(row.wrapped_dek));

    if (!unwrap_ok)
    {
        OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
        tde_audit(ACCESS_DENIED, psprintf("%u", effective_relid), false);
        return false;
    }

    tde_audit(KMS_DEK_ACCESS, psprintf("%u", effective_relid), true);

    memcpy(dek_out, dek_temp, TDE_DEK_LEN);
    *gen_out = row.generation;

    /* Store the DEK for next calls */
    tde_rel_dek_cache_store(effective_relid, dek_temp, row.generation);
    
    OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
    return true;
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_kms_get_rel_dek_gen — hot-path DEK accessor (v1.5+)
 *
 * The key to encrypt with and its generation, read together.  Resolves the
 * effective OID, checks the shmem cache (fast path), on a miss fetches from
 * pg_vault_tde_catalog + KMS unwrap and stores via tde_rel_dek_cache_store.
 * -------------------------------------------------------------------------*/
bool
pg_vault_tde_kms_get_rel_dek_gen(Oid relid, unsigned char *dek_out,
                                 int dek_len, uint64 *gen_out)
{
    bool             found = false;
    Oid              effective_relid;
    TdeRelDekMap    *e;
    TdeRelDekMapKey  search_key;

    Assert(dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(gen_out != NULL);

    effective_relid = resolve_effective_relid(relid);

    /* The rotating worker writes with the key it is rotating to. */
    if (tde_rotation_owns(effective_relid))
    {
        if (tde_rotation.new_valid)
        {
            memcpy(dek_out, tde_rotation.new_dek, TDE_DEK_LEN);
            *gen_out = tde_rotation.new_gen;
        }
        else
        {
            memcpy(dek_out, tde_rotation.old_dek, TDE_DEK_LEN);
            *gen_out = tde_rotation.old_gen;
        }
        return true;
    }

    tde_rel_dek_key(&search_key, effective_relid);

    /* ---- Fast path: LW_SHARED cache lookup ---- */
    if(!rel_dek_map) 
        ereport (ERROR, errmsg("pg_vault_tde: error: shmem cache is null, the extension must be loaded via shared_preload_libraries"));

    LWLockAcquire(rel_dek_lock, LW_SHARED);
    e = (TdeRelDekMap*) hash_search(rel_dek_map, &search_key, HASH_FIND, NULL);

    /*
     * Not an entry read during recovery that nobody has checked since: a
     * promoted node would encrypt under a key a rotation replayed meanwhile
     * had retired (PSQLE-190).  The slow path checks it once.  Nothing is
     * encrypted during recovery, so this costs one catalog read per relation
     * after a promotion.
     */
    if (e && e->dek_valid && !(e->loaded_in_recovery && !RecoveryInProgress()))
    {
        memcpy(dek_out, e->dek, TDE_DEK_LEN);
        *gen_out = e->generation;
        found = true;
    }
    else if (e && e->rotating && e->prev_dek_valid)
    {
        /* Mid-rotation the outgoing key is still current for everyone else. */
        memcpy(dek_out, e->prev_dek, TDE_DEK_LEN);
        *gen_out = e->generation;
        found = true;
    }

    LWLockRelease(rel_dek_lock);

    if (found)
        return true;

    return tde_rel_dek_load(effective_relid, dek_out, gen_out);
}

bool
pg_vault_tde_kms_get_rel_dek(Oid relid, unsigned char *dek_out, int dek_len)
{
    uint64 gen;

    return pg_vault_tde_kms_get_rel_dek_gen(relid, dek_out, dek_len, &gen);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_kms_get_rel_dek_for_gen — the key that decrypts generation gen
 *
 * The current DEK, the previous one, or — for the rotating worker only — the
 * key it is rotating to.  The catalog only ever holds the current key, so a
 * generation older than the previous one has no key once the cache is gone.
 * -------------------------------------------------------------------------*/
bool
pg_vault_tde_kms_get_rel_dek_for_gen(Oid relid, uint64 gen,
                                     unsigned char *dek_out, int dek_len)
{
    bool             found = false;
    Oid              effective_relid = resolve_effective_relid(relid);
    TdeRelDekMap    *e;
    TdeRelDekMapKey  search_key;
    uint64           current_gen;

    Assert(dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

    if (tde_rotation_owns(effective_relid))
    {
        if (tde_rotation.new_valid && gen == tde_rotation.new_gen)
            memcpy(dek_out, tde_rotation.new_dek, TDE_DEK_LEN);
        else if (gen == tde_rotation.old_gen)
            memcpy(dek_out, tde_rotation.old_dek, TDE_DEK_LEN);
        else
            return false;
        return true;
    }

    if (!rel_dek_map)
        return false;

    tde_rel_dek_key(&search_key, effective_relid);

    LWLockAcquire(rel_dek_lock, LW_SHARED);
    e = (TdeRelDekMap*) hash_search(rel_dek_map, &search_key, HASH_FIND, NULL);

    if (e && e->dek_valid && gen == e->generation)
    {
        memcpy(dek_out, e->dek, TDE_DEK_LEN);
        found = true;
    }
    else if (e && e->dek_valid && e->prev_dek_valid && gen + 1 == e->generation)
    {
        memcpy(dek_out, e->prev_dek, TDE_DEK_LEN);
        found = true;
    }
    else if (e && e->rotating && e->prev_dek_valid && gen == e->generation)
    {
        memcpy(dek_out, e->prev_dek, TDE_DEK_LEN);
        found = true;
    }

    LWLockRelease(rel_dek_lock);

    if (found)
        return true;

    /*
     * Miss: the catalog's key serves only its own generation.  Straight to the
     * catalog, not through get_rel_dek_gen(): mid-rotation that would answer
     * with the outgoing key, while a reader whose snapshot already sees the
     * rotation's commit needs the new one for the rows it rewrote.
     */
    if (!tde_rel_dek_load(effective_relid, dek_out, &current_gen))
        return false;

    if (current_gen == gen)
        return true;

    OPENSSL_cleanse(dek_out, dek_len);
    return false;
}

/*
 * generate_dek — produce a fresh 32-byte AES-256 DEK
 * Returns true on success.
 */
static bool pg_vault_tde_catalog_generate_dek(unsigned char *dek_out, int dek_len)
{
    if (!pg_strong_random(dek_out, dek_len))
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: vault provider: pg_strong_random failed"));
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_register_rel — called on CREATE TABLE
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_register_rel(Oid relid)
{
    unsigned char dek[TDE_DEK_LEN];
    unsigned char wrapped[512];
    int           wrapped_len = sizeof(wrapped);
    const TdeKmsProvider *kms;

    bytea *wrapped_bytea;

    Relation  rel;
    TupleDesc tup_desc;
    HeapTuple new_tuple;
    Datum values[CATALOG_NATTS];
    bool isnull[CATALOG_NATTS];

    ScanKeyData scan_key;
    SysScanDesc scan;
    Oid catalog_idx;
    Oid catalog_oid;
    HeapTuple found_tuple = NULL;

    Oid  ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));

    Assert(OidIsValid(relid));

    /* If this is a TOAST table, map to parent */
    if(get_rel_relkind(relid) == RELKIND_TOASTVALUE){
        return;
    }

    kms = tde_kms_provider();

    if (!kms)
        ereport(ERROR,
                errmsg("pg_vault_tde: no active KMS provider — cannot "
                       "register DEK for relid=%u", relid));

    /* Generate a fresh DEK */
    if (!pg_vault_tde_catalog_generate_dek(dek, TDE_DEK_LEN))
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        ereport(ERROR,
                errmsg("pg_vault_tde: generate_dek failed for relid=%u",
                       relid));
    }

    /* Wrap the DEK */
    if (!kms->wrap_dek(dek, TDE_DEK_LEN, wrapped, &wrapped_len))
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        ereport(ERROR,
                errmsg("pg_vault_tde: wrap_dek failed for relid=%u", relid));
    }

    OPENSSL_cleanse(dek, TDE_DEK_LEN);

    catalog_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);
    if (!OidIsValid(catalog_oid))
        ereport(ERROR, (errmsg("catalog pg_vault_tde_catalog not found")));

    rel = table_open(catalog_oid, RowExclusiveLock);
    tup_desc = RelationGetDescr(rel);

    memset(isnull, false, sizeof(isnull));

    values[Anum_pg_vault_tde_relid-1] = ObjectIdGetDatum(relid);
    values[Anum_pg_vault_tde_generation-1] = Int64GetDatum(1);

    wrapped_bytea = (bytea *) palloc0(VARHDRSZ + wrapped_len);
    SET_VARSIZE(wrapped_bytea, VARHDRSZ + wrapped_len);
    memcpy(VARDATA(wrapped_bytea), wrapped, wrapped_len);
    values[Anum_pg_vault_tde_wrapped_dek-1] = PointerGetDatum(wrapped_bytea);

    values[Anum_pg_vault_tde_kms_provider-1] = CStringGetTextDatum(pg_vault_tde_kms_provider);
    catalog_idx = get_relname_relid("pg_vault_tde_catalog_pkey", ext_ns);

    ScanKeyInit(&scan_key, Anum_pg_vault_tde_relid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));
    scan = systable_beginscan(rel, catalog_idx, true, NULL, 1, &scan_key);

    found_tuple = systable_getnext(scan);

    if (HeapTupleIsValid(found_tuple))
    {
        /*
         * Entry already exists — the DEK was registered by a prior call
         * (typically the object_access_hook that fires during CTAS before
         * data insertion).  Do NOT overwrite it with a new DEK: the existing
         * rows are already encrypted under the current DEK, and replacing it
         * here would make them unreadable.
         *
         * Return immediately; the wrapped DEK in the catalog remains valid.
         */
        systable_endscan(scan);
        table_close(rel, RowExclusiveLock);

        ereport(DEBUG1,
                errmsg("pg_vault_tde: relid=%u already in catalog — "
                       "skipping duplicate registration", relid));
        return;
    }

    values[Anum_pg_vault_tde_created_at-1] = TimestampTzGetDatum(GetCurrentTransactionStartTimestamp());
    values[Anum_pg_vault_tde_updated_at-1] = TimestampTzGetDatum(GetCurrentTransactionStartTimestamp());

    new_tuple = heap_form_tuple(tup_desc, values, isnull);
    CatalogTupleInsert(rel, new_tuple);

    tde_audit(KMS_DEK_CREATE, psprintf("%u", relid), true);

    systable_endscan(scan);
    table_close(rel, RowExclusiveLock);
    heap_freetuple(new_tuple);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_update_rel_dek — replace the wrapped DEK for a
 * relation that already has a catalog entry (used by online rotation BGW).
 *
 * Generates a brand-new DEK, wraps it via the active KMS provider, and
 * stores it with CatalogTupleUpdate so the existing row is replaced in-place.
 * The caller is responsible for first zeroing the shmem cache entry
 * (pg_vault_tde_catalog_zero_rel_dek) so that concurrent readers re-fetch
 * the new key from the catalog.
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_update_rel_dek(Oid relid)
{
    unsigned char dek[TDE_DEK_LEN];
    unsigned char wrapped[512];
    int           wrapped_len = sizeof(wrapped);
    const TdeKmsProvider *kms;

    bytea        *wrapped_bytea;

    Relation    rel;
    TupleDesc   tup_desc;
    HeapTuple   old_tuple;
    HeapTuple   new_tuple;
    Datum       values[CATALOG_NATTS];
    bool        isnull[CATALOG_NATTS];
    bool        do_replace[CATALOG_NATTS];

    ScanKeyData scan_key;
    SysScanDesc scan;
    Oid         catalog_idx;
    Oid         catalog_oid;
    int64       new_gen;

    Oid ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));

    Assert(OidIsValid(relid));

    kms = tde_kms_provider();

    if (!kms)
        ereport(ERROR,
                errmsg("pg_vault_tde: no active KMS provider — cannot "
                       "update DEK for relid=%u", relid));

    /* Generate a fresh DEK */
    if (!pg_vault_tde_catalog_generate_dek(dek, TDE_DEK_LEN))
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        ereport(ERROR,
                errmsg("pg_vault_tde: generate_dek failed for relid=%u",
                       relid));
    }

    /* Wrap the DEK */
    if (!kms->wrap_dek(dek, TDE_DEK_LEN, wrapped, &wrapped_len))
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        ereport(ERROR,
                errmsg("pg_vault_tde: wrap_dek failed for relid=%u", relid));
    }

    /*
     * The new key goes to the rotation, never to the shared cache: it belongs
     * to a transaction that has not committed.  It becomes usable (new_valid)
     * only once the catalog row below is written; an error before that aborts
     * the transaction, and the abort callback wipes it.
     */
    if (tde_rotation_owns(resolve_effective_relid(relid)))
        memcpy(tde_rotation.new_dek, dek, TDE_DEK_LEN);

    OPENSSL_cleanse(dek, TDE_DEK_LEN);

    catalog_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);
    if (!OidIsValid(catalog_oid))
        ereport(ERROR, (errmsg("pg_vault_tde_catalog not found")));

    rel = table_open(catalog_oid, RowExclusiveLock);
    tup_desc = RelationGetDescr(rel);

    catalog_idx = get_relname_relid("pg_vault_tde_catalog_pkey", ext_ns);
    ScanKeyInit(&scan_key, Anum_pg_vault_tde_relid, BTEqualStrategyNumber,
                F_OIDEQ, ObjectIdGetDatum(relid));
    scan = systable_beginscan(rel, catalog_idx, true,
                              NULL, 1, &scan_key);

    old_tuple = systable_getnext(scan);
    if (!HeapTupleIsValid(old_tuple))
    {
        systable_endscan(scan);
        table_close(rel, RowExclusiveLock);
        ereport(ERROR,
                errmsg("pg_vault_tde: no catalog entry found for relid=%u "
                       "— cannot update DEK", relid));
    }

    memset(values,     0,     sizeof(values));
    memset(isnull,     false, sizeof(isnull));
    memset(do_replace, false, sizeof(do_replace));

    wrapped_bytea = (bytea *) palloc0(VARHDRSZ + wrapped_len);
    SET_VARSIZE(wrapped_bytea, VARHDRSZ + wrapped_len);
    memcpy(VARDATA(wrapped_bytea), wrapped, wrapped_len);

    {
        bool    gen_isnull;
        int64   old_gen = DatumGetInt64(
                              heap_getattr(old_tuple, Anum_pg_vault_tde_generation,
                                           tup_desc, &gen_isnull));
        new_gen = gen_isnull ? 2 : old_gen + 1;
        values[Anum_pg_vault_tde_generation-1] = Int64GetDatum(new_gen);
    }

    values[Anum_pg_vault_tde_wrapped_dek-1]  = PointerGetDatum(wrapped_bytea);
    values[Anum_pg_vault_tde_kms_provider-1] = CStringGetTextDatum(pg_vault_tde_kms_provider);
    values[Anum_pg_vault_tde_updated_at-1]   = TimestampTzGetDatum(GetCurrentTransactionStartTimestamp());

    do_replace[Anum_pg_vault_tde_wrapped_dek-1]  = true;
    do_replace[Anum_pg_vault_tde_generation-1]   = true;
    do_replace[Anum_pg_vault_tde_kms_provider-1] = true;
    do_replace[Anum_pg_vault_tde_updated_at-1]   = true;

    new_tuple = heap_modify_tuple(old_tuple, tup_desc, values, isnull, do_replace);
    CatalogTupleUpdate(rel, &old_tuple->t_self, new_tuple);

    if (tde_rotation_owns(resolve_effective_relid(relid)))
    {
        tde_rotation.new_gen   = (uint64) new_gen;
        tde_rotation.new_valid = true;
    }
    
    tde_audit(KMS_DEK_ROTATE, psprintf("%u", relid), true);

    systable_endscan(scan);
    table_close(rel, RowExclusiveLock);
    heap_freetuple(new_tuple);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_deregister_rel — called on DROP TABLE
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_deregister_rel(Oid relid)
{
    Relation rel;
    Oid  ext_ns;
    Oid catalog_idx;

    SysScanDesc scan;
    ScanKeyData scan_key;
    HeapTuple tuple;

    /* Evict from shmem cache with OPENSSL_cleanse */
    pg_vault_tde_catalog_evict_rel(relid);
    
    ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
    rel = table_open(get_relname_relid("pg_vault_tde_catalog", ext_ns), RowExclusiveLock);

    if(rel->rd_rel->relkind == RELKIND_TOASTVALUE){
        table_close(rel, RowExclusiveLock);
        return;
    }

    catalog_idx = get_relname_relid("pg_vault_tde_catalog_pkey", ext_ns);

    ScanKeyInit(&scan_key, Anum_pg_vault_tde_relid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));
    scan = systable_beginscan(rel, catalog_idx, true, NULL, 1, &scan_key);

    tuple = systable_getnext(scan);

    if(!HeapTupleIsValid(tuple)){
        ereport(WARNING, errmsg("pg_vault_tde: no catalog entry found for dropped relid=%u", relid));
        systable_endscan(scan);
        table_close(rel, RowExclusiveLock);
        return;
    }

    CatalogTupleDelete(rel, &(tuple->t_self));
    tde_audit(KMS_DEK_DELETE, psprintf("%u", relid), true);

    systable_endscan(scan);
    table_close(rel, RowExclusiveLock);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_evict_rel — evict shmem entry, keep catalog row
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_evict_rel(Oid relid)
{
    bool             found = false;
    TdeRelDekMap    *e;
    TdeRelDekMapKey  search_key;

    tde_rel_dek_key(&search_key, relid);

    if (!rel_dek_map)
        return;

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);

    e = (TdeRelDekMap*) hash_search(rel_dek_map, &search_key, HASH_FIND, &found);
    if (found)
    {
        OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
        OPENSSL_cleanse(e->prev_dek, TDE_DEK_LEN);
        hash_search(rel_dek_map, &search_key, HASH_REMOVE, NULL);
    }

    LWLockRelease(rel_dek_lock);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_evict_db — flush THIS database's cached DEKs
 *
 * OPENSSL_cleanse every dek[]/prev_dek[] belonging to MyDatabaseId and drop
 * the entries.  The pg_vault_tde_catalog rows are NOT removed; DEKs are
 * reloaded from the catalog on the next pg_vault_tde_kms_get_rel_dek() call.
 *
 * This is what the administrative commands actually mean, because everything
 * they act on is per-database: pg_vault_tde_wallet_lock() locks this
 * database's wallet (/var/lib/pg_vault_tde/<db_oid>/wallet.p12), and
 * pg_vault_tde_rotate_kek() rewraps this database's pg_vault_tde_catalog.
 * Entries belonging to other databases are neither stale nor unreachable, so
 * flushing them only forces unrelated backends into a needless KMS round-trip
 * — or into an outright failure, if their own wallet happens to be locked.
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_evict_db(void)
{
    HASH_SEQ_STATUS  seq;
    TdeRelDekMap    *e;
    long             removed = 0;

    if(!rel_dek_map)
        return;

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);

    /* Removing the current entry mid-scan is supported by dynahash. */
    hash_seq_init(&seq, rel_dek_map);
    while((e = (TdeRelDekMap*) hash_seq_search(&seq)) != NULL)
    {
        if (e->key.dbid != MyDatabaseId)
            continue;

        OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
        OPENSSL_cleanse(e->prev_dek, TDE_DEK_LEN);
        hash_search(rel_dek_map, &e->key, HASH_REMOVE, NULL);
        removed++;
    }

    LWLockRelease(rel_dek_lock);

    ereport(LOG,
            errmsg("pg_vault_tde: %ld DEK(s) evicted from the shared memory "
                   "cache for database %u", removed, MyDatabaseId));
}


/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_cache_entries — cached DEKs, all databases
 *
 * The count is cluster-wide because the cache is: entries are keyed by
 * (dbid, relid) in one shared segment, so pg_vault_tde.max_encrypted_relations
 * is a budget shared by every database.  A caller that fills the cache in bulk
 * (the startup preload) compares this against the GUC to stop before it starts
 * spending KMS round-trips it cannot memoise.
 * -------------------------------------------------------------------------*/
long
pg_vault_tde_catalog_cache_entries(void)
{
    long n;

    if (!rel_dek_map)
        return 0;

    LWLockAcquire(rel_dek_lock, LW_SHARED);
    n = hash_get_num_entries(rel_dek_map);
    LWLockRelease(rel_dek_lock);

    return n;
}


/* -------------------------------------------------------------------------
 * tde_rotation_xact_callback — end the rotation with its transaction
 *
 * COMMIT runs once the transaction is durable and visible but before its locks
 * are released, so the writers queued behind the rotation's lock find the new
 * key already current when they wake.  ABORT puts the outgoing key back.
 * Neither may raise an error.  An entry evicted meanwhile is simply absent:
 * the next access reloads it from the catalog, which is right either way.
 * -------------------------------------------------------------------------*/
static void
tde_rotation_xact_callback(XactEvent event, void *arg)
{
    bool             committed;
    TdeRelDekMap    *e;
    TdeRelDekMapKey  search_key;

    if (!tde_rotation.active)
        return;

    if (event == XACT_EVENT_COMMIT)
        committed = true;
    else if (event == XACT_EVENT_ABORT)
        committed = false;
    else
        return;

    if (rel_dek_map)
    {
        tde_rel_dek_key(&search_key, tde_rotation.relid);

        LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);
        e = (TdeRelDekMap*) hash_search(rel_dek_map, &search_key, HASH_FIND, NULL);
        if (e)
        {
            if (committed && tde_rotation.new_valid)
            {
                memcpy(e->dek, tde_rotation.new_dek, TDE_DEK_LEN);
                e->generation = tde_rotation.new_gen;
                memcpy(e->prev_dek, tde_rotation.old_dek, TDE_DEK_LEN);
                e->prev_dek_valid = true;
            }
            else
            {
                memcpy(e->dek, tde_rotation.old_dek, TDE_DEK_LEN);
                e->generation = tde_rotation.old_gen;
            }
            e->dek_valid = true;
            e->rotating  = false;
            /* Both keys came from this node's own catalog, not a replay. */
            e->loaded_in_recovery = false;
        }
        LWLockRelease(rel_dek_lock);
    }

    OPENSSL_cleanse(&tde_rotation, sizeof(tde_rotation));
}

void pg_vault_tde_catalog_zero_rel_dek(Oid relid)
{
    Oid              effective_relid = resolve_effective_relid(relid);
    unsigned char    outgoing_dek[TDE_DEK_LEN];
    uint64           outgoing_gen;
    TdeRelDekMap    *e;
    TdeRelDekMapKey  search_key;
    bool             demoted;
    bool             busy;

    if (!rel_dek_map)
        return;

    if (tde_rotation.active)
        ereport(ERROR,
                errmsg("pg_vault_tde: a rotation of relid=%u is already open "
                       "in this transaction", tde_rotation.relid));

    /* Registered before anything changes, so every exit path reaches it. */
    if (!tde_rotation_callback_registered)
    {
        RegisterXactCallback(tde_rotation_xact_callback, NULL);
        tde_rotation_callback_registered = true;
    }

    /*
     * Recover the outgoing DEK BEFORE touching the cache, and unconditionally.
     *
     * Once pg_vault_tde_catalog_update_rel_dek() overwrites the catalog row,
     * this backend's copy and prev_dek[] are the only ones left, and every
     * pre-rotation tuple needs it.  A cold entry is not exotic: it is the
     * normal state after a restart, and after wallet_lock() or wallet_unlock(),
     * which evict.  pg_vault_tde_kms_get_rel_dek_gen() is a plain LW_SHARED hit
     * when the entry is warm and an unwrap from the catalog when it is not; it
     * takes rel_dek_lock itself, so it has to run before the lock below.
     */
    if (!pg_vault_tde_kms_get_rel_dek_gen(effective_relid, outgoing_dek,
                                          TDE_DEK_LEN, &outgoing_gen))
        ereport(ERROR,
                errmsg("pg_vault_tde: cannot rotate relid=%u: its current DEK "
                       "is neither cached nor recoverable from the catalog",
                       effective_relid));

    tde_rel_dek_key(&search_key, effective_relid);

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);

    e = (TdeRelDekMap*) hash_search(rel_dek_map, &search_key, HASH_FIND, NULL);
    busy    = (e != NULL && e->rotating);
    demoted = (e != NULL && !e->rotating);
    if (demoted)
    {
        /*
         * From here until the transaction ends nobody installs a current key
         * (tde_rel_dek_cache_store) and everyone but this backend keeps
         * encrypting and decrypting with the outgoing one, which is what the
         * catalog shows them.  generation stays the outgoing key's: the new
         * generation is written by a transaction that may still abort, and
         * shared memory does not roll back.
         */
        memcpy(e->prev_dek, outgoing_dek, TDE_DEK_LEN);
        OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
        e->dek_valid      = false;
        e->prev_dek_valid = true;
        e->generation     = outgoing_gen;
        e->rotating       = true;
    }

    LWLockRelease(rel_dek_lock);

    if (!demoted)
    {
        OPENSSL_cleanse(outgoing_dek, TDE_DEK_LEN);

        if (busy)
            ereport(ERROR,
                    errmsg("pg_vault_tde: relid=%u is already being rotated",
                           effective_relid));

        /*
         * get_rel_dek_gen() installed the entry a moment ago, so this only
         * fires if a concurrent wallet_lock()/rotate_kek()/DROP raced us.
         */
        ereport(ERROR,
                errmsg("pg_vault_tde: DEK cache entry for relid=%u was evicted "
                       "while starting a rotation; retry the rotation",
                       effective_relid));
    }

    tde_rotation.active    = true;
    tde_rotation.relid     = effective_relid;
    memcpy(tde_rotation.old_dek, outgoing_dek, TDE_DEK_LEN);
    tde_rotation.old_gen   = outgoing_gen;
    tde_rotation.new_valid = false;

    OPENSSL_cleanse(outgoing_dek, TDE_DEK_LEN);

    ereport(LOG,
            errmsg("pg_vault_tde: relid=%u DEK demoted to prev_dek; "
                   "awaiting the new DEK", effective_relid));
}



bool
pg_vault_tde_catalog_rewrap_all(void)
{
    Oid               ext_ns;
    ScanKeyData       scan_key;
    SysScanDesc       scan;
    Oid               rel_oid;
    Relation          catalog_rel;
    TupleDesc         tup_desc;
    HeapTuple         old_tuple;
    HeapTuple         new_tuple;
    CatalogIndexState indstate;
    MemoryContext     old_ctx;
    MemoryContext     tuple_ctx;
    const TdeKmsProvider *kms;

    /*
     * Resolve (and lazily initialise) the provider before opening the catalog:
     * init() may ereport, and doing so with no relation lock held keeps the
     * error path trivial.
     */
    kms = tde_kms_provider();

    if (!kms)
        ereport(ERROR, errmsg("pg_vault_tde: no active KMS provider — cannot rewrap"));

    /*
     * Warn when the local wallet may be shared between databases.
     *
     * A rewrap covers exactly one database: it walks pg_vault_tde_catalog,
     * which CREATE EXTENSION creates separately in each database and which no
     * backend can read across a database boundary.  Since 1.7.2 the local
     * wallet keeps every KEK version (PSQLE-185), so the other databases'
     * DEKs stay readable under the version they were wrapped with — but they
     * are not re-wrapped: they move to the new KEK only when each of those
     * databases rotates too.  Before 1.7.2 the file held one KEK and the first
     * database to rotate stranded all the others.
     *
     * A WARNING rather than an ERROR: setting wallet_path is legitimate for a
     * single-database cluster.  The message carries its own filter — a DBA
     * who set a per-database path knows at once that no other database uses
     * this file.
     */
    if (pg_vault_tde_kms_provider != NULL &&
        strcmp(pg_vault_tde_kms_provider, "local") == 0 &&
        pg_vault_tde_local_wallet_is_overridden())
        ereport(WARNING,
                errmsg("pg_vault_tde: this rewrap covers only database %u",
                       MyDatabaseId),
                errdetail("pg_vault_tde.wallet_path points somewhere other than "
                          "this database's default "
                          "/var/lib/pg_vault_tde/%u/wallet.p12, and the new KEK "
                          "version is added to that file for every database "
                          "reading it.",
                          MyDatabaseId),
                errhint("Any other database using this wallet keeps its DEKs "
                        "under the previous KEK version, still readable, until "
                        "it rotates too; run the rotation there as well."));

    ext_ns  = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));
    rel_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);

    if (!OidIsValid(ext_ns) || !OidIsValid(rel_oid))
        ereport(ERROR, errmsg("pg_vault_tde: catalog table pg_vault_tde_catalog absent"));

    /*
     * MemoryContext per-tuple: evita frammentazione e overhead di heap_freetuple
     * su molte iterazioni.
     */
    tuple_ctx = AllocSetContextCreate(CurrentMemoryContext,
                                      "rewrap-all-tuple-ctx",
                                      ALLOCSET_DEFAULT_SIZES);

    catalog_rel = table_open(rel_oid, ShareRowExclusiveLock);
    tup_desc    = RelationGetDescr(catalog_rel);
    indstate    = CatalogOpenIndexes(catalog_rel);

    ScanKeyInit(&scan_key, Anum_pg_vault_tde_kms_provider,
                BTEqualStrategyNumber, F_TEXTEQ,
                CStringGetTextDatum(pg_vault_tde_kms_provider));

    scan = systable_beginscan(catalog_rel, InvalidOid, false,
                              NULL, 1, &scan_key);

    while (HeapTupleIsValid(old_tuple = systable_getnext(scan)))
    {
        bytea        *wdek_bytea;
        bool          is_null[CATALOG_NATTS];
        Datum         values[CATALOG_NATTS];
        bool          replaces[CATALOG_NATTS];
        unsigned char new_wrapped[TDE_WRAPPED_DEK_MAX_LEN];
        int           new_wrapped_len;
        bytea        *new_wdek_b;
        Oid           relid;

        MemoryContextReset(tuple_ctx);

        heap_deform_tuple(old_tuple, tup_desc, values, is_null);

        if (is_null[Anum_pg_vault_tde_wrapped_dek - 1])
        {
            continue;
        }

        wdek_bytea = DatumGetByteaPP(values[Anum_pg_vault_tde_wrapped_dek - 1]);
        relid      = DatumGetObjectId(values[Anum_pg_vault_tde_relid - 1]);

        old_ctx = MemoryContextSwitchTo(tuple_ctx);

        new_wrapped_len = sizeof(new_wrapped);

        PG_TRY();
        {
            if (!kms->rewrap_dek(
                        (unsigned char *) VARDATA_ANY(wdek_bytea),
                        VARSIZE_ANY_EXHDR(wdek_bytea),
                        new_wrapped, &new_wrapped_len))
                ereport(ERROR,
                        (errmsg("pg_vault_tde: rewrap failed for relid %u",
                                relid)));

            new_wdek_b = (bytea *) palloc(VARHDRSZ + new_wrapped_len);
            SET_VARSIZE(new_wdek_b, VARHDRSZ + new_wrapped_len);
            memcpy(VARDATA(new_wdek_b), new_wrapped, new_wrapped_len);

            memset(replaces, 0, sizeof(replaces));
            replaces[Anum_pg_vault_tde_wrapped_dek - 1] = true;
            values[Anum_pg_vault_tde_wrapped_dek - 1]   = PointerGetDatum(new_wdek_b);
            is_null[Anum_pg_vault_tde_wrapped_dek - 1]  = false;

            new_tuple = heap_modify_tuple(old_tuple, tup_desc, values, is_null, replaces);
            CatalogTupleUpdateWithInfo(catalog_rel, &old_tuple->t_self,
                                       new_tuple, indstate);

            OPENSSL_cleanse(new_wrapped, new_wrapped_len);
        }
        PG_CATCH();
        {
            OPENSSL_cleanse(new_wrapped, sizeof(new_wrapped));
            MemoryContextSwitchTo(old_ctx);
            systable_endscan(scan);
            CatalogCloseIndexes(indstate);
            table_close(catalog_rel, ShareRowExclusiveLock);
            MemoryContextDelete(tuple_ctx);
            PG_RE_THROW();
        }
        PG_END_TRY();

        MemoryContextSwitchTo(old_ctx);
    }

    MemoryContextDelete(tuple_ctx);
    systable_endscan(scan);
    CatalogCloseIndexes(indstate);
    table_close(catalog_rel, ShareRowExclusiveLock);

    return true;
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_read_all_wrapped — snapshot of all wrapped DEKs
 * for the physical-backup key sealing (see pg_vault_tde_seal.c).
 * -------------------------------------------------------------------------*/

int
pg_vault_tde_catalog_read_all_wrapped(TdeCatalogSealRow **rows_out)
{
    Oid          ext_ns;
    Oid          catalog_oid;
    Oid          catalog_idx;
    Relation     catalog_rel;
    TupleDesc    tupdesc;
    SysScanDesc  scan;
    HeapTuple    tuple;
    TdeCatalogSealRow *rows;
    int          nrows = 0;
    int          cap = 16;
    
    ext_ns = get_extension_schema(
                get_extension_oid(pg_vault_tde_extension_name, true));
    if (!OidIsValid(ext_ns))
        ereport(ERROR, errmsg("pg_vault_tde: extension schema not found"));

    catalog_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);
    if (!OidIsValid(catalog_oid))
        ereport(ERROR, errmsg("pg_vault_tde_catalog not found"));
    catalog_idx = get_relname_relid("pg_vault_tde_catalog_pkey", ext_ns);

    rows = palloc(cap * sizeof(TdeCatalogSealRow));

    catalog_rel = table_open(catalog_oid, AccessShareLock);
    tupdesc     = RelationGetDescr(catalog_rel);

    /* 0 scan keys on the pkey index = full scan in relid order */
    scan = systable_beginscan(catalog_rel, catalog_idx, true,
                            NULL, 0, NULL);

    while (HeapTupleIsValid(tuple = systable_getnext(scan)))
    {
        Datum  d;
        bool   isnull;
        bytea *wdek_src;
        TdeCatalogSealRow *row;

        d = heap_getattr(tuple, Anum_pg_vault_tde_wrapped_dek,
                        tupdesc, &isnull);
        if (isnull)
            continue;               /* no wrapped DEK yet: skip */

        if (nrows == cap)
        {
            cap *= 2;
            rows = repalloc(rows, cap * sizeof(TdeCatalogSealRow));
        }
        row = &rows[nrows];

        /* Copy while the buffer page is still pinned by the scan. */
        wdek_src = DatumGetByteaPP(d);
        row->wrapped_dek = (bytea *) palloc(VARHDRSZ + VARSIZE_ANY_EXHDR(wdek_src));
        SET_VARSIZE(row->wrapped_dek, VARHDRSZ + VARSIZE_ANY_EXHDR(wdek_src));
        memcpy(VARDATA(row->wrapped_dek), VARDATA_ANY(wdek_src),
                VARSIZE_ANY_EXHDR(wdek_src));
    
        d = heap_getattr(tuple, Anum_pg_vault_tde_relid, tupdesc, &isnull);
        row->relid = DatumGetObjectId(d);

        d = heap_getattr(tuple, Anum_pg_vault_tde_generation, tupdesc, &isnull);
        row->generation = isnull ? 0 : (uint64) DatumGetInt64(d);

        d = heap_getattr(tuple, Anum_pg_vault_tde_kms_provider, tupdesc, &isnull);
        row->kms_provider = isnull ? pstrdup("") : text_to_cstring(DatumGetTextPP(d));
    
        nrows++;
    }

    systable_endscan(scan);
    table_close(catalog_rel, AccessShareLock);

    *rows_out = (nrows > 0) ? rows : NULL;
    if (nrows == 0)
        pfree(rows);
    return nrows;
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_upsert_row — import one sealed-bundle row
 * (insert by relid, or in-place update of an existing entry).
 *
 * Not safe to run concurrently with another writer on the SAME relid (an
 * online rotation via pg_vault_tde_rotate_online(), or the DDL hook
 * registering a brand-new table): this is scan-then-branch, not an atomic
 * upsert, so two concurrent writers can both miss each other's row and
 * collide.  Postgres's own MVCC checks catch it — heap_update()/the unique
 * index raise "tuple concurrently updated" or a duplicate-key error rather
 * than silently losing a write — so unseal_keys() aborts cleanly and can be
 * re-run once the other writer is done.  Deliberately not retried here: see
 * the README "Key-rotation note".
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_upsert_row(Oid relid, uint64 generation,
                                bytea *wrapped_dek, const char *kms_provider)
{   
    Oid          ext_ns;
    Oid          catalog_oid;
    Oid          catalog_idx;
    Relation     rel;
    TupleDesc    tup_desc;
    ScanKeyData  scan_key;
    SysScanDesc  scan;
    HeapTuple    old_tuple;
    HeapTuple    new_tuple;
    Datum        values[CATALOG_NATTS];
    bool         isnull[CATALOG_NATTS];
    
    ext_ns = get_extension_schema(
                get_extension_oid(pg_vault_tde_extension_name, true));
    if (!OidIsValid(ext_ns))
        ereport(ERROR, errmsg("pg_vault_tde: extension schema not found"));
    
    catalog_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);
    if (!OidIsValid(catalog_oid))
        ereport(ERROR, errmsg("pg_vault_tde_catalog not found"));
    catalog_idx = get_relname_relid("pg_vault_tde_catalog_pkey", ext_ns);
    
    rel = table_open(catalog_oid, RowExclusiveLock);
    tup_desc = RelationGetDescr(rel);
    
    ScanKeyInit(&scan_key, Anum_pg_vault_tde_relid, BTEqualStrategyNumber,
                F_OIDEQ, ObjectIdGetDatum(relid));
    scan = systable_beginscan(rel, catalog_idx, true,
                            NULL, 1, &scan_key);
    old_tuple = systable_getnext(scan);

    memset(values, 0,     sizeof(values));
    memset(isnull, false, sizeof(isnull));

    values[Anum_pg_vault_tde_generation-1]   = Int64GetDatum((int64) generation);
    values[Anum_pg_vault_tde_wrapped_dek-1]  = PointerGetDatum(wrapped_dek);
    values[Anum_pg_vault_tde_kms_provider-1] = CStringGetTextDatum(kms_provider);
    values[Anum_pg_vault_tde_updated_at-1]   =
        TimestampTzGetDatum(GetCurrentTransactionStartTimestamp());
    
    if (HeapTupleIsValid(old_tuple))
    {
        bool do_replace[CATALOG_NATTS];
    
        memset(do_replace, false, sizeof(do_replace));
        do_replace[Anum_pg_vault_tde_generation-1]   = true;
        do_replace[Anum_pg_vault_tde_wrapped_dek-1]  = true;
        do_replace[Anum_pg_vault_tde_kms_provider-1] = true;
        do_replace[Anum_pg_vault_tde_updated_at-1]   = true;

        new_tuple = heap_modify_tuple(old_tuple, tup_desc,
                                    values, isnull, do_replace);
        CatalogTupleUpdate(rel, &old_tuple->t_self, new_tuple);
    }
    else
    {
        values[Anum_pg_vault_tde_relid-1] = ObjectIdGetDatum(relid);
        values[Anum_pg_vault_tde_created_at-1] =
            TimestampTzGetDatum(GetCurrentTransactionStartTimestamp());
            
        new_tuple = heap_form_tuple(tup_desc, values, isnull);
        CatalogTupleInsert(rel, new_tuple);
    }

    systable_endscan(scan);
    table_close(rel, RowExclusiveLock);
    heap_freetuple(new_tuple);
}


PG_FUNCTION_INFO_V1(pg_vault_tde_rotate_kek_sql);
PGDLLEXPORT Datum
pg_vault_tde_rotate_kek_sql(PG_FUNCTION_ARGS)
{
    const TdeKmsProvider *kms;

    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("pg_vault_tde_rotate_kek requires superuser")));

    kms = tde_kms_provider();

    if (!kms)
        ereport(ERROR,
                errmsg("pg_vault_tde: no active KMS provider — cannot rotate KEK"));

    if (!kms->prepare_kek_rotation())
        ereport(ERROR,
                (errmsg("pg_vault_tde: prepare_kek_rotation failed")));

    PG_TRY();
    {
        pg_vault_tde_catalog_rewrap_all();
        kms->commit_kek_rotation();

        tde_audit(KMS_KEK_ROTATE, NULL, true);
    }
    PG_CATCH();
    {
        tde_audit(KMS_KEK_ROTATE, NULL, false);
        
        PG_RE_THROW();
    }
    PG_END_TRY();

    pg_vault_tde_catalog_evict_db();
    PG_RETURN_VOID();
}
