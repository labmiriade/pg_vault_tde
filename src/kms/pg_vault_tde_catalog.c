/*
 * pg_vault_tde_catalog.c — Per-table DEK catalog + shmem cache (v1.5)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * OVERVIEW:
 * ---------
 * This module manages the TdeRelDekMap shared-memory hash table (an HTAB
 * created with ShmemInitHash, keyed by relid) and provides the
 * pg_vault_tde_kms_get_rel_dek() accessor used by all TAM encrypt/decrypt
 * paths in v1.5+.  A single LWLock from the "TdeRelDekMap" named tranche
 * guards the whole table.
 *
 * HOT PATH:
 * ---------
 * Every call to tde_encrypt_heap_tuple / tde_decrypt_heap_tuple goes through
 * pg_vault_tde_kms_get_rel_dek().  The fast path is:
 *   1. Acquire LW_SHARED on rel_dek_lock
 *   2. hash_search(HASH_FIND) for the relid key (O(1) average)
 *   3. Copy DEK into caller's stack buffer
 *   4. Release LW_SHARED
 *
 * Cache miss (first access after startup, or after key rotation):
 *   1. Read wrapped_dek from pg_vault_tde_catalog via direct catalog scan
 *      (table_open + systable_beginscan — no SPI, safe inside TAM callbacks)
 *   2. Call tde_active_kms_provider->unwrap_dek()
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
    RequestNamedLWLockTranche("TdeRelDekMap", 1);  /* Lock outside of the map */
}

bool tde_catalog_cache_entry(Oid relid, TdeRelDekMap* out_entry)
{
    TdeRelDekMap *e = NULL;
    LWLockAcquire(rel_dek_lock, LW_SHARED);

    e = (TdeRelDekMap*) hash_search(rel_dek_map, &relid, HASH_FIND, NULL);
    if(e && e->dek_valid)
        memcpy(out_entry, e, sizeof(TdeRelDekMap));
    else 
        e = NULL;  
         
    LWLockRelease(rel_dek_lock);

    return e != NULL ? true : false;
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

    rel_dek_lock = &GetNamedLWLockTranche("TdeRelDekMap")[0].lock;

    MemSet(&info, 0, sizeof(info));
    info.keysize = sizeof(Oid);
    info.entrysize = sizeof(TdeRelDekMap);

    rel_dek_map = ShmemInitHash("TdeRelDekMap",
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

    scan = systable_beginscan(pg_depend_rel, DependDependerIndexId, true, GetTransactionSnapshot(), 1, &scan_key);

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
                              GetTransactionSnapshot(), 1, &scan_key);

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
    TdeRelDekMap *stored_slot = NULL;
    bool found;

    if(!rel_dek_map) 
        ereport(ERROR, errmsg("pg_vault_tde: error: shmem cache is null, the extension must be loaded via shared_preload_libraries"));

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);
    stored_slot = (TdeRelDekMap*) hash_search(rel_dek_map, &relid, HASH_ENTER_NULL, &found);

    if(!stored_slot){
        LWLockRelease(rel_dek_lock);
        OPENSSL_cleanse(dek, TDE_DEK_LEN);

        ereport(ERROR, 
                errmsg("pg_vault_tde: DEK cache full (capacity=%d); "
                         "consider increasing pg_vault_tde.max_encrypted_relations.",
                         pg_vault_tde_max_encrypted_relations));
    }

    if(found && stored_slot->dek_valid)
    {
        LWLockRelease(rel_dek_lock);
        return false;
    }
    else if(found && !stored_slot->dek_valid && stored_slot->prev_dek_valid)
    {
        memcpy(stored_slot->dek, dek, TDE_DEK_LEN);
        stored_slot->dek_valid = true; 
        
        LWLockRelease(rel_dek_lock);
        return true;
    }

    if(!found)
    {
        stored_slot->prev_dek_valid = false;
        MemSet(stored_slot->prev_dek, 0, TDE_DEK_LEN);
    }

    memcpy(stored_slot->dek, dek, TDE_DEK_LEN);
    stored_slot->dek_valid = true; 
    stored_slot->generation = generation;

    LWLockRelease(rel_dek_lock);
    return true;
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_kms_get_rel_dek — hot-path DEK accessor (v1.5+)
 *
 * Resolves effective OID, checks shmem cache (fast path), on miss fetches
 * from pg_vault_tde_catalog + KMS unwrap, stores via tde_rel_dek_cache_store.
 * -------------------------------------------------------------------------*/
bool
pg_vault_tde_kms_get_rel_dek(Oid relid,
                               unsigned char *dek_out, int dek_len)
{
    bool  found = false;
    Oid   effective_relid;
    TdeRelDekMap *e;

    Assert(dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

    effective_relid = resolve_effective_relid(relid);

    /* ---- Fast path: LW_SHARED cache lookup ---- */
    if(!rel_dek_map) 
        ereport (ERROR, errmsg("pg_vault_tde: error: shmem cache is null, the extension must be loaded via shared_preload_libraries"));

    LWLockAcquire(rel_dek_lock, LW_SHARED);
    e = (TdeRelDekMap*) hash_search(rel_dek_map, &effective_relid, HASH_FIND, NULL);

    if (e && e->dek_valid)
    {
        memcpy(dek_out, e->dek, TDE_DEK_LEN);
        found = true;
    }
    
    LWLockRelease(rel_dek_lock);

    if (found)
        return true;

    /* ---- Slow path: catalog scan + KMS unwrap ---- */
    {
        TdeCatalogRow row;
        unsigned char dek_temp[TDE_DEK_LEN];
        bool          unwrap_ok;

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

        if (!tde_active_kms_provider || !tde_active_kms_provider->unwrap_dek)
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: no active KMS provider for "
                           "unwrap_dek (relid=%u)", effective_relid));
            return false;
        }

        {
            int dek_temp_len = TDE_DEK_LEN;
            unwrap_ok = tde_active_kms_provider->unwrap_dek(
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

        /* Store the DEK for next calls */
        tde_rel_dek_cache_store(effective_relid, dek_temp, row.generation);
        
        OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
        return true;
    }
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_kms_get_rel_prev_dek — fallback DEK during rotation
 * -------------------------------------------------------------------------*/
bool
pg_vault_tde_kms_get_rel_prev_dek(Oid relid,
                                   unsigned char *prev_dek_out, int dek_len)
{
    bool found = false;
    Oid effective_relid = resolve_effective_relid(relid);
    TdeRelDekMap *e;

    Assert(prev_dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

    if (!rel_dek_map)
        return false;

    LWLockAcquire(rel_dek_lock, LW_SHARED);
    e = (TdeRelDekMap*) hash_search(rel_dek_map, &effective_relid, HASH_FIND, NULL);

    if (e && e->prev_dek_valid)
    {
        memcpy(prev_dek_out, e->prev_dek, TDE_DEK_LEN);
        found = true;
    }
    
    LWLockRelease(rel_dek_lock);

    return found; 
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

    if (!tde_active_kms_provider)
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
    if (!tde_active_kms_provider->wrap_dek(dek, TDE_DEK_LEN,
                                            wrapped, &wrapped_len))
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
    scan = systable_beginscan(rel, catalog_idx, true, GetTransactionSnapshot(), 1, &scan_key);

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

    Oid ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));

    Assert(OidIsValid(relid));

    if (!tde_active_kms_provider)
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
    if (!tde_active_kms_provider->wrap_dek(dek, TDE_DEK_LEN,
                                            wrapped, &wrapped_len))
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        ereport(ERROR,
                errmsg("pg_vault_tde: wrap_dek failed for relid=%u", relid));
    }

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
                              GetTransactionSnapshot(), 1, &scan_key);

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
        values[Anum_pg_vault_tde_generation-1] = Int64GetDatum(gen_isnull ? 2 : old_gen + 1);
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
    scan = systable_beginscan(rel, catalog_idx, true, GetTransactionSnapshot(), 1, &scan_key);

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
    bool found = false;
    TdeRelDekMap *e;

    if (!rel_dek_map)
        return;

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);

    e = (TdeRelDekMap*) hash_search(rel_dek_map, &relid, HASH_FIND, &found);
    if (found)
    {
        OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
        OPENSSL_cleanse(e->prev_dek, TDE_DEK_LEN);
        hash_search(rel_dek_map, &relid, HASH_REMOVE, NULL);
    }

    LWLockRelease(rel_dek_lock);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_evict_all — flush all cached DEKs from shared memory
 *
 * OPENSSL_cleanse every dek[] and prev_dek[] buffer, then reset used = 0.
 * The pg_vault_tde_catalog rows are NOT removed; DEKs are reloaded from
 * the catalog on the next pg_vault_tde_kms_get_rel_dek() call.
 *
 * Used by pg_vault_tde_wallet_lock() to ensure plaintext key material does
 * not persist in shared memory after the wallet is administratively locked.
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_evict_all(void)
{
    HASH_SEQ_STATUS seq;
    TdeRelDekMap    *e; 

    if(!rel_dek_map)
        return;

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);
    
    hash_seq_init(&seq, rel_dek_map);
    while((e = (TdeRelDekMap*) hash_seq_search(&seq)) != NULL)
    {
        OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
        OPENSSL_cleanse(e->prev_dek, TDE_DEK_LEN);
        hash_search(rel_dek_map, &e->relid, HASH_REMOVE, NULL);
    }

    LWLockRelease(rel_dek_lock);

    ereport(LOG, errmsg("pg_vault_tde: all DEKs evicted from shared memory cache"));
}

uint64
pg_vault_tde_catalog_get_rel_generation(Oid relid)
{
    uint64 gen = 0;
    Oid    effective_relid;
    TdeRelDekMap* e;

    if(!OidIsValid(relid) || !rel_dek_map)
        return 0;

    effective_relid = resolve_effective_relid(relid);

    LWLockAcquire(rel_dek_lock, LW_SHARED);

    e = (TdeRelDekMap*) hash_search(rel_dek_map, &effective_relid, HASH_FIND, NULL);
    if(e) 
        gen = e->generation;

    LWLockRelease(rel_dek_lock);

    if (gen > 0)
        return gen;

    /* Cache miss (e.g. after restart): read generation from the catalog. */
    {
        TdeCatalogRow row;

        if (tde_catalog_read_row(effective_relid, &row) &&
            row.found && !row.generation_isnull && row.generation > 0)
            return row.generation;
    }

    return 1;
}

void pg_vault_tde_catalog_zero_rel_dek(Oid relid)
{
    Oid effective_relid = resolve_effective_relid(relid);
    TdeRelDekMap *e;

    if (!rel_dek_map)
        return;

    LWLockAcquire(rel_dek_lock, LW_EXCLUSIVE);
    
    e = (TdeRelDekMap*) hash_search(rel_dek_map, &effective_relid, HASH_FIND, NULL);
    if (e)
    {
        memcpy(e->prev_dek, e->dek, TDE_DEK_LEN);
        OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
        e->dek_valid      = false;
        e->prev_dek_valid = true;
        e->generation++;
    }
    LWLockRelease(rel_dek_lock);

    ereport(LOG, errmsg("pg_vault_tde: Old dek saved and setted dek invalid"));
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
                              GetTransactionSnapshot(), 1, &scan_key);

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
            if (!tde_active_kms_provider->rewrap_dek(
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
                            GetTransactionSnapshot(), 0, NULL);

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
                            GetTransactionSnapshot(), 1, &scan_key);
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
    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("pg_vault_tde_rotate_kek requires superuser")));

    if (!tde_active_kms_provider->prepare_kek_rotation())
        ereport(ERROR,
                (errmsg("pg_vault_tde: prepare_kek_rotation failed")));

    PG_TRY();
    {
        pg_vault_tde_catalog_rewrap_all();
        tde_active_kms_provider->commit_kek_rotation();

        tde_audit(KMS_KEK_ROTATE, NULL, true);
    }
    PG_CATCH();
    {
        tde_audit(KMS_KEK_ROTATE, NULL, false);
        
        PG_RE_THROW();
    }
    PG_END_TRY();

    pg_vault_tde_catalog_evict_all();
    PG_RETURN_VOID();
}
