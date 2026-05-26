/*
 * pg_vault_tde_catalog.c — Per-table DEK catalog + shmem cache (v1.5)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * OVERVIEW:
 * ---------
 * This module manages the TdeRelDekCache shared-memory array and provides
 * the pg_vault_tde_kms_get_rel_dek() accessor used by all TAM encrypt/decrypt
 * paths in v1.5+.
 *
 * HOT PATH:
 * ---------
 * Every call to tde_encrypt_heap_tuple / tde_decrypt_heap_tuple goes through
 * pg_vault_tde_kms_get_rel_dek().  The fast path is:
 *   1. Acquire LW_SHARED on TdeRelDekCache.lock
 *   2. Linear-scan entries[] for relid match (< 1 µs for <= 1024 tables)
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
#include "src/include/pg_vault_tde_guc.h"
#include "src/kms/pg_vault_tde_kms_provider.h"


/* -------------------------------------------------------------------------
 * Module-level shmem pointer
 * -------------------------------------------------------------------------*/
static TdeRelDekCache *rel_dek_cache = NULL;

/* -------------------------------------------------------------------------
 * Shmem sizing helpers
 * -------------------------------------------------------------------------*/

/*
 * tde_rel_dek_cache_size — size of the TdeRelDekCache shmem segment.
 *
 * Called from shmem_request_hook.  At that point the GUC has been read but
 * shmem allocation has not happened yet.
 */
static Size
tde_rel_dek_cache_size(int capacity)
{
    return offsetof(TdeRelDekCache, entries)
           + (Size) capacity * sizeof(TdeRelDekEntry);
}

/*
 * tde_rel_dek_cache_store_fallback
 *
 * Cache the global fallback DEK under a specific relid so that subsequent
 * calls to pg_vault_tde_kms_get_rel_dek hit the fast (no-SPI) shmem path.
 *
 * Called when pg_vault_tde_catalog has no wrapped_dek entry for relid and
 * we fell back to the v1.4 global DEK.  Without this caching, every decrypt
 * call would re-enter the SPI catalog lookup — which fails when called during
 * CommitTransaction (e.g., PostgreSQL materialising a WITH HOLD cursor).
 *
 * The cached entry uses the global DEK as-is.  If the global DEK is later
 * rotated, pg_vault_tde_catalog_evict_rel() should be called for this relid
 * to force a fresh lookup on the next decrypt.  This is a v1.5 simplification;
 * proper per-entry generation tracking is deferred to v1.6.
 */
static void
tde_rel_dek_cache_store_fallback(Oid relid, const unsigned char *dek)
{
    TdeRelDekEntry *empty_slot = NULL;
    int             j;

    if (!rel_dek_cache)
        return;

    LWLockAcquire(&rel_dek_cache->lock, LW_EXCLUSIVE);
    for (j = 0; j < rel_dek_cache->capacity; j++)
    {
        TdeRelDekEntry *e = &rel_dek_cache->entries[j];

        if (e->relid == relid)
        {
            /* Another backend already cached an entry for this relid */
            LWLockRelease(&rel_dek_cache->lock);
            return;
        }
        if (!empty_slot && e->relid == InvalidOid)
            empty_slot = e;
    }

    if (!empty_slot)
    {
        /* Cache full — skip rather than evicting a potentially-valid entry */
        LWLockRelease(&rel_dek_cache->lock);
        return;
    }

    memcpy(empty_slot->dek, dek, TDE_DEK_LEN);
    empty_slot->relid     = relid;
    empty_slot->dek_valid = true;
    rel_dek_cache->used++;
    LWLockRelease(&rel_dek_cache->lock);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_shmem_request — reserve shmem space (PG 15+ hook)
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_shmem_request(void)
{
    int capacity;

    /*
     * Read the GUC.  The GUC is registered before this hook fires, so
     * pg_vault_tde_max_encrypted_relations is already populated.
     */
    capacity = pg_vault_tde_max_encrypted_relations;
    if (capacity < 64)
        capacity = TDE_REL_DEK_CACHE_DEFAULT;

    RequestAddinShmemSpace(tde_rel_dek_cache_size(capacity));
    RequestNamedLWLockTranche("TdeRelDekCache", 1);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_shmem_init — map shmem and init LWLock
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_shmem_init(void)
{
    int    capacity;
    Size   seg_size;
    bool   found;

    capacity = pg_vault_tde_max_encrypted_relations;
    if (capacity < 64)
        capacity = TDE_REL_DEK_CACHE_DEFAULT;

    seg_size     = tde_rel_dek_cache_size(capacity);
    rel_dek_cache = (TdeRelDekCache *)
        ShmemInitStruct("TdeRelDekCache", seg_size, &found);

    if (!found)
    {
        /*
         * First postmaster backend to initialise this segment.
         * Zero-fill (ShmemInitStruct guarantees this for new segments) and
         * initialise the embedded LWLock.
         *
         * LWLockInitialize takes a pointer INTO the shmem segment — valid
         * across all backends because it is a physical offset, not a
         * virtual-address pointer.
         */
        MemSet(rel_dek_cache, 0, seg_size);
        {
            /*
             * GetNamedLWLockTranche returns a LWLockPadded array; extract the
             * tranche ID from the first slot to initialise our embedded lock.
             */
            LWLockPadded *named_locks = GetNamedLWLockTranche("TdeRelDekCache");
            LWLockInitialize(&rel_dek_cache->lock,
                             named_locks[0].lock.tranche);
        }
        rel_dek_cache->capacity = capacity;
        rel_dek_cache->used     = 0;
    }
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
 * pg_vault_tde_kms_get_rel_dek — hot-path DEK accessor (v1.5 replacement
 * for pg_vault_tde_kms_get_dek with per-table granularity)
 *
 * v1.6 enhancement: if relid is a TOAST table (detected by SPI lookup of
 * relkind), automatically route to the parent table's DEK.
 * This allows TOAST chunks to be encrypted with the same DEK as their parent.
 * -------------------------------------------------------------------------*/
bool
pg_vault_tde_kms_get_rel_dek(Oid relid,
                               unsigned char *dek_out, int dek_len)
{
    int   i;
    bool  found = false;
    Oid   effective_relid = relid;  /* might be remapped from TOAST → parent */
    Oid   relrewrite;
    Assert(dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

    /*
     * v1.6: TOAST table routing.
     * If relid refers to a TOAST table, fetch its parent's OID and use that
     * for DEK lookup instead.  This ensures TOAST chunks are encrypted with
     * the same key as their parent table.
     */
    if (OidIsValid(relid))
    {
        /* If this is a TOAST table, map to parent */
        if(get_rel_relkind(relid) == RELKIND_TOASTVALUE){
            Oid parent_relid = pg_vault_tde_get_parent_relid(relid);
            if (OidIsValid(parent_relid))
                effective_relid = parent_relid;
            /* else: keep relid as-is (invalid parent), let normal path handle error */
        }
        
        /*
         * Check pg_class.relrewrite on effective_relid (not the original
         * relid).  During VACUUM FULL / CLUSTER, PostgreSQL creates a temp
         * table (NewTable) with pg_class.relrewrite = OldTable.relid before
         * invoking relation_copy_for_cluster.  When writing TOAST chunks to
         * NewTable's TOAST relation (T_new), the TOAST routing above remaps
         * effective_relid from T_new → NewTable.  We must then follow
         * NewTable's relrewrite → OldTable so that TOAST chunks are encrypted
         * with OldTable's DEK.  After finish_heap_swap OldTable has no
         * relrewrite (= 0), so reads use OldTable's DEK correctly.
         *
         * BUG if we used relid here: T_new.relrewrite = 0, so the check
         * would be a no-op, TOAST chunks would be encrypted with NewTable's
         * DEK, and every subsequent SELECT would get a GCM authentication
         * failure because the post-swap parent lookup returns OldTable's DEK.
         */
        relrewrite = get_rel_rewrite(effective_relid);
        if(relrewrite != InvalidOid){
            effective_relid = relrewrite;
        }
    }
    
    if (!rel_dek_cache)
    {
        /*
         * Shmem not yet initialised (e.g. called before shmem_startup_hook
         * has run — can happen during early backend startup).  Fall back to
         * the global DEK for backward compatibility with v1.4 tables.
         */
        return pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
    }

    /* ---- Fast path: LW_SHARED cache lookup ---- */
    LWLockAcquire(&rel_dek_cache->lock, LW_SHARED);
    for (i = 0; i < rel_dek_cache->capacity; i++)
    {
        TdeRelDekEntry *e = &rel_dek_cache->entries[i];

        if (e->relid == effective_relid && e->dek_valid)
        {
            memcpy(dek_out, e->dek, TDE_DEK_LEN);
            found = true;
            break;
        }
    }
    LWLockRelease(&rel_dek_cache->lock);

    if (found)
        return true;

    /* ---- Slow path: effective_relid == 0 (global DEK) or cache miss ---- */
    if (effective_relid == InvalidOid)
    {
        /*
         * Backward-compat: relid=0 maps to the v1.4 single global DEK.
         * Read from the old TdeKmsSharedState struct.
         */
        return pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
    }

    /*
     * Cache miss for a named relation.  Fetch the wrapped DEK from
     * pg_vault_tde_catalog via direct catalog scan, unwrap via the active
     * KMS provider, and insert into the shmem cache.
     *
     * We use table_open + systable_beginscan rather than SPI because
     * pg_vault_tde_catalog is a plain heap table (NOT encrypted_heap) and
     * direct access avoids the executor overhead and re-entrancy risks that
     * SPI would introduce inside a TAM callback.
     *
     * NOTE: If the original relid was a TOAST table, effective_relid
     * has been remapped to the parent, so this lookup uses the parent's
     * wrapped_dek entry.
     */
    {
        TupleDesc     tupdesc;
        HeapTuple     tuple;
        bool          isnull = true;
        bool          tuple_found = false;
        Datum         wrapped_datum;
        bytea        *wrapped_bytea;
        unsigned char wrapped_buf[512];
        int           wrapped_len = 0;
        unsigned char dek_temp[TDE_DEK_LEN];
        bool          unwrap_ok;

        ScanKeyData scan_key; 
        SysScanDesc scan;
        Relation catalog_rel;
        Oid catalog_idx;

        /*
         * Guard: pg_vault_tde_catalog only exists after the v1.4→v1.5
         * upgrade.  On vanilla v1.0/v1.4 deployments the table is absent;
         * fall back to the global DEK rather than throwing an ERROR.
         */
        Oid  ext_ns = get_extension_schema(get_extension_oid(pg_vault_tde_extension_name, true));

        if (!OidIsValid(ext_ns) ||
            !OidIsValid(get_relname_relid("pg_vault_tde_catalog", ext_ns)))
        {
            ereport(DEBUG1,
                    errmsg("pg_vault_tde: catalog table absent, "
                            "using global DEK for relid=%u", effective_relid));
            return pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
        }
    

        catalog_rel = table_open(get_relname_relid("pg_vault_tde_catalog", ext_ns), AccessShareLock);
        tupdesc = RelationGetDescr(catalog_rel);

        //systable_beginscan uses index scan on the default B-Tree index created on pg_vault_tde_catalog's pkey
        catalog_idx = get_relname_relid("pg_vault_tde_catalog_pkey", ext_ns);

        ScanKeyInit(&scan_key, Anum_pg_vault_tde_relid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(effective_relid));

        scan = systable_beginscan(catalog_rel, catalog_idx, true, GetTransactionSnapshot(), 1, &scan_key);

        if (HeapTupleIsValid(tuple = systable_getnext(scan)))
        {
            tuple_found = true;
            wrapped_datum = heap_getattr(tuple, Anum_pg_vault_tde_wrapped_dek, tupdesc, &isnull);

            if (!isnull)
            {
                /*
                 * Copy the wrapped DEK bytes into the stack buffer while the
                 * buffer page is still pinned by the scan.  We must not
                 * access wrapped_bytea after systable_endscan() releases the
                 * buffer pin.
                 */
                wrapped_bytea = DatumGetByteaPP(wrapped_datum);
                wrapped_len = VARSIZE_ANY_EXHDR(wrapped_bytea);
                if (wrapped_len <= (int) sizeof(wrapped_buf))
                    memcpy(wrapped_buf, VARDATA_ANY(wrapped_bytea), wrapped_len);
            }
        }

        /*
         * Always close scan and relation before any early return.
         * Returning inside the scan block leaves the relation and its index
         * registered with the ResourceOwner, triggering "resource was not
         * closed" warnings at transaction end.
         */
        systable_endscan(scan);
        table_close(catalog_rel, AccessShareLock);

        /*
         * Handle fallback cases after cleanup: no row found, or
         * wrapped_dek IS NULL (v1.4 tables have no catalog entry).
         *
         * Also populate rel_dek_cache so subsequent calls for this relid
         * take the fast path.  This is critical for WITH HOLD cursor
         * materialisation during CommitTransaction, where SPI cannot be
         * re-entered.  See tde_rel_dek_cache_store_fallback.
         *
         * NOTE (v16: when storing in cache, use effective_relid (which
         * may have been remapped from TOAST → parent).
         */
        if (!tuple_found)
        {
            bool got_dek;

            ereport(DEBUG1,
                    errmsg("pg_vault_tde: no entry on pg_vault_tde_catalog for "
                           "relid=%u, falling back to global DEK", effective_relid));
            got_dek = pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
            if (got_dek)
                tde_rel_dek_cache_store_fallback(effective_relid, (unsigned char *) dek_out);
            return got_dek;
        }

        if (isnull)
        {
            bool got_dek;

            ereport(DEBUG1,
                    errmsg("pg_vault_tde: wrapped_dek IS NULL for "
                           "relid=%u, falling back to global DEK", effective_relid));
            got_dek = pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
            if (got_dek)
                tde_rel_dek_cache_store_fallback(effective_relid, (unsigned char *) dek_out);
            return got_dek;
        }

        if (wrapped_len > (int) sizeof(wrapped_buf))
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: wrapped_dek too large (%d bytes) "
                           "for relid=%u", wrapped_len, relid));
            return false;
        }

        /* Unwrap via the active KMS provider */
        if (!tde_active_kms_provider ||
            !tde_active_kms_provider->unwrap_dek)
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: no active KMS provider for "
                           "unwrap_dek (relid=%u)", relid));
            return false;
        }

        unwrap_ok = tde_active_kms_provider->unwrap_dek(
                        wrapped_buf, wrapped_len,
                        dek_temp, TDE_DEK_LEN);

        OPENSSL_cleanse(wrapped_buf, sizeof(wrapped_buf));

        if (!unwrap_ok)
        {
            OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
            return false;
        }

        /* Insert into shmem cache (LW_EXCLUSIVE) */
        LWLockAcquire(&rel_dek_cache->lock, LW_EXCLUSIVE);
        {
            TdeRelDekEntry *empty_slot = NULL;

            /* Scan for existing entry (another backend may have loaded it) */
            for (i = 0; i < rel_dek_cache->capacity; i++)
            {
                TdeRelDekEntry *e = &rel_dek_cache->entries[i];

                if (e->relid == relid && e->dek_valid)
                {
                    /* Already loaded by another backend — use what's there */
                    memcpy(dek_out, e->dek, TDE_DEK_LEN);
                    OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
                    LWLockRelease(&rel_dek_cache->lock);
                    return true;
                }
                if(e->relid == relid && !e->dek_valid && e->prev_dek_valid)
                {
                    /*
                     * Rotation window: zero_rel_dek set dek_valid=false; the
                     * new catalog row was just written by register_rel.  Load
                     * the new DEK and mark the cache entry valid again so
                     * subsequent calls take the fast path instead of re-reading
                     * the catalog on every single tuple.
                     */
                    memcpy(e->dek, dek_temp, TDE_DEK_LEN);
                    e->dek_valid = true; 
                    OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
                    memcpy(dek_out, e->dek, TDE_DEK_LEN);
                    LWLockRelease(&rel_dek_cache->lock);
                    return true;
                }
                if (!empty_slot && e->relid == InvalidOid)
                    empty_slot = e;
            }

            if (!empty_slot)
            {
                /* Cache full — evict the first non-rotating entry */
                ereport(WARNING,
                        errmsg("pg_vault_tde: DEK cache full (capacity=%d); "
                               "evicting first entry to make room for "
                               "relid=%u.  Consider increasing "
                               "pg_vault_tde.max_encrypted_relations.",
                           rel_dek_cache->capacity, relid));
                empty_slot = &rel_dek_cache->entries[0];
                OPENSSL_cleanse(empty_slot->dek, TDE_DEK_LEN);
                OPENSSL_cleanse(empty_slot->prev_dek, TDE_DEK_LEN);
                rel_dek_cache->used--;
            }

            memcpy(empty_slot->dek, dek_temp, TDE_DEK_LEN);
            OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
            memcpy(dek_out, empty_slot->dek, TDE_DEK_LEN);
            empty_slot->relid     = relid;
            empty_slot->dek_valid = true;
            empty_slot->generation = 1;     /* will be corrected by catalog */
            rel_dek_cache->used++;
        }
        LWLockRelease(&rel_dek_cache->lock);

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
    int  i;
    bool found = false;

    Assert(prev_dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

    if (!rel_dek_cache)
        return false;

    LWLockAcquire(&rel_dek_cache->lock, LW_SHARED);
    for (i = 0; i < rel_dek_cache->capacity; i++)
    {
        TdeRelDekEntry *e = &rel_dek_cache->entries[i];
        if (e->relid == relid && e->prev_dek_valid)
        {
            memcpy(prev_dek_out, e->prev_dek, TDE_DEK_LEN);
            found = true;
            break;
        }
    }
    LWLockRelease(&rel_dek_cache->lock);

    if (found)
        return true;

    /*
     * Per-table prev_dek not found (relid has no catalog entry — v1.4 table
     * using the global DEK).  Fall back to the global prev_dek stored in
     * TdeKmsShmem; this handles the reencrypt_table() path where the caller
     * rotated the global DEK and now needs to re-read old-DEK rows.
     */
    return pg_vault_tde_kms_get_prev_dek((char *) prev_dek_out, dek_len);
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_register_rel — called on CREATE TABLE
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_register_rel(Oid relid, const char *vault_key_name)
{
    unsigned char dek[TDE_DEK_LEN];
    unsigned char wrapped[512];
    int           wrapped_len = sizeof(wrapped);
    char          generated_key_name[64];
    const char   *effective_key_name;
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
    if (!tde_active_kms_provider->generate_dek(dek, TDE_DEK_LEN))
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

    /* Construct key name if not provided */
    if (vault_key_name && vault_key_name[0] != '\0')
        effective_key_name = vault_key_name;
    else
    {
        snprintf(generated_key_name, sizeof(generated_key_name),
                 "pg-tde-rel-%u", relid);
        effective_key_name = generated_key_name;
    }

    catalog_oid = get_relname_relid("pg_vault_tde_catalog", ext_ns);
    if (!OidIsValid(catalog_oid))
        ereport(ERROR, (errmsg("catalog pg_vault_tde_catalog not found")));

    rel = table_open(catalog_oid, RowExclusiveLock);
    tup_desc = RelationGetDescr(rel);

    memset(isnull, false, sizeof(isnull));

    values[Anum_pg_vault_tde_relid-1] = ObjectIdGetDatum(relid);
    values[Anum_pg_vault_tde_key_name-1] = CStringGetTextDatum(effective_key_name);
    values[Anum_pg_vault_tde_generation-1] = Int64GetDatum(pg_vault_tde_kms_get_generation());

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

    ereport(DEBUG1,
            errmsg("pg_vault_tde: %u successufully registered", relid));

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
pg_vault_tde_catalog_update_rel_dek(Oid relid, const char *vault_key_name)
{
    unsigned char dek[TDE_DEK_LEN];
    unsigned char wrapped[512];
    int           wrapped_len = sizeof(wrapped);
    char          generated_key_name[64];
    const char   *effective_key_name;
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
    if (!tde_active_kms_provider->generate_dek(dek, TDE_DEK_LEN))
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

    if (vault_key_name && vault_key_name[0] != '\0')
        effective_key_name = vault_key_name;
    else
    {
        snprintf(generated_key_name, sizeof(generated_key_name),
                 "pg-tde-rel-%u", relid);
        effective_key_name = generated_key_name;
    }

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

    values[Anum_pg_vault_tde_wrapped_dek-1]  = PointerGetDatum(wrapped_bytea);
    values[Anum_pg_vault_tde_generation-1]   = Int64GetDatum(pg_vault_tde_kms_get_generation());
    values[Anum_pg_vault_tde_kms_provider-1] = CStringGetTextDatum(pg_vault_tde_kms_provider);
    values[Anum_pg_vault_tde_key_name-1]     = CStringGetTextDatum(effective_key_name);
    values[Anum_pg_vault_tde_updated_at-1]   = TimestampTzGetDatum(GetCurrentTransactionStartTimestamp());

    do_replace[Anum_pg_vault_tde_wrapped_dek-1]  = true;
    do_replace[Anum_pg_vault_tde_generation-1]   = true;
    do_replace[Anum_pg_vault_tde_kms_provider-1] = true;
    do_replace[Anum_pg_vault_tde_key_name-1]     = true;
    do_replace[Anum_pg_vault_tde_updated_at-1]   = true;

    new_tuple = heap_modify_tuple(old_tuple, tup_desc, values, isnull, do_replace);
    CatalogTupleUpdate(rel, &old_tuple->t_self, new_tuple);

    ereport(DEBUG1,
            errmsg("pg_vault_tde: relid=%u DEK updated in catalog (rotation)",
                   relid));

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

    systable_endscan(scan);
    table_close(rel, RowExclusiveLock);

    ereport(DEBUG1,
            errmsg("pg_vault_tde: deregistered DEK for dropped relid=%u",
                   relid));
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_evict_rel — evict shmem entry, keep catalog row
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_evict_rel(Oid relid)
{
    int i;

    if (!rel_dek_cache)
        return;

    LWLockAcquire(&rel_dek_cache->lock, LW_EXCLUSIVE);
    for (i = 0; i < rel_dek_cache->capacity; i++)
    {
        TdeRelDekEntry *e = &rel_dek_cache->entries[i];
        if (e->relid == relid)
        {
            OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
            OPENSSL_cleanse(e->prev_dek, TDE_DEK_LEN);
            e->relid          = InvalidOid;
            e->dek_valid      = false;
            e->prev_dek_valid = false;
            rel_dek_cache->used--;
            break;
        }
    }
    LWLockRelease(&rel_dek_cache->lock);
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
    int i;

    if (!rel_dek_cache)
        return;

    LWLockAcquire(&rel_dek_cache->lock, LW_EXCLUSIVE);
    for (i = 0; i < rel_dek_cache->capacity; i++)
    {
        TdeRelDekEntry *e = &rel_dek_cache->entries[i];
        if (e->relid != InvalidOid)
        {
            OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
            OPENSSL_cleanse(e->prev_dek, TDE_DEK_LEN);
            e->relid          = InvalidOid;
            e->dek_valid      = false;
            e->prev_dek_valid = false;
        }
    }
    rel_dek_cache->used = 0;
    LWLockRelease(&rel_dek_cache->lock);

    ereport(LOG, errmsg("pg_vault_tde: all DEKs evicted from shared memory cache"));
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_get_dek_count — count live shmem DEK entries
 * -------------------------------------------------------------------------*/
int
pg_vault_tde_catalog_get_dek_count(void)
{
    int count;

    if (!rel_dek_cache)
        return 0;

    LWLockAcquire(&rel_dek_cache->lock, LW_SHARED);
    count = rel_dek_cache->used;
    LWLockRelease(&rel_dek_cache->lock);

    return count;
}

void pg_vault_tde_catalog_zero_rel_dek(Oid relid) 
{
    int i;

    if (!rel_dek_cache)
        return;

    LWLockAcquire(&rel_dek_cache->lock, LW_EXCLUSIVE);
    for (i = 0; i < rel_dek_cache->capacity; i++)
    {
        TdeRelDekEntry *e = &rel_dek_cache->entries[i];
        if (e->relid == relid)
        {
            memcpy(e->prev_dek, e->dek, TDE_DEK_LEN);
            OPENSSL_cleanse(e->dek, TDE_DEK_LEN);
            e->dek_valid      = false;
            e->prev_dek_valid = true;
            e->generation++;
            break;
        }
    }
    LWLockRelease(&rel_dek_cache->lock);

    ereport(LOG, errmsg("pg_vault_tde: Old dek saved and setted dek invalid"));
}

