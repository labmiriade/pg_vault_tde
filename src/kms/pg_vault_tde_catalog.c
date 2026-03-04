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
 *   1. Read wrapped_dek from pg_vault_tde_catalog via SPI
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
#include "executor/spi.h"
#include "miscadmin.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/memutils.h"
#include "utils/builtins.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"     /* get_relname_relid */
#include "catalog/namespace.h"  /* get_namespace_oid */
#include "postmaster/postmaster.h"

#include <openssl/crypto.h>     /* OPENSSL_cleanse */

#include "src/include/pg_vault_tde_catalog.h"
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
 * pg_vault_tde_kms_get_rel_dek — hot-path DEK accessor (v1.5 replacement
 * for pg_vault_tde_kms_get_dek with per-table granularity)
 * -------------------------------------------------------------------------*/
bool
pg_vault_tde_kms_get_rel_dek(Oid relid,
                               unsigned char *dek_out, int dek_len)
{
    int   i;
    bool  found = false;

    Assert(dek_out != NULL);
    Assert(dek_len == TDE_DEK_LEN);

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

        if (e->relid == relid && e->dek_valid)
        {
            memcpy(dek_out, e->dek, TDE_DEK_LEN);
            found = true;
            break;
        }
    }
    LWLockRelease(&rel_dek_cache->lock);

    if (found)
        return true;

    /* ---- Slow path: relid == 0 (global DEK) or cache miss ---- */
    if (relid == InvalidOid)
    {
        /*
         * Backward-compat: relid=0 maps to the v1.4 single global DEK.
         * Read from the old TdeKmsSharedState struct.
         */
        return pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
    }

    /*
     * Cache miss for a named relation.  Fetch the wrapped DEK from
     * pg_vault_tde_catalog via SPI, unwrap via the active KMS provider,
     * and insert into the shmem cache.
     *
     * We use SPI for catalog access because HeapTuple-level access to
     * pg_vault_tde_catalog during TAM callbacks would cause recursion
     * (pg_vault_tde_catalog is itself an ordinary heap table in the public
     * schema, NOT an encrypted_heap table — it must remain plaintext for
     * recovery to work).
     */
    {
        int           spi_rc;
        SPITupleTable *tuptable;
        TupleDesc     tupdesc;
        HeapTuple     tuple;
        bool          isnull;
        Datum         wrapped_datum;
        bytea        *wrapped_bytea;
        unsigned char wrapped_buf[512];
        int           wrapped_len;
        unsigned char dek_temp[TDE_DEK_LEN];
        bool          unwrap_ok;

        /*
         * Guard: pg_vault_tde_catalog only exists after the v1.4→v1.5
         * upgrade.  On vanilla v1.0/v1.4 deployments the table is absent;
         * fall back to the global DEK rather than throwing an ERROR.
         */
        {
            Oid  pub_ns = get_namespace_oid("public", true /* missing_ok */);

            if (!OidIsValid(pub_ns) ||
                !OidIsValid(get_relname_relid("pg_vault_tde_catalog", pub_ns)))
            {
                ereport(DEBUG1,
                        errmsg("pg_vault_tde: catalog table absent, "
                               "using global DEK for relid=%u", relid));
                return pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
            }
        }

        if (SPI_connect() != SPI_OK_CONNECT)
        {
            ereport(WARNING,
                    errmsg("pg_vault_tde: cannot connect to SPI for "
                           "DEK cache miss (relid=%u)", relid));
            return false;
        }

        spi_rc = SPI_execute_with_args(
                     "SELECT wrapped_dek FROM pg_vault_tde_catalog "
                     "WHERE relid = $1",
                     1,
                     (Oid[]){OIDOID},
                     (Datum[]){ObjectIdGetDatum(relid)},
                     (char[]){' '},
                     true,   /* read-only */
                     1       /* max rows */
                 );

        if (spi_rc != SPI_OK_SELECT || SPI_processed == 0)
        {
            bool got_dek;

            SPI_finish();
            /*
             * No catalog entry: fall back to global DEK (v1.4 tables have
             * no entry; treat them as relid=0).
             *
             * Also populate rel_dek_cache so subsequent calls for this relid
             * take the fast (no-SPI) path.  This is critical for WITH HOLD
             * cursor materialisation during CommitTransaction, where SPI
             * cannot be re-entered.  See tde_rel_dek_cache_store_fallback.
             */
            ereport(DEBUG1,
                    errmsg("pg_vault_tde: no catalog entry for relid=%u, "
                           "falling back to global DEK", relid));
            got_dek = pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
            if (got_dek)
                tde_rel_dek_cache_store_fallback(relid, (unsigned char *) dek_out);
            return got_dek;
        }

        tuptable = SPI_tuptable;
        tupdesc  = tuptable->tupdesc;
        tuple    = tuptable->vals[0];

        wrapped_datum = SPI_getbinval(tuple, tupdesc, 1, &isnull);
        if (isnull)
        {
            bool got_dek;

            SPI_finish();
            ereport(DEBUG1,
                    errmsg("pg_vault_tde: wrapped_dek IS NULL for "
                           "relid=%u, falling back to global DEK", relid));
            got_dek = pg_vault_tde_kms_get_dek((char *) dek_out, dek_len);
            if (got_dek)
                tde_rel_dek_cache_store_fallback(relid, (unsigned char *) dek_out);
            return got_dek;
        }

        wrapped_bytea = DatumGetByteaPP(wrapped_datum);
        wrapped_len   = VARSIZE_ANY_EXHDR(wrapped_bytea);

        if (wrapped_len > (int) sizeof(wrapped_buf))
        {
            SPI_finish();
            ereport(WARNING,
                    errmsg("pg_vault_tde: wrapped_dek too large (%d bytes) "
                           "for relid=%u", wrapped_len, relid));
            return false;
        }
        memcpy(wrapped_buf, VARDATA_ANY(wrapped_bytea), wrapped_len);
        SPI_finish();

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

                if (e->relid == relid)
                {
                    /* Already loaded by another backend — use what's there */
                    memcpy(dek_out, e->dek, TDE_DEK_LEN);
                    OPENSSL_cleanse(dek_temp, TDE_DEK_LEN);
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
    int           wrapped_len = 0;
    char          generated_key_name[64];
    const char   *effective_key_name;
    int           spi_rc;
    Datum         args[4];
    Oid           argtypes[4];
    char          nulls[4];

    Assert(OidIsValid(relid));

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

    /* Insert catalog entry via SPI */
    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR,
                errmsg("pg_vault_tde: SPI_connect failed in "
                       "catalog_register_rel"));

    argtypes[0] = OIDOID;
    argtypes[1] = TEXTOID;
    argtypes[2] = INT8OID;
    argtypes[3] = BYTEAOID;

    args[0] = ObjectIdGetDatum(relid);
    args[1] = CStringGetTextDatum(effective_key_name);
    args[2] = Int64GetDatum(1);
    {
        bytea *wrapped_bytea = (bytea *) palloc(VARHDRSZ + wrapped_len);
        SET_VARSIZE(wrapped_bytea, VARHDRSZ + wrapped_len);
        memcpy(VARDATA(wrapped_bytea), wrapped, wrapped_len);
        args[3] = PointerGetDatum(wrapped_bytea);
    }

    memset(nulls, ' ', sizeof(nulls));

    spi_rc = SPI_execute_with_args(
                 "INSERT INTO pg_vault_tde_catalog "
                 "  (relid, vault_key_name, generation, wrapped_dek, kms_provider) "
                 "VALUES ($1, $2, $3, $4, current_setting('pg_vault_tde.kms_provider'))"
                 "ON CONFLICT (relid) DO UPDATE SET "
                 "  vault_key_name = EXCLUDED.vault_key_name, "
                 "  generation     = EXCLUDED.generation, "
                 "  wrapped_dek    = EXCLUDED.wrapped_dek, "
                 "  kms_provider   = EXCLUDED.kms_provider, "
                 "  updated_at     = now()",
                 4, argtypes, args, nulls,
                 false, /* not read-only */
                 1
             );

    SPI_finish();

    if (spi_rc != SPI_OK_INSERT && spi_rc != SPI_OK_UPDATE)
        ereport(ERROR,
                errmsg("pg_vault_tde: catalog INSERT failed for relid=%u "
                       "(SPI result: %d)", relid, spi_rc));

    ereport(DEBUG1,
            errmsg("pg_vault_tde: registered DEK for relid=%u, key=%s",
                   relid, effective_key_name));
}

/* -------------------------------------------------------------------------
 * pg_vault_tde_catalog_deregister_rel — called on DROP TABLE
 * -------------------------------------------------------------------------*/
void
pg_vault_tde_catalog_deregister_rel(Oid relid)
{
    /* Evict from shmem cache with OPENSSL_cleanse */
    pg_vault_tde_catalog_evict_rel(relid);

    /* Remove catalog row */
    if (SPI_connect() != SPI_OK_CONNECT)
    {
        ereport(WARNING,
                errmsg("pg_vault_tde: SPI_connect failed in "
                       "catalog_deregister_rel for relid=%u", relid));
        return;
    }

    SPI_execute_with_args(
        "DELETE FROM pg_vault_tde_catalog WHERE relid = $1",
        1,
        (Oid[]){OIDOID},
        (Datum[]){ObjectIdGetDatum(relid)},
        (char[]){' '},
        false, 0
    );

    SPI_finish();

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
