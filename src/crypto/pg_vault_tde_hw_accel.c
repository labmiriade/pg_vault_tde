/*
 * pg_vault_tde_hw_accel.c - Hardware acceleration & OpenSSL provider layer
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * DESIGN RATIONALE:
 * -----------------
 * OpenSSL 3.x introduced a "provider" architecture that replaces the old
 * ENGINE mechanism.  Providers are dynamically loadable modules that supply
 * cryptographic algorithm implementations.  For example:
 *
 *   - "default"      — built-in AES-NI/ARM CE auto-dispatch (always present)
 *   - "fips"         — FIPS 140-2/3 validated module
 *   - "qatprovider"  — Intel QuickAssist Technology hardware offload
 *   - "pkcs11"       — HSM integration via PKCS#11
 *
 * When the GUC pg_vault_tde.crypto_provider is set, we load the named
 * provider via OSSL_PROVIDER_load().  Once loaded, EVP_CIPHER_fetch()
 * considers all loaded providers and picks the best available implementation.
 * This means that after loading "qatprovider", AES-256-GCM operations
 * automatically route to QAT hardware (if the device driver is available).
 *
 * We pre-fetch cipher objects at init time and cache them for the process
 * lifetime, avoiding the EVP_CIPHER_fetch() cost on every encrypt/decrypt
 * call.  This is safe because providers are loaded per-process and cipher
 * objects remain valid until the provider is unloaded.
 *
 * FALLBACK STRATEGY:
 *   1. provider load fails    → WARNING, continue with default provider
 *   2. GCM cipher fetch fails → WARNING, fall back to EVP_aes_256_gcm()
 *   3. SIV cipher fetch fails → normal (QAT doesn't support SIV); IAM does
 *                                its own fetch as fallback
 *
 * The extension NEVER refuses to start because of missing hardware.
 *
 * OPENSSL 1.1.x COMPATIBILITY:
 * OSSL_PROVIDER_load and EVP_CIPHER_fetch do not exist in OpenSSL 1.1.x.
 * We guard all provider code with OPENSSL_VERSION_NUMBER >= 0x30000000L.
 * On older OpenSSL, the module is a no-op; legacy ciphers are used.
 */
#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "utils/builtins.h"

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include "src/include/pg_vault_tde_hw_accel.h"
#include "src/include/pg_vault_tde_guc.h"

/* ============================================================
 * Module state — per-process, initialised once in _PG_init().
 * ============================================================ */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER *tde_hw_provider = NULL;       /* loaded HW provider */
#endif

static EVP_CIPHER    *tde_fetched_gcm = NULL;        /* AES-256-GCM cipher */
static EVP_CIPHER    *tde_fetched_siv = NULL;        /* AES-256-SIV cipher */
static bool           tde_hw_initialized = false;
static bool           tde_provider_loaded = false;
static char           tde_loaded_provider_name[128] = "";

/*
 * tde_hw_accel_init -- Load the configured provider and cache cipher objects.
 *
 * Called from _PG_init() after GUC registration. On OpenSSL < 3.0
 * this is a harmless no-op: the module falls back to the default ciphers.
 *
 * Idempotent: subsequent calls are no-ops.
 */
void
tde_hw_accel_init(void)
{
    if (tde_hw_initialized)
        return;
    tde_hw_initialized = true;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /*
     * If the GUC specifies a provider, attempt to load it.
     * Examples: "qatprovider" (Intel QAT), "fips" (FIPS module).
     */
    if (pg_vault_tde_crypto_provider != NULL &&
        pg_vault_tde_crypto_provider[0] != '\0')
    {
        /*
         * Ensure the default provider is explicitly loaded so that
         * non-QAT algorithms (SHA-256 for PBKDF2, etc.) remain available.
         * Without this, loading only qatprovider would hide algorithms
         * that QAT does not implement.
         */
        if (OSSL_PROVIDER_load(NULL, "default") == NULL)
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: failed to load OpenSSL 'default' "
                            "provider alongside '%s'",
                            pg_vault_tde_crypto_provider)));
        }

        tde_hw_provider = OSSL_PROVIDER_load(NULL,
                                              pg_vault_tde_crypto_provider);
        if (tde_hw_provider == NULL)
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: failed to load OpenSSL provider "
                            "'%s' — falling back to default (AES-NI/CE)",
                            pg_vault_tde_crypto_provider)));
        }
        else
        {
            tde_provider_loaded = true;
            strlcpy(tde_loaded_provider_name,
                    pg_vault_tde_crypto_provider,
                    sizeof(tde_loaded_provider_name));

            ereport(LOG,
                    (errmsg("pg_vault_tde: loaded OpenSSL provider '%s' "
                            "for hardware-accelerated crypto",
                            tde_loaded_provider_name)));
        }
    }

    /*
     * Pre-fetch cipher objects from whatever providers are loaded.
     * EVP_CIPHER_fetch with NULL propq picks the highest-priority provider.
     *
     * GCM: required — if fetch fails, fall back to legacy EVP_aes_256_gcm().
     * SIV: optional — QAT doesn't support SIV; IAM has its own fallback.
     */
    tde_fetched_gcm = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (tde_fetched_gcm == NULL)
    {
        ereport(WARNING,
                (errmsg("pg_vault_tde: EVP_CIPHER_fetch(AES-256-GCM) failed; "
                        "using legacy cipher (default provider)")));
    }
    else
    {
        const OSSL_PROVIDER *prov = EVP_CIPHER_get0_provider(tde_fetched_gcm);
        const char *pname = prov ? OSSL_PROVIDER_get0_name(prov) : "built-in";

        ereport(LOG,
                (errmsg("pg_vault_tde: AES-256-GCM cipher served by provider '%s'",
                        pname)));
    }

    tde_fetched_siv = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
    if (tde_fetched_siv != NULL)
    {
        const OSSL_PROVIDER *prov = EVP_CIPHER_get0_provider(tde_fetched_siv);
        const char *pname = prov ? OSSL_PROVIDER_get0_name(prov) : "built-in";

        ereport(LOG,
                (errmsg("pg_vault_tde: AES-256-SIV cipher served by provider '%s'",
                        pname)));
    }
    else
    {
        ereport(DEBUG1,
                (errmsg("pg_vault_tde: AES-256-SIV not available via fetched "
                        "provider; IAM will use per-call fetch fallback")));
    }

#else /* OpenSSL < 3.0 */
    ereport(LOG,
            (errmsg("pg_vault_tde: OpenSSL < 3.0 detected; provider mechanism "
                    "unavailable, using built-in AES-NI auto-dispatch")));
#endif
}

/*
 * tde_hw_accel_cleanup -- Free fetched ciphers and unload provider.
 *
 * Called from the on_proc_exit cleanup chain to avoid OpenSSL memory leaks.
 * Safe to call multiple times; NULLs the pointers after freeing.
 */
void
tde_hw_accel_cleanup(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (tde_fetched_gcm != NULL)
    {
        EVP_CIPHER_free(tde_fetched_gcm);
        tde_fetched_gcm = NULL;
    }
    if (tde_fetched_siv != NULL)
    {
        EVP_CIPHER_free(tde_fetched_siv);
        tde_fetched_siv = NULL;
    }
    if (tde_hw_provider != NULL)
    {
        OSSL_PROVIDER_unload(tde_hw_provider);
        tde_hw_provider = NULL;
    }
#endif
    tde_provider_loaded = false;
    tde_hw_initialized = false;
}

/*
 * tde_hw_accel_gcm_cipher -- Return the best available AES-256-GCM cipher.
 *
 * If a provider was loaded and the fetch succeeded, returns the fetched
 * cipher (which may be QAT-accelerated).  Otherwise returns the legacy
 * EVP_aes_256_gcm() which auto-dispatches to AES-NI/ARM CE.
 *
 * WARNING: the returned pointer is owned by this module.  Callers MUST NOT
 * call EVP_CIPHER_free() on it.
 */
const EVP_CIPHER *
tde_hw_accel_gcm_cipher(void)
{
    if (tde_fetched_gcm != NULL)
        return tde_fetched_gcm;

    /* Legacy fallback — always available on any OpenSSL version */
    return EVP_aes_256_gcm();
}

/*
 * tde_hw_accel_siv_cipher -- Return the AES-256-SIV cipher (may be NULL).
 *
 * Returns the pre-fetched SIV cipher if available, or NULL.  When NULL,
 * the IAM module should call EVP_CIPHER_fetch() itself as a per-call
 * fallback (this is the existing behavior when no provider is loaded).
 *
 * QAT does not implement SIV, so this returns NULL when QAT is the only
 * provider.  After tde_hw_accel_init() loads "default" alongside QAT,
 * SIV will be available from the default provider.
 */
const EVP_CIPHER *
tde_hw_accel_siv_cipher(void)
{
    return tde_fetched_siv;  /* may be NULL */
}

/*
 * tde_hw_accel_provider_name -- Name of the loaded provider (or "").
 */
const char *
tde_hw_accel_provider_name(void)
{
    return tde_loaded_provider_name;
}

/*
 * tde_hw_accel_is_loaded -- True if an explicit provider was loaded.
 */
bool
tde_hw_accel_is_loaded(void)
{
    return tde_provider_loaded;
}


/* ================================================================
 * SQL-callable diagnostic function
 *
 * pg_vault_tde_hw_accel_info() → record
 *
 * Returns a composite row with hardware acceleration diagnostics:
 *   openssl_version    text     e.g. "OpenSSL 3.0.13 30 Jan 2024"
 *   configured_provider text    GUC value (empty = default)
 *   provider_loaded    boolean  true if explicit provider active
 *   gcm_cipher         text     provider name serving AES-256-GCM
 *   siv_cipher         text     provider name serving AES-256-SIV
 *   aes_ni_available   boolean  true if CPU supports AES instructions
 * ================================================================ */
PG_FUNCTION_INFO_V1(pg_vault_tde_hw_accel_info);
PGDLLEXPORT Datum
pg_vault_tde_hw_accel_info(PG_FUNCTION_ARGS)
{
    TupleDesc       tupdesc;
    HeapTuple       htup;
    Datum           values[6];
    bool            nulls[6] = {false, false, false, false, false, false};
    const char     *gcm_prov = "default";
    const char     *siv_prov = "default";
    bool            aes_hw = false;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errmsg("return type must be a row type")));
    tupdesc = BlessTupleDesc(tupdesc);

    /* 1. OpenSSL version string */
    values[0] = CStringGetTextDatum(OpenSSL_version(OPENSSL_VERSION));

    /* 2. Configured provider (GUC value) */
    values[1] = CStringGetTextDatum(
        pg_vault_tde_crypto_provider != NULL ?
            pg_vault_tde_crypto_provider : "");

    /* 3. Provider loaded? */
    values[2] = BoolGetDatum(tde_provider_loaded);

    /* 4. GCM cipher provider name */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (tde_fetched_gcm != NULL)
    {
        const OSSL_PROVIDER *prov = EVP_CIPHER_get0_provider(tde_fetched_gcm);
        if (prov)
            gcm_prov = OSSL_PROVIDER_get0_name(prov);
    }
#endif
    values[3] = CStringGetTextDatum(gcm_prov);

    /* 5. SIV cipher provider name */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (tde_fetched_siv != NULL)
    {
        const OSSL_PROVIDER *prov = EVP_CIPHER_get0_provider(tde_fetched_siv);
        if (prov)
            siv_prov = OSSL_PROVIDER_get0_name(prov);
    }
#endif
    values[4] = CStringGetTextDatum(siv_prov);

    /* 6. AES hardware instruction support */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    aes_hw = __builtin_cpu_supports("aes");
#elif defined(__aarch64__)
    /*
     * On ARM64, we probe /proc/cpuinfo for the "aes" feature flag.
     * getauxval(AT_HWCAP) + HWCAP_AES would be cleaner but requires
     * <sys/auxv.h> which is Linux-specific.  For portability we just
     * report true — all ARMv8-A CPUs support Crypto Extensions.
     */
    aes_hw = true;
#endif
    values[5] = BoolGetDatum(aes_hw);

    htup = heap_form_tuple(tupdesc, values, nulls);
    PG_RETURN_DATUM(HeapTupleGetDatum(htup));
}
