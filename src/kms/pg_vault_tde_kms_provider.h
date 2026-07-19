/*
 * pg_vault_tde_kms_provider.h — KMS provider vtable abstraction (v1.5)
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * WHY THIS EXISTS:
 * ----------------
 * v1.4 hardwired the Vault/OpenBao HTTP connector as the only KMS backend.
 * v1.5 introduces the local wallet (PKCS#12) provider and prepares the
 * interface for PKCS#11 (v1.7) and KMIP 1.2 (v1.8) without requiring any
 * caller-side changes.
 *
 * All KMS backends implement this function-pointer table.  The active
 * provider is chosen at startup by the `pg_vault_tde.kms_provider` GUC
 * and assigned to `tde_active_kms_provider` in pg_vault_tde.c.
 *
 * OWNERSHIP:
 * ----------
 * @SecurityKMS owns this header.  The signature of every entry in
 * TdeKmsProvider is FROZEN once the v1.5 branch merges.  Any change
 * requires updating ALL providers and ALL call sites (Rule 2, AGENTS.md).
 *
 * DEPENDENCY:
 * -----------
 * This header MUST NOT include any tam/, iam/, or crypto/ headers.
 * Rule: kms/ depends on nothing inside this extension.
 */
#ifndef PG_VAULT_TDE_KMS_PROVIDER_H
#define PG_VAULT_TDE_KMS_PROVIDER_H

#include "postgres.h"

/*
 * Maximum length of a provider name used in GUC and error messages.
 */
#define TDE_KMS_PROVIDER_NAME_LEN  32

/*
 * TdeKmsProvider — vtable for a KMS backend.
 *
 * Every function pointer is non-NULL for a valid provider.  Providers that
 * do not implement a given operation (e.g. `shutdown` for a stateless
 * provider) MUST supply a no-op function that returns true/void — never NULL.
 *
 * Error convention:
 *   - All functions that return bool: return false on recoverable failure.
 *     The caller decides whether to ereport(ERROR) or fall back.
 *   - All functions that return void: use ereport(ERROR) for unrecoverable
 *     failures; they never return on error.
 *
 * Memory ownership:
 *   - All output buffers (dek_out, wrapped_out) are caller-allocated.
 *   - Provider functions MUST NOT palloc output buffers — they fill
 *     caller-provided arrays so that OPENSSL_cleanse on the caller's
 *     stack wipes the key material reliably.
 */
typedef struct TdeKmsProvider
{
    /*
     * Human-readable name: "vault", "local", "pkcs11", "kmip".
     * Used in log messages and pg_vault_tde_health_check() output.
     */
    const char *name;

    /*
     * init — one-time backend initialisation.
     *
     * Called from shmem_startup_hook after the shared memory segment is
     * ready.  The provider allocates any per-backend state here (e.g.
     * opens the PKCS#12 wallet, sets up a curl handle).
     *
     * Returns true on success, false if the provider cannot initialise
     * (e.g. wallet file missing, Vault unreachable at startup).  A false
     * return causes pg_vault_tde to start in degraded mode.
     */
    bool (*init)(void);

    /*
     * wrap_dek — encrypt (wrap) a plaintext DEK using the KMS KEK.
     *
     * Input  : dek[dek_len]           — plaintext DEK (NEVER stored to disk)
     * Output : wrapped_out[*out_len]  — opaque ciphertext, provider-specific
     *          *out_len               — byte length of wrapped output
     *
     * The wrapped form is stored in pg_vault_tde_catalog.wrapped_dek.
     * For Vault: POST /transit/encrypt/<key> (base64-encoded ciphertext string).
     * For local wallet: AES-256-WRAP (RFC 3394) using the PKCS#12 KEK.
     *
     * Returns true on success.
     */
    bool (*wrap_dek)(const unsigned char *dek, int dek_len,
                     unsigned char *wrapped_out, int *out_len);

    /*
     * unwrap_dek — decrypt a wrapped DEK back to plaintext.
     *
     * Input  : wrapped[wrapped_len]   — opaque ciphertext from wrap_dek
     *          *dek_len               — capacity of dek_out (must be >= TDE_DEK_LEN)
     * Output : dek_out[*dek_len]      — plaintext DEK; caller MUST
     *                                   OPENSSL_cleanse after use
     *          *dek_len               — actual bytes written (always TDE_DEK_LEN on success)
     *
     * Returns true on success, false if the buffer is too small, the KEK is
     * unavailable, or the wrapped ciphertext is corrupt.
     */
    bool (*unwrap_dek)(const unsigned char *wrapped, int wrapped_len,
                       unsigned char *dek_out, int *dek_len);

    /*
     * rewrap_dek — re-wrap an existing DEK under a new KEK version.
     *
     * Used after KEK rotation (Vault: Transit key rotate; wallet:
     * passphrase change).  Providers that do not support rewrap in one
     * round-trip may implement this as unwrap_dek + wrap_dek.
     *
     * Input  : old_wrapped[old_len]       — currently stored wrapped DEK
     * Output : new_wrapped[*new_len]      — re-wrapped under new KEK
     *
     * Returns true on success.
     */
    bool (*rewrap_dek)(const unsigned char *old_wrapped, int old_len,
                       unsigned char *new_wrapped, int *new_len);

    /* Arms the provider for a rewrap cycle; must be called before pg_vault_tde_catalog_rewrap_all(). */
    bool (*prepare_kek_rotation)(void);
    void (*commit_kek_rotation)(void);

    /*
     * health_check — probe provider availability.
     *
     * Returns true if the provider can currently wrap/unwrap DEKs.
     * Non-blocking: must return in under 100 ms.  On timeout, return false.
     * Called from pg_vault_tde_health_check() SQL function.
     */
    bool (*health_check)(void);

    /*
     * shutdown — per-backend cleanup.
     *
     * Called from on_proc_exit callback.  MUST be idempotent (may be called
     * multiple times on error recovery paths).
     * Wipes sensitive material (e.g. PKCS#12 passphrase buffer, curl handle).
     */
    void (*shutdown)(void);
} TdeKmsProvider;

/*
 * tde_active_kms_provider — the selected KMS backend for this connection.
 *
 * Assigned in pg_vault_tde.c _PG_init based on pg_vault_tde.kms_provider GUC.
 * All callers that need KMS operations use this pointer — NEVER call provider
 * functions directly.
 *
 * Defined in pg_vault_tde.c; declared extern here so kms.c and tam.c can read
 * it without including pg_vault_tde.c's internals.
 *
 * PER-DATABASE KMS:
 * Because pg_vault_tde.kms_provider (and all companion GUCs) are declared
 * PGC_SUSET, a superuser can assign different KMS settings to individual
 * databases in the same cluster without restarting PostgreSQL:
 *
 *   ALTER DATABASE tenant_a SET pg_vault_tde.kms_provider   = 'vault';
 *   ALTER DATABASE tenant_a SET pg_vault_tde.vault_key_name = 'tde-dek-a';
 *   ALTER DATABASE tenant_b SET pg_vault_tde.kms_provider   = 'local';
 *
 * Each backend resolves tde_active_kms_provider from the effective GUC value
 * for its own database during connection setup.  The cluster-wide default in
 * postgresql.conf is the fallback for databases that do not override.
 */
extern const TdeKmsProvider *tde_active_kms_provider;

/*
 * Provider registration functions — one per provider implementation.
 * Called ONLY from pg_vault_tde.c to populate tde_active_kms_provider.
 */
const TdeKmsProvider *pg_vault_tde_kms_vault_provider(void);   /* vault */
const TdeKmsProvider *pg_vault_tde_kms_local_provider(void);   /* local wallet */
const TdeKmsProvider *pg_vault_tde_kms_pkcs11_provider(void);  /* pkcs11 HSM */

#endif /* PG_VAULT_TDE_KMS_PROVIDER_H */
