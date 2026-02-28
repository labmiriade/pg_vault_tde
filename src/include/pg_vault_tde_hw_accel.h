/*
 * pg_vault_tde_hw_accel.h - Hardware acceleration & OpenSSL provider API
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * This module abstracts the OpenSSL 3.x provider mechanism so that hardware
 * accelerators (Intel QAT, ARM Crypto Extensions via custom provider, FIPS
 * provider, etc.) can be loaded at postmaster startup via a single GUC.
 *
 * When the GUC pg_vault_tde.crypto_provider is empty (default), the module
 * uses the legacy EVP_aes_256_gcm()/EVP_aes_256_siv() symbols which auto-
 * dispatch to AES-NI or ARM CE through the built-in default provider.
 *
 * When a provider name is specified (e.g. "qatprovider"), the module calls
 * OSSL_PROVIDER_load() at init time, then EVP_CIPHER_fetch() for both GCM
 * and SIV ciphers.  If loading fails, it falls back to the default ciphers
 * with a WARNING — the extension never refuses to start due to a missing
 * hardware accelerator.
 */
#ifndef PG_VAULT_TDE_HW_ACCEL_H
#define PG_VAULT_TDE_HW_ACCEL_H

#include "postgres.h"
#include <openssl/evp.h>

/*
 * tde_hw_accel_init -- Load the configured OpenSSL provider and pre-fetch
 * GCM/SIV ciphers.  Called once from _PG_init().
 *
 * Safe to call even on OpenSSL 1.1.x (no-op with WARNING).
 */
void tde_hw_accel_init(void);

/*
 * tde_hw_accel_cleanup -- Free fetched ciphers and unload provider.
 * Called from the on_proc_exit() cleanup chain.
 */
void tde_hw_accel_cleanup(void);

/*
 * tde_hw_accel_gcm_cipher -- Return the AES-256-GCM cipher to use.
 *
 * Returns the fetched cipher if a provider was loaded, or the legacy
 * EVP_aes_256_gcm() otherwise.  The returned pointer is owned by this
 * module — callers MUST NOT EVP_CIPHER_free() it.
 */
const EVP_CIPHER *tde_hw_accel_gcm_cipher(void);

/*
 * tde_hw_accel_siv_cipher -- Return the AES-256-SIV cipher to use.
 *
 * Returns the fetched cipher if available, or NULL.  When NULL, the
 * caller (IAM module) should call EVP_CIPHER_fetch() itself as a
 * fallback (SIV is not supported by all providers, e.g. QAT).
 * The returned pointer is owned by this module — callers MUST NOT
 * EVP_CIPHER_free() it.
 */
const EVP_CIPHER *tde_hw_accel_siv_cipher(void);

/*
 * tde_hw_accel_provider_name -- Return the name of the loaded provider.
 * Returns "" if no explicit provider was loaded (using defaults).
 */
const char *tde_hw_accel_provider_name(void);

/*
 * tde_hw_accel_is_loaded -- Return true if an explicit provider was loaded.
 */
bool tde_hw_accel_is_loaded(void);

#endif /* PG_VAULT_TDE_HW_ACCEL_H */
