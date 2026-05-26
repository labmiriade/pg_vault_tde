/*
 * pg_vault_tde_kms.h - KMS/Vault integration header
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_KMS_H
#define PG_VAULT_TDE_KMS_H

#include "postgres.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "common/base64.h"           /* pg_b64_decode */

/*
 * AES-256 DEK length in bytes: 256 bits / 8 = 32 bytes.
 * This is the single source of truth for DEK size; do NOT redefine
 * this constant in any .c file (header hygiene rule).
 */
#define TDE_DEK_LEN 32

/*
 * Called from shmem_request_hook chain (PG 15+).
 * Reserves shared memory space.
 * Must be called BEFORE shmem is allocated.
 */
void pg_vault_tde_kms_shmem_request(void);

/*
 * Called from shmem_startup_hook chain — maps the DEK cache struct and
 * initialises the embedded LWLock (including LWLockNewTrancheId which
 * requires shared memory to be ready — safe here, not in _PG_init).
 */
void pg_vault_tde_kms_shmem_init(void);

/*
 * Vault-provider DEK fetch: connects to HashiCorp Vault / OpenBao Transit,
 * generates a new DEK, and stores it in shared memory.
 *
 * This function is called ONLY by the Vault KMS provider (pg_vault_tde_kms_vault.c)
 * from its `init()` and `generate_dek()` vtable callbacks.  The general
 * cross-provider interface is tde_active_kms_provider->wrap_dek() /
 * ->unwrap_dek() (see pg_vault_tde_kms_provider.h).
 *
 * Returns true on success (DEK stored in shmem), false on Vault unreachable
 * or auth failure.  Non-fatal on failure — caller decides error policy.
 */
bool pg_vault_tde_vault_fetch_dek(void);

/*
 * DEK cache accessors.
 * get_dek: returns local backend copy, refreshes from shmem if generation
 *          has changed (key rotation detection via epoch counter).
 * set_dek: stores new DEK and increments generation in shmem.
 * zero_dek: wipes DEK and increments generation (pre-rotation step).
 * get_generation: returns current rotation epoch (for monitoring/tests).
 */
bool   pg_vault_tde_kms_get_dek(char *out_dek, Size dek_len);
void   pg_vault_tde_kms_set_dek(const char *new_dek, Size dek_len);
void   pg_vault_tde_kms_zero_dek(void);
uint64 pg_vault_tde_kms_get_generation(void);

/*
 * Previous-DEK accessors for graceful key rotation.
 *
 * During rotation, zero_dek() saves the current DEK as prev_dek.
 * The decrypt path falls back to prev_dek if GCM authentication
 * fails with the current DEK (see tde_gcm_decrypt in crypto.c).
 *
 * get_prev_dek: copies the saved prev DEK if available.
 * clear_prev_dek: wipes prev DEK from shmem (call after re-encryption).
 */
bool   pg_vault_tde_kms_get_prev_dek(char *out_dek, Size dek_len);
void   pg_vault_tde_kms_clear_prev_dek(void);

/*
 * KEK wrapping (v1.3): attempt to restore the DEK from a persisted
 * wrapped DEK file via Vault Transit decrypt.  Returns true if DEK
 * was successfully unwrapped and stored in shmem.
 */
bool   pg_vault_tde_try_unwrap_on_startup(void);

/*
 * Background worker registration (v1.3).
 * Registers the token renewal BGW if pg_vault_tde.bgw_enabled = true.
 * Must be called from _PG_init() before postmaster fork.
 */
void   pg_vault_tde_register_bgw(void);

#endif /* PG_VAULT_TDE_KMS_H */
