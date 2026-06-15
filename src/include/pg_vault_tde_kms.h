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
 * Background worker registration (v1.3).
 * Registers the token renewal BGW if pg_vault_tde.bgw_enabled = true.
 * Must be called from _PG_init() before postmaster fork.
 */
void   pg_vault_tde_register_bgw(void);

#endif /* PG_VAULT_TDE_KMS_H */
