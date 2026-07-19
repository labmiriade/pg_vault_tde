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
 * Called from shmem_startup_hook chain — maps the Vault token cache struct
 * (pg_vault_tde_kms_cache) and initialises its embedded LWLock (including
 * LWLockNewTrancheId which requires shared memory to be ready — safe here,
 * not in _PG_init).  The per-relation DEK cache is a separate HTAB owned
 * by pg_vault_tde_catalog.c.
 */
void pg_vault_tde_kms_shmem_init(void);

/*
 * pkcs11 provider's shared-memory KEK-version beacon (v1.7+).
 * Same shmem_request_hook / shmem_startup_hook chain as above, defined in
 * pg_vault_tde_kms_pkcs11.c (owns the Pkcs11SharedState struct and the
 * pkcs11_shared static pointer — both file-scope there).
 */
void pg_vault_tde_kms_pkcs11_shmem_request(void);
void pg_vault_tde_kms_pkcs11_shmem_init(void);

/*
 * Background worker registration (v1.3).
 * Registers the token renewal BGW if pg_vault_tde.bgw_enabled = true.
 * Must be called from _PG_init() before postmaster fork.
 */
void   pg_vault_tde_register_bgw(void);

#endif /* PG_VAULT_TDE_KMS_H */
