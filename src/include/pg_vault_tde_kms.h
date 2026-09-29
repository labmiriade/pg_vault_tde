/*
 * pg_vault_tde_kms.h - KMS/Vault integration header
 *
 * Copyright (c) 2026 Miriade S.r.l.  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_KMS_H
#define PG_VAULT_TDE_KMS_H

#include "postgres.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "common/base64.h"           /* pg_b64_decode */

/*
 * tde_caller_is_superuser — whether the role that called the SQL function is a
 * superuser.  Most key-management functions are SECURITY DEFINER, and inside
 * them superuser() asks about the function's owner — the superuser who ran
 * CREATE EXTENSION — so it is always true: only REVOKE ... FROM PUBLIC kept
 * them closed, and wallet_init() is granted to pg_monitor (PSQLE-206).
 * GetOuterUserId() is the role outside every SECURITY DEFINER call.
 */
#ifndef FRONTEND
#include "miscadmin.h"               /* GetOuterUserId, superuser_arg */

static inline bool
tde_caller_is_superuser(void)
{
    return superuser_arg(GetOuterUserId());
}
#endif

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
void   pg_vault_tde_register_preload_bgw(void);

#endif /* PG_VAULT_TDE_KMS_H */
