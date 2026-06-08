/*
 * pg_dump_tde_kms.h - KMS provider vtable for pg_dump_tde / pg_restore_tde
 *
 * Defines PdeKmsProvider, the abstract interface used by the backup utilities
 * to generate, wrap, and unwrap the Data Encryption Key (DEK) without being
 * coupled to a specific KMS backend (Vault Transit or local PKCS#12 wallet).
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */

#ifndef PG_DUMP_TDE_KMS_H
#define PG_DUMP_TDE_KMS_H

#include "postgres_fe.h"
#include "libpq-fe.h"

#define TDE_DEK_LEN      32

typedef struct PdeKmsProvider {
    const char* name; 

    bool (*init)(PGconn *conn);

    bool (*generate_dek)(unsigned char* out, int len);
    
    /*
     * wrap_dek — encrypt the plaintext DEK for storage in tde_backup_header.
     *
     * *out_len is BIDIRECTIONAL: caller sets it to the capacity of @out before
     * the call; provider sets it to bytes written on success.  Mirrors the same
     * contract as the backend TdeKmsProvider.wrap_dek (see kms.instructions.md).
     */
    bool (*wrap_dek)(const unsigned char* dek, int dek_len,
                     unsigned char* out, int* out_len);

    /*
     * unwrap_dek — recover the plaintext DEK from the wrapped blob read out of
     * tde_backup_header.  @dek_len is input-only capacity; unwrapped output is
     * always exactly TDE_DEK_LEN bytes.
     */
    bool (*unwrap_dek)(const unsigned char* wrapped_dek, int wrapped_len,
                        unsigned char* dek_out, int dek_len);

    void (*shutdown)(void);
} PdeKmsProvider;

extern const PdeKmsProvider* dump_tde_active_provider;

/*
 * Provider registration functions — one per provider implementation.
 * Called ONLY from pg_vault_tde.c to populate tde_active_kms_provider.
 */
const PdeKmsProvider *pg_dump_tde_kms_vault_provider(void);   /* vault */
const PdeKmsProvider *pg_dump_tde_kms_local_provider(void);   /* local wallet */


/*
 * LOAD_PARAM(field, guc) — read one PostgreSQL GUC into config->field.
 * Calls PQexec("SHOW <guc>") and snprintf's the result; returns false on error.
 * Must be called from a function that has a local `conn` and `config` pointer.
 */
#define LOAD_PARAM(field, guc)                                          \
    do {                                                                \
        PGresult *_r = PQexec(conn, "SHOW " guc);                      \
        if (PQresultStatus(_r) != PGRES_TUPLES_OK)                     \
        {                                                               \
            pg_log_error("cannot read GUC %s: %s",                     \
                         guc, PQerrorMessage(conn));                   \
            PQclear(_r);                                               \
            return false;                                               \
        }                                                               \
        snprintf(config->field, sizeof(config->field), "%s",          \
                 PQgetvalue(_r, 0, 0));                                 \
        PQclear(_r);                                                    \
    } while (0)

#endif

