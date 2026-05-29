/*
 * pg_dump_tde_kms.h - AES-256-GCM encrypt/decrypt API
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */

#ifndef PG_DUMP_TDE_KMS_H
#define PG_DUMP_TDE_KMS_H
#endif

#include "postgres_fe.h"
#include "libpq-fe.h"

typedef struct PdeKmsProvider {
    const char* name; 

    bool (*init)(PGconn *conn);

    bool (*generate_dek)(unsigned char* out, int len);
    
    bool (*wrap_dek)(const unsigned char* dek, int dek_len, 
                     unsigned char* out, int* out_len);

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
=======================
Utility for load guc
=======================
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



