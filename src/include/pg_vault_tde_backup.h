/*
 * pg_vault_tde_backup.h - Backup encryption header types and API
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_BACKUP_H
#define PG_VAULT_TDE_BACKUP_H

#include "postgres.h"
#include "src/include/pg_vault_tde_crypto.h"

#define TDE_BACKUP_MAGIC_LEN     10  /* strlen("PGVAULTTDE") */

/*
 * Maximum size of the RSA-OAEP wrapped DEK blob.
 * RSA-4096 output is 4096/8 = 512 bytes; this is the upper bound
 * for the wrapped_dek field regardless of the wrapping algorithm.
 */
#define TDE_BACKUP_WRAPPED_LEN  512

/*
 * tde_backup_header
 *
 * Fixed-size header prepended to every encrypted pg_dump output file.
 * All fields are in host byte order (backups are not portable across
 * architectures by design; use pg_dump --format=plain for portability).
 */
typedef struct tde_backup_header
{
    char     magic[TDE_BACKUP_MAGIC_LEN]; /* "PGVAULTTDE" */
    uint32   format_version;              /* TDE_BACKUP_FORMAT_VERSION */
    uint8    stream_iv[TDE_GCM_IV_LEN];   /* per-backup stream IV */
    uint16   wrapped_dek_len;             /* actual length of wrapped_dek */
    uint8    wrapped_dek[TDE_BACKUP_WRAPPED_LEN]; /* DEK wrapped by KEK */
} tde_backup_header;

bool tde_backup_header_init(tde_backup_header *hdr);
void tde_backup_encrypt_block(const char *block_data, Size block_len,
                               uint64 block_seq,
                               char *out_buf, Size *out_len);

/* SQL-callable status function */
extern Datum pg_vault_tde_backup_status(PG_FUNCTION_ARGS);

#endif /* PG_VAULT_TDE_BACKUP_H */
