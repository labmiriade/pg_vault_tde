/*
 * pg_vault_tde_backup.h - Backup encryption header types and API
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#ifndef PG_VAULT_TDE_BACKUP_H
#define PG_VAULT_TDE_BACKUP_H

#ifdef FRONTEND
/*
 * In frontend builds, pg_vault_tde_kms.h and pg_vault_tde_crypto.h pull in
 * lwlock.h / postgres.h which cannot be included here.  Mirror the constants
 * only; authoritative definitions live in the respective backend headers.
 */
#define TDE_DEK_LEN      32
#define TDE_GCM_IV_LEN   12
#define TDE_GCM_TAG_LEN  16
#define TDE_V2_GEN_LEN    8
#define TDE_V2_OVERHEAD  (1 + TDE_V2_GEN_LEN + TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN)
#else
#include "pg_vault_tde_kms.h"     /* TDE_DEK_LEN */
#include "pg_vault_tde_crypto.h"  /* TDE_GCM_IV_LEN, TDE_GCM_TAG_LEN, TDE_V2_OVERHEAD */
#endif

#define TDE_BACKUP_MAGIC_LEN     10  /* strlen("PGVAULTTDE") */

/*
 * Maximum size of the RSA-OAEP wrapped DEK blob.
 * RSA-4096 output is 4096/8 = 512 bytes; this is the upper bound
 * for the wrapped_dek field regardless of the wrapping algorithm.
 */
#define TDE_BACKUP_WRAPPED_LEN  512
#define TDE_BACKUP_BLOCK_SIZE         (64 * 1024) /* 64KB streaming blocks */

/* Current backup format version — increment on breaking changes. */
#define TDE_BACKUP_FORMAT_VERSION 1
#define TDE_BACKUP_MAGIC          "PGVAULTTDE"
#define VAULT_PROVIDER            "vault"
#define LOCAL_PROVIDER            "local"

/*
 * Per-block AES-256-GCM overhead: 12-byte IV + 16-byte authentication tag.
 * Out-buffers passed to tde_backup_encrypt_block() must be at least
 * (block_len + TDE_BACKUP_ENCRYPT_OVERHEAD) bytes.
 */
#define TDE_BACKUP_ENCRYPT_OVERHEAD   (TDE_GCM_IV_LEN + TDE_GCM_TAG_LEN)


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
    uint16   wrapped_dek_len;             /* actual length of wrapped_dek */
    uint8    wrapped_dek[TDE_BACKUP_WRAPPED_LEN]; /* DEK wrapped by KEK */
} tde_backup_header;

typedef struct TdeBackupContext
{
    unsigned char dek[TDE_DEK_LEN];
    int dek_len;
} TdeBackupContext;

bool tde_backup_header_init(tde_backup_header *hdr, TdeBackupContext* ctx);
char *tde_backup_encrypt_block(const TdeBackupContext* ctx,
                         const char *block_data, Size block_len,
                         uint64 block_seq, Size *out_len);

bool tde_backup_init(ConnParams* params);

#endif /* PG_VAULT_TDE_BACKUP_H */
