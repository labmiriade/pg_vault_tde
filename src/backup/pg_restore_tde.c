/*
 * pg_restore_tde.c - TDE-encrypted logical backup restore utility
 *
 * Copyright (c) 2026 Miriade Srl
 * Licensed under the PostgreSQL License.
 *
 * Mirrors pg_dump_tde: reads a file produced by pg_dump_tde, reads the
 * tde_backup_header to unwrap the DEK via the active KMS provider, then
 * decrypts the AES-256-GCM block stream and pipes the plaintext to pg_restore.
 *
 * Current status: argument parsing and KMS initialisation skeleton.
 * TODO: implement the decrypt-and-pipe loop using tde_backup_decrypt_block().
 */
#include "postgres_fe.h"
#include "libpq-fe.h"

#include "fe_utils/connect_utils.h"
#include "getopt_long.h"
#include "common/logging.h"

#include <stdio.h>

#include "pg_vault_tde_backup.h"

int main(int argc, char** argv) {
    pg_logging_init(argv[0]);

    int pipefd[2];
    pid_t pid;
    FILE* infile; 
    char* input_file = NULL;

    TdeBackupContext *bkp_ctx;

    int pg_restore_argc = 0;
    ConnParams cparams = {0};
    int c;

    static struct option long_options[] = {
        {"host", required_argument, NULL, 'h'}, 
        {"port", required_argument, NULL, 'p'}, 
        {"username", required_argument, NULL, 'U'}, 
        {"dbname", required_argument, NULL, 'd'}, 
        {"input", required_argument, NULL, 'i'}, 
        {"jobs", required_argument, NULL, 'j'}, 

        {NULL, 0, NULL, 0} /*Sentinel of EOA used by getopt_long*/
    };
    
    char **pg_restore_args = palloc((argc * 2 + 5) * sizeof(char *));

    bkp_ctx = palloc(sizeof(*bkp_ctx));

    pg_restore_args[pg_restore_argc++] = "pg_restore";
    pg_restore_args[pg_restore_argc++] = "-Fc";

    while((c = getopt_long(argc, argv, "h:p:U:d:i:j:", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'h':
            cparams.pghost = optarg;
            pg_restore_args[pg_restore_argc++] = '-h';
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'p':
            cparams.pgport = optarg;
            pg_restore_args[pg_restore_argc++] = '-p';
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'U':
            cparams.pguser = optarg;
            pg_restore_args[pg_restore_argc++] = '-U';
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'd':
            cparams.dbname = optarg;
            pg_restore_args[pg_restore_argc++] = '-d';
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'i':
            input_file = optarg;
            break;
        case 'j': 
            perror("error: option j is not supported \n");
            goto error_cleanup;
        case '?': 
            fprintf(stderr, "error: %c invalid option\n", c);
            goto error_cleanup;
        
        default:
            break;
        }
    }

    for(int i = optind; i < argc; i++)
    {
        pg_restore_args[pg_restore_argc++] = argv[i];
    }

    pg_restore_args[pg_restore_argc] = NULL;

    if(!input_file) {
        perror("error: --input is required\n");
        goto error_cleanup;
    }

    infile = fopen(input_file, "rb");
    if(!infile) {
        perror("error: could not open output file");
        goto error_cleanup;
    }

    if(!tde_backup_init(&cparams))
    {
        fprintf(stderr, "fatal error: could not initialize TDE backup\n");
        fclose(infile);
        goto error_cleanup;
    }

    /*
     * TODO: read tde_backup_header from infile, call tde_backup_header_validate()
     * to unwrap the DEK into bkp_ctx, then fork pg_restore with stdin connected
     * to a pipe, and stream tde_backup_decrypt_block() output block-by-block.
     */

error_cleanup:
    OPENSSL_cleanse(bkp_ctx, sizeof(*bkp_ctx));
    pfree(bkp_ctx);
    pfree(pg_restore_args);
    exit(EXIT_FAILURE);
}