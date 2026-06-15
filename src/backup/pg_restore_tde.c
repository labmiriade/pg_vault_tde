/*
 * pg_restore_tde.c - TDE-encrypted logical backup restore utility
 *
 * Copyright (c) 2026 Miriade Srl
 * Licensed under the PostgreSQL License.
 *
 * Mirrors pg_dump_tde: reads a file produced by pg_dump_tde, validates the
 * tde_backup_header and unwraps the DEK via the active KMS provider, then
 * decrypts the AES-256-GCM block stream and pipes the plaintext to pg_restore.
 *
 * Usage:
 *   pg_restore_tde -d <dbname> -i <file> [pg_restore options]
 *
 * The database connection is used only to read KMS GUCs; no data is written
 * to it.  Decrypted plaintext is piped to pg_restore via an anonymous pipe.
 */
#include "postgres_fe.h"
#include "libpq-fe.h"
#include "getopt_long.h"
#include "common/logging.h"

#include <stdio.h>
#include <openssl/crypto.h>
#include <sys/wait.h>

#include "pg_vault_tde_backup.h"

int main(int argc, char** argv) {
    pg_logging_init(argv[0]);

    int pipefd[2];
    pid_t pid;
    FILE* infile; 
    char* input_file = NULL;

    TdeBackupContext *bkp_ctx;
    tde_backup_header header;

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
    
    /*
     * Each pg_restore_tde CLI flag translates to two entries in pg_restore_args
     * ("-X" + value), so argc * 2 is the worst-case upper bound.  The extra 5
     * covers argv[0] ("pg_restore"), "-Fc", a trailing NULL, and two spares.
     */
    char **pg_restore_args = palloc((argc * 2 + 5) * sizeof(char *));

    bkp_ctx = palloc(sizeof(*bkp_ctx));

    /*
     * Custom format (-Fc) is mandatory: it is the only pg_dump output format
     * compatible with the block stream written by pg_dump_tde.
     */
    pg_restore_args[pg_restore_argc++] = "pg_restore";
    pg_restore_args[pg_restore_argc++] = "-Fc";

    while((c = getopt_long(argc, argv, "h:p:U:d:i:j:", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'h':
            cparams.pghost = optarg;
            pg_restore_args[pg_restore_argc++] = "-h";
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'p':
            cparams.pgport = optarg;
            pg_restore_args[pg_restore_argc++] = "-p";
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'U':
            cparams.pguser = optarg;
            pg_restore_args[pg_restore_argc++] = "-U";
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'd':
            cparams.dbname = optarg;
            pg_restore_args[pg_restore_argc++] = "-d";
            pg_restore_args[pg_restore_argc++] = optarg;
            break;
        case 'i':
            input_file = optarg;
            break;
        case 'j':
            fprintf(stderr, "error: -j (parallel jobs) is not supported\n");
            goto error_cleanup;

        default:
            break;
        }
    }

    for(int i = optind; i < argc; i++)
    {
        pg_restore_args[pg_restore_argc++] = argv[i];
    }

    pg_restore_args[pg_restore_argc] = NULL; /* execvp requires a NULL terminator */

    if(!input_file) {
        fprintf(stderr, "error: --input is required\n");
        goto error_cleanup;
    }

    infile = fopen(input_file, "rb");
    if(!infile) {
        perror("error: could not open input file");
        goto error_cleanup;
    }

    if(!tde_backup_init(&cparams))
    {
        fprintf(stderr, "fatal error: could not initialize TDE backup\n");
        fclose(infile);
        goto error_cleanup;
    }

    if(fread(&header, sizeof(tde_backup_header), 1, infile) != 1) {
        perror("error: could not read backup header");
        fclose(infile);
        goto error_cleanup;
    }

    if(!tde_backup_header_validate(&header, bkp_ctx)) {
        perror("error: invalid or corrupted backup header");
        fclose(infile);
        goto error_cleanup;
    }

    if(pipe(pipefd) == -1) {
        perror("error: could not create pipe");
        fclose(infile);
        goto error_cleanup;
    }

    pid = fork();
    if(pid == -1) {
        perror("error: fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
        fclose(infile);
        goto error_cleanup;
    }

    if(pid == 0)
    {
        /*
         * Child process: exec pg_restore with stdin redirected to the read
         * end of the pipe.  Close the write end and infile — the child does
         * not read the encrypted file directly.
         */
        fclose(infile);
        OPENSSL_cleanse(bkp_ctx, sizeof(TdeBackupContext));
        pfree(bkp_ctx);

        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        execvp("pg_restore", pg_restore_args);

        /* execvp only returns on failure. */
        perror("error: could not execute pg_restore");
        pfree(pg_restore_args);
        exit(EXIT_FAILURE);
    }
    else
    {
        /* Parent process: read encrypted blocks, decrypt each, write plaintext to pipe. */
        char enc_buffer[TDE_BACKUP_BLOCK_ENC_SIZE];
        char* out_buffer = NULL;
        Size out_len;
        uint64 block_seq = 0;
        size_t bytes_read;
        int status;
        uint32 block_len;

        close(pipefd[0]);

        while(fread(&block_len, sizeof(block_len), 1, infile))
        {
            if(block_len < (uint32) TDE_BACKUP_ENCRYPT_OVERHEAD || 
                block_len > (uint32) TDE_BACKUP_BLOCK_ENC_SIZE)
            {
                perror("error: invalid block size");
                goto error_cleanup;
            }

            bytes_read = fread(enc_buffer, 1, block_len, infile);
            if(bytes_read != (size_t) block_len)
            {
                perror("error: truncated block");
                goto error_cleanup;
            }

            out_buffer = tde_backup_decrypt_block(bkp_ctx, 
                                                  enc_buffer, 
                                                  (Size) bytes_read, 
                                                  block_seq, 
                                                  &out_len);
            if(out_buffer == NULL) {
                fprintf(stderr, "error: cannot decrypt block %llu\n", (unsigned long long) block_seq);
                close(pipefd[1]);
                fclose(infile);
                goto error_cleanup;
            }

            if(write(pipefd[1], out_buffer, out_len) != (ssize_t) out_len)
            {
                perror("error: write to pipe failed");
                close(pipefd[1]);
                fclose(infile);
                OPENSSL_cleanse(out_buffer, out_len);
                pfree(out_buffer);
                goto error_cleanup;
            }

            OPENSSL_cleanse(out_buffer, out_len);
            pfree(out_buffer);
            OPENSSL_cleanse(enc_buffer, block_len);

            block_seq++;
        }

        OPENSSL_cleanse(bkp_ctx, sizeof(TdeBackupContext));
        pfree(bkp_ctx);
        close(pipefd[1]);
        fclose(infile);
        pfree(pg_restore_args);

        if(waitpid(pid, &status, 0) == -1) {
            perror("error: waitpid failed");
            exit(EXIT_FAILURE);
        }

        if(WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "fatal error: pg_restore exited with status %d\n", 
                    WEXITSTATUS(status));
            exit(EXIT_FAILURE);
        }

        return 0;
    }

error_cleanup:
    OPENSSL_cleanse(bkp_ctx, sizeof(*bkp_ctx));
    pfree(bkp_ctx);
    pfree(pg_restore_args);
    exit(EXIT_FAILURE);
}