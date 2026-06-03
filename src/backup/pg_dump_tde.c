#include "postgres_fe.h"
#include "libpq-fe.h"
#include "fe_utils/connect_utils.h"
#include "common/fe_memutils.h"
#include "common/logging.h"
#include "getopt_long.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/crypto.h>
#include <sys/wait.h>

#include "pg_vault_tde_backup.h"


int main(int argc, char **argv) {
    pg_logging_init(argv[0]);
    int pipefd[2];
    pid_t pid;
    FILE *outfile;
    tde_backup_header header;
    TdeBackupContext *bkp_ctx;
    char *output_file = NULL;
    int pg_dump_argc = 0;
    int c; 
    ConnParams cparams = {0};

    static struct option long_options[] = {
        {"host", required_argument, NULL, 'h'}, 
        {"port", required_argument, NULL, 'p'}, 
        {"username", required_argument, NULL, 'U'}, 
        {"dbname", required_argument, NULL, 'd'}, 
        {"output", required_argument, NULL, 'o'}, 
        {"jobs", required_argument, NULL, 'j'}, 

        {NULL, 0, NULL, 0} /*Sentinel of EOA used by getopt_long*/
    };
    
    /*
     * Each pg_dump_tde CLI flag translates to two entries in pg_dump_args
     * ("-X" + value), so argc * 2 is the worst-case upper bound.  The extra 5
     * covers argv[0] ("pg_dump"), "-Fc", a trailing NULL, and two spares.
     */
    char **pg_dump_args = palloc((argc * 2 + 5) * sizeof(char *));

    bkp_ctx = palloc(sizeof(*bkp_ctx));
    /*
     * Custom format (-Fc) is mandatory: it is the only pg_dump output format
     * that streams a single byte sequence suitable for piping to the parent
     * process for block-level encryption.
     */
    pg_dump_args[pg_dump_argc++] = "pg_dump";
    pg_dump_args[pg_dump_argc++] = "-Fc";


    /*Parse, sanitize and extract pg_dump_tde-specific arguments */
    while((c = getopt_long(argc, argv, "h:p:U:d:o:j:", long_options, NULL )) != -1)
    {
        switch (c)
        {
        case 'h':
            cparams.pghost = optarg;  /*optarg is defined outside this file, contains the parameter*/
            pg_dump_args[pg_dump_argc++] = "-h";
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'p':
            cparams.pgport = optarg;
            pg_dump_args[pg_dump_argc++] = "-p";
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'U':
            cparams.pguser = optarg;
            pg_dump_args[pg_dump_argc++] = "-U";
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'd':
            cparams.dbname = optarg;    
            pg_dump_args[pg_dump_argc++] = "-d";
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'o':
            output_file = optarg;  
            break;      
        case 'j':
            fprintf(stderr, "error: option j is not supported \n");
            goto error_cleanup;
        
        case '?':
            fprintf(stderr, "error: %c invalid option\n", c);
            goto error_cleanup;
    
        default:
            break;
        }
    }

    for(int i=optind; i < argc; i++)
    {
        pg_dump_args[pg_dump_argc++] = argv[i];
    }

    pg_dump_args[pg_dump_argc] = NULL; /* execvp requires a NULL terminator */

    /* --output is mandatory: there is no default output path. */
    if (!output_file) {
        fprintf(stderr, "error: --output is required\n");
        goto error_cleanup;
    }

    outfile = fopen(output_file, "wb");
    if (!outfile) {
        perror("error: could not open output file");
        goto error_cleanup;
    }

    if(!tde_backup_init(&cparams))
    {
        fprintf(stderr, "fatal error: could not initialize TDE backup\n");
        fclose(outfile);
        goto error_cleanup;
    }

    if (!tde_backup_header_init(&header, bkp_ctx)) {
        fprintf(stderr, "fatal error: could not initialize TDE backup header\n");
        fclose(outfile);
        goto error_cleanup;
    }

    if (fwrite(&header, sizeof(tde_backup_header), 1, outfile) != 1) {
        perror("error: could not write backup header");
        fclose(outfile);
        goto error_cleanup;
    }

    if (pipe(pipefd) == -1) {
        perror("error: could not create pipe");
        fclose(outfile);
        goto error_cleanup;
    }

    pid = fork();
    if (pid == -1) {
        perror("error: fork failed");
        /* close the pipe ends we just opened */
        close(pipefd[0]);
        close(pipefd[1]);
        fclose(outfile);
        goto error_cleanup;
    }

    if (pid == 0) {
        /*
         * Child process: exec pg_dump with stdout redirected to the write
         * end of the pipe.  Close the read end and outfile — the child does
         * not write to the output file directly.
         */
        fclose(outfile);
        OPENSSL_cleanse(bkp_ctx, sizeof(*bkp_ctx));
        pfree(bkp_ctx);

        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        execvp("pg_dump", pg_dump_args);

        /*
         * execvp only returns on failure.  pg_dump_args was already pfreed
         * above so we cannot pfree it again here.
         */
        perror("error: could not execute pg_dump");
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);

    } else {
        /* Parent process: read pg_dump output, encrypt each block, write to file. */
        char     in_buffer[TDE_BACKUP_BLOCK_SIZE];
        /* issue 8: use the named constant so the size is verified at compile time */
        char     *out_buffer = NULL;
        ssize_t  bytes_read;
        Size     out_len;
        uint64   block_seq = 0;
        int      status;

        close(pipefd[1]);

        while ((bytes_read = read(pipefd[0], in_buffer, TDE_BACKUP_BLOCK_SIZE)) > 0) {
            out_buffer = tde_backup_encrypt_block(
                bkp_ctx,
                in_buffer,
                (Size) bytes_read,
                block_seq,
                &out_len
            );

            if (out_buffer == NULL) {
                close(pipefd[0]);
                fclose(outfile);
                goto error_cleanup;
            }

            if (fwrite(out_buffer, 1, out_len, outfile) != out_len) {
                perror("error: could not write encrypted block");
                close(pipefd[0]);
                fclose(outfile);
                pfree(out_buffer);
                
                goto error_cleanup;
            }
            pfree(out_buffer);
            block_seq++;

            OPENSSL_cleanse(in_buffer, sizeof(in_buffer));
        }

        OPENSSL_cleanse(bkp_ctx, sizeof(*bkp_ctx));
        pfree(bkp_ctx);

        if (bytes_read < 0)
            perror("warning: read error on pipe");

        close(pipefd[0]);
        fclose(outfile);
        pfree(pg_dump_args);

        if (waitpid(pid, &status, 0) == -1) {
            perror("error: waitpid failed");
            unlink(output_file); /* partial file is unusable; remove to avoid confusion */
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "fatal error: pg_dump exited with status %d\n",
                    WEXITSTATUS(status));
            unlink(output_file); /* pg_dump failed mid-stream; file is incomplete */
            exit(EXIT_FAILURE);
        }
    }

    return 0;

error_cleanup:
    OPENSSL_cleanse(bkp_ctx, sizeof(*bkp_ctx));
    pfree(bkp_ctx);
    pfree(pg_dump_args);
    exit(EXIT_FAILURE);

}