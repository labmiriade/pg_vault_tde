#include "postgres_fe.h"
#include "libpq-fe.h"
#include "fe_utils/connect_utils.h"
#include "common/fe_memutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/wait.h>
#include "pg_vault_tde_backup.h"
#include "getopt_long.h"


int main(int argc, char **argv) {
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
        {"jobs", required_argument, NULL, 'j'}
    };
    
    char **pg_dump_args = palloc((argc + 5) * sizeof(char *));

    bkp_ctx = palloc(sizeof(*bkp_ctx));
    /*
     * Custom format (-Fc) is mandatory: it is the only pg_dump output format
     * that streams a single byte sequence suitable for piping to the parent
     * process for block-level encryption.
     */
    pg_dump_args[pg_dump_argc++] = "-Fc";


    /*Parse, sanitize and extract pg_dump_tde-specific arguments */
    while((c = getopt_long(argc, argv, "h:p:U:d:o:j:", long_options, NULL )) != -1)
    {
        switch (c)
        {
        case 'h':
            cparams.pghost = optarg;  /*optarg is defined outside this file, contains the parameter*/
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'p':
            cparams.pgport = optarg;
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'U':
            cparams.pguser = optarg;
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'd':
            cparams.dbname = optarg;    
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        case 'o':
            output_file = optarg;  
            break;      
        case 'j':
            fprintf(stderr, "error: option j is not supported \n");
            pfree(pg_dump_args);
            exit(EXIT_FAILURE);
    
        default:
            pg_dump_args[pg_dump_argc++] = optarg;
            break;
        }
    }

    pg_dump_args[pg_dump_argc] = NULL; /* execvp requires a NULL terminator */

    /* --output is mandatory: there is no default output path. */
    if (!output_file) {
        fprintf(stderr, "error: --output is required\n");
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    outfile = fopen(output_file, "wb");
    if (!outfile) {
        perror("error: could not open output file");
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if(!tde_backup_init(&cparams))
    {
        fprintf(stderr, "fatal error: could not initialize TDE backup\n");
        fclose(outfile);
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);
    }
    

    if (!tde_backup_header_init(&header, bkp_ctx)) {
        fprintf(stderr, "fatal error: could not initialize TDE backup header\n");
        fclose(outfile);
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if (fwrite(&header, sizeof(tde_backup_header), 1, outfile) != 1) {
        perror("error: could not write backup header");
        fclose(outfile);
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if (pipe(pipefd) == -1) {
        perror("error: could not create pipe");
        fclose(outfile);
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        perror("error: fork failed");
        /* close the pipe ends we just opened */
        close(pipefd[0]);
        close(pipefd[1]);
        fclose(outfile);
        pfree(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        /*
         * Child process: exec pg_dump with stdout redirected to the write
         * end of the pipe.  Close the read end and outfile — the child does
         * not write to the output file directly.
         */
        fclose(outfile);
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
                exit(EXIT_FAILURE);
            }

            if (fwrite(out_buffer, 1, out_len, outfile) != out_len) {
                perror("error: could not write encrypted block");
                close(pipefd[0]);
                fclose(outfile);
                pfree(pg_dump_args);
                exit(EXIT_FAILURE);
            }
            pfree(out_buffer);
            block_seq++;
        }

        if (bytes_read < 0)
            perror("warning: read error on pipe");

        close(pipefd[0]);
        fclose(outfile);
        pfree(pg_dump_args);

        if (waitpid(pid, &status, 0) == -1) {
            perror("error: waitpid failed");
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "fatal error: pg_dump exited with status %d\n",
                    WEXITSTATUS(status));
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}