#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include "pg_vault_tde_backup.h"

int main(int argc, char **argv) {
    int pipefd[2];
    pid_t pid;
    FILE *outfile;
    tde_backup_header header;
    char *output_file = NULL;
    
    /*
     * Build the argument list for pg_dump.  Allocate enough room for the
     * original argv entries plus the arguments we unconditionally prepend
     * ("pg_dump", "-Fc") and the NULL terminator.
     */
    char **pg_dump_args = malloc((argc + 5) * sizeof(char *));
    if(!pg_dump_args) exit(EXIT_FAILURE);

    int pg_dump_argc = 0;

    /*
     * Custom format (-Fc) is mandatory: it is the only pg_dump output format
     * that streams a single byte sequence suitable for piping to the parent
     * process for block-level encryption.
     */
    pg_dump_args[pg_dump_argc++] = "pg_dump";
    pg_dump_args[pg_dump_argc++] = "-Fc";

    /* Parse, sanitize, and extract pg_dump_tde-specific arguments. */
    for (int i = 1; i < argc; i++) {
        /*
         * Reject -j / --jobs: parallel pg_dump writes to a directory, not
         * stdout, so it cannot be piped through the encryption stage.
         */
        if (strcmp(argv[i], "-j") == 0 || strncmp(argv[i], "--jobs", 6) == 0) {
            fprintf(stderr, "error: option '%s' is not supported "
                    "(parallel mode is incompatible with pipe-based encryption)\n",
                    argv[i]);
            free(pg_dump_args);
            exit(EXIT_FAILURE);
        }

        /* -o / --output is a pg_dump_tde-specific option: capture the path. */
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                fprintf(stderr, "error: missing filename after '%s'\n",
                        argv[i - 1]);
                free(pg_dump_args);
                exit(EXIT_FAILURE);
            }
        }

        /*
         * Silently drop any -F / -Fc / --format=c the caller passes: we
         * already locked the format above and forwarding it would cause
         * pg_dump to receive a duplicate option.
         */
        else if (strcmp(argv[i], "-F") == 0 || strcmp(argv[i], "-Fc") == 0 ||
                 strcmp(argv[i], "--format=c") == 0) {
            /* Skip the argument value that follows a bare -F. */
            if (strcmp(argv[i], "-F") == 0 && (i + 1 < argc))
                i++;
            continue;
        }

        /* Forward all other arguments to pg_dump unchanged. */
        else {
            pg_dump_args[pg_dump_argc++] = argv[i];
        }
    }
    pg_dump_args[pg_dump_argc] = NULL; /* execvp requires a NULL terminator */


    /* --output is mandatory: there is no default output path. */
    if (!output_file) {
        fprintf(stderr, "error: --output is required\n");
        free(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    outfile = fopen(output_file, "wb");
    if (!outfile) {
        perror("error: could not open output file");
        free(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if (!tde_backup_header_init(&header)) {
        fprintf(stderr, "fatal error: could not initialize TDE backup header\n");
        fclose(outfile);
        free(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if (fwrite(&header, sizeof(tde_backup_header), 1, outfile) != 1) {
        perror("error: could not write backup header");
        fclose(outfile);
        free(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if (pipe(pipefd) == -1) {
        perror("error: could not create pipe");
        fclose(outfile);
        free(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        perror("error: fork failed");
        /* issue 7: close the pipe ends we just opened */
        close(pipefd[0]);
        close(pipefd[1]);
        fclose(outfile);
        free(pg_dump_args);
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        /*
         * Child process: exec pg_dump with stdout redirected to the write
         * end of the pipe.  Close the read end and outfile — the child does
         * not write to the output file directly.
         */
        fclose(outfile);
        free(pg_dump_args);

        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        execvp("pg_dump", pg_dump_args);

        /*
         * execvp only returns on failure.  pg_dump_args was already freed
         * above so we cannot free it again here.
         */
        perror("error: could not execute pg_dump");
        exit(EXIT_FAILURE);

    } else {
        /* Parent process: read pg_dump output, encrypt each block, write to file. */
        char     in_buffer[TDE_BACKUP_BLOCK_SIZE];
        /* issue 8: use the named constant so the size is verified at compile time */
        char     out_buffer[TDE_BACKUP_BLOCK_SIZE + TDE_BACKUP_ENCRYPT_OVERHEAD];
        ssize_t  bytes_read;
        Size     out_len;
        uint64   block_seq = 0;
        int      status;

        close(pipefd[1]);

        while ((bytes_read = read(pipefd[0], in_buffer, TDE_BACKUP_BLOCK_SIZE)) > 0) {
            tde_backup_encrypt_block(
                header.wrapped_dek,
                header.wrapped_dek_len,
                in_buffer,
                (Size) bytes_read,
                block_seq,
                out_buffer,
                &out_len
            );

            if (fwrite(out_buffer, 1, out_len, outfile) != out_len) {
                perror("error: could not write encrypted block");
                close(pipefd[0]);
                fclose(outfile);
                free(pg_dump_args);
                exit(EXIT_FAILURE);
            }

            block_seq++;
        }

        if (bytes_read < 0)
            perror("warning: read error on pipe");

        close(pipefd[0]);
        fclose(outfile);
        free(pg_dump_args);

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