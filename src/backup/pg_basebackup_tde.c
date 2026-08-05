/*
 * pg_basebackup_tde - pg_basebackup wrapper with TDE key sealing
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License.
 *
 * Wraps pg_basebackup so that a physical backup is accompanied by one sealed
 * bundle of wrapped DEKs per database (pg_vault_tde_seal_keys_bytea).  The
 * bundles are HMAC-SHA256 signed and contain ONLY wrapped DEKs — never the
 * KEK, which must be provisioned on the restore host separately (wallet copy
 * for the local provider; same Vault for the vault provider).
 *
 * Flow:
 *   1. Parse the CLI.  Every flag is forwarded verbatim to pg_basebackup;
 *      -D/-h/-p/-U/-d/-l are additionally captured for our own libpq
 *      connections, --keys-dir is consumed (not forwarded).
 *   2. Enumerate databases; for each one with the pg_vault_tde extension
 *      fetch the sealed bundle INTO MEMORY.  Any failure aborts before the
 *      backup starts.
 *   3. fork/exec pg_basebackup and wait for it.
 *   4. Only on success, write each bundle to
 *      <keys-dir>/pg_vault_tde_keys.<datname>.sealed with mode 0600.
 *
 * Sealing happens before the backup (a key rotation completing after the
 * seal but before the backup ends is the documented edge case: re-run the
 * backup), while the files are written after it, because pg_basebackup
 * requires the target directory to be empty — this also means a failed
 * backup leaves no bundle files behind.
 *
 * The seal passphrase is read from --seal-passphrase-file (first line of the
 * file) or, failing that, from PG_VAULT_TDE_SEAL_PASSPHRASE.  It is never
 * accepted as a CLI value, to avoid leaking it in `ps` output and shell
 * history.
 *
 * Restore stays manual: restore the data dir, provision the KEK, then for
 * each database run
 *   SELECT pg_vault_tde_unseal_keys('<path>/pg_vault_tde_keys.<db>.sealed', '<passphrase>');
 */
#include "postgres_fe.h"
#include "libpq-fe.h"
#include "common/fe_memutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define SEAL_PASSPHRASE_ENV "PG_VAULT_TDE_SEAL_PASSPHRASE"
#define SEAL_FILE_PREFIX    "pg_vault_tde_keys."
#define SEAL_FILE_SUFFIX    ".sealed"

typedef struct SealedBundle
{
    char   *datname;
    char   *data;
    size_t  len;
} SealedBundle;

static const char *progname = "pg_basebackup_tde";

static void
usage(void)
{
    printf("%s: run pg_basebackup and seal the pg_vault_tde wrapped DEKs alongside it.\n\n"
           "Usage:\n"
           "  %s [PG_BASEBACKUP_OPTIONS] [--keys-dir DIR]\n\n"
           "All options are forwarded to pg_basebackup.  In addition:\n"
           "  --keys-dir DIR              where to write the sealed key bundles\n"
           "                              (default: the -D/--pgdata directory)\n"
           "  --seal-passphrase-file FILE read the seal passphrase from the first\n"
           "                              line of FILE (keep it chmod 0600)\n\n"
           "Without --seal-passphrase-file, the passphrase is read from the\n"
           "environment variable %s.  One of the two is required;\n"
           "the passphrase is never accepted on the command line.\n\n"
           "One bundle per database is written as pg_vault_tde_keys.<datname>.sealed\n"
           "(mode 0600) after pg_basebackup completes successfully.  Databases\n"
           "without the pg_vault_tde extension are skipped.\n",
           progname, progname, SEAL_PASSPHRASE_ENV);
}

/*
 * If argv[*i] is short option "sopt" (e.g. "-D", also glued "-Dvalue") or
 * long option "lopt" (both "--pgdata value" and "--pgdata=value"), return
 * its value and advance *i past it.  Otherwise return NULL.
 */
static char *
opt_value(char **argv, int argc, int *i, const char *sopt, const char *lopt)
{
    char *arg = argv[*i];
    size_t lopt_len = strlen(lopt);

    if (sopt != NULL && strncmp(arg, sopt, 2) == 0)
    {
        if (arg[2] != '\0')
            return arg + 2;                  /* -Dvalue */
        if (*i + 1 < argc)
            return argv[++(*i)];             /* -D value */
        return NULL;
    }
    if (strncmp(arg, lopt, lopt_len) == 0)
    {
        if (arg[lopt_len] == '=')
            return arg + lopt_len + 1;       /* --pgdata=value */
        if (arg[lopt_len] == '\0' && *i + 1 < argc)
            return argv[++(*i)];             /* --pgdata value */
    }
    return NULL;
}

/*
 * Map a database name to a filename-safe form: anything outside
 * [A-Za-z0-9_.-] becomes '_'.  Database names may contain arbitrary bytes;
 * the sealed filename only needs to be recognizable, the authoritative name
 * is not parsed back from it.
 */
static char *
sanitize_datname(const char *datname)
{
    char *out = pg_strdup(datname);

    for (char *p = out; *p; p++)
    {
        unsigned char c = (unsigned char) *p;

        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
            *p = '_';
    }
    return out;
}

/*
 * Read the seal passphrase from the first line of path (the ~/.pgpass
 * pattern: safer than a CLI value, which would leak in `ps` output and
 * shell history).  Trailing newline/CR are stripped.  Returns NULL after
 * printing an error.
 */
static char *
read_passphrase_file(const char *path)
{
    FILE   *fp;
    char    line[1024];
    size_t  len;

    fp = fopen(path, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "%s: error: could not open passphrase file \"%s\": %s\n",
                progname, path, strerror(errno));
        return NULL;
    }
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        fprintf(stderr, "%s: error: passphrase file \"%s\" is empty\n",
                progname, path);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
    if (len == 0)
    {
        fprintf(stderr, "%s: error: passphrase file \"%s\" has an empty first line\n",
                progname, path);
        return NULL;
    }
    return pg_strdup(line);
}

/*
 * Open a libpq connection to dbname, layering the captured -h/-p/-U flags
 * (and, for the maintenance connection, an optional -d connection string)
 * over the environment.  Returns NULL after printing an error.
 */
static PGconn *
connect_db(const char *host, const char *port, const char *user,
           const char *conn_dbname, const char *dbname)
{
    const char *keys[8];
    const char *vals[8];
    int         n = 0;
    PGconn     *conn;

    /*
     * A -d value may be a full connection string; give it first so that
     * expand_dbname applies, then let the specific keywords override it
     * (libpq honors the last occurrence of a keyword).
     */
    if (conn_dbname != NULL)
    {
        keys[n] = "dbname";   vals[n] = conn_dbname; n++;
    }
    if (host != NULL) { keys[n] = "host"; vals[n] = host; n++; }
    if (port != NULL) { keys[n] = "port"; vals[n] = port; n++; }
    if (user != NULL) { keys[n] = "user"; vals[n] = user; n++; }
    if (dbname != NULL) { keys[n] = "dbname"; vals[n] = dbname; n++; }
    keys[n] = "fallback_application_name"; vals[n] = progname; n++;
    keys[n] = NULL; vals[n] = NULL;

    conn = PQconnectdbParams(keys, vals, 1);
    if (PQstatus(conn) != CONNECTION_OK)
    {
        fprintf(stderr, "%s: error: connection to database \"%s\" failed: %s",
                progname, dbname ? dbname : (conn_dbname ? conn_dbname : ""),
                PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }
    return conn;
}

int
main(int argc, char **argv)
{
    char  **bb_args;
    int     bb_argc = 0;
    char   *pgdata = NULL;
    char   *keys_dir = NULL;
    char   *host = NULL;
    char   *port = NULL;
    char   *user = NULL;
    char   *conn_dbname = NULL;
    char   *label = NULL;
    char   *pass_file = NULL;
    const char *passphrase;
    SealedBundle *bundles = NULL;
    int     nbundles = 0;
    PGconn *conn;
    PGresult *res;
    char  **datnames;
    int     ndbs;
    pid_t   pid;
    int     status;

    /* worst case every argv entry is forwarded, plus argv[0] and NULL */
    bb_args = pg_malloc((argc + 2) * sizeof(char *));
    bb_args[bb_argc++] = "pg_basebackup";

    for (int i = 1; i < argc; i++)
    {
        char *arg = argv[i];
        char *val;
        int   before = i;

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-?") == 0)
        {
            usage();
            return 0;
        }

        if ((val = opt_value(argv, argc, &i, NULL, "--keys-dir")) != NULL)
        {
            keys_dir = val;         /* consumed, NOT forwarded */
            continue;
        }
        if ((val = opt_value(argv, argc, &i, NULL, "--seal-passphrase-file")) != NULL)
        {
            pass_file = val;        /* consumed, NOT forwarded */
            continue;
        }

        /* captured AND forwarded */
        if ((val = opt_value(argv, argc, &i, "-D", "--pgdata")) != NULL)
            pgdata = val;
        else if ((val = opt_value(argv, argc, &i, "-h", "--host")) != NULL)
            host = val;
        else if ((val = opt_value(argv, argc, &i, "-p", "--port")) != NULL)
            port = val;
        else if ((val = opt_value(argv, argc, &i, "-U", "--username")) != NULL)
            user = val;
        else if ((val = opt_value(argv, argc, &i, "-d", "--dbname")) != NULL)
            conn_dbname = val;
        else if ((val = opt_value(argv, argc, &i, "-l", "--label")) != NULL)
            label = val;
        else if ((val = opt_value(argv, argc, &i, "-F", "--format")) != NULL)
        {
            if (strcmp(val, "t") == 0 || strcmp(val, "tar") == 0)
            {
                fprintf(stderr, "%s: error: --format=tar is not supported; "
                        "use the plain format or run pg_vault_tde_seal_keys() manually\n",
                        progname);
                return 1;
            }
        }

        /* forward the original argv slice (handles both "-D x" and "-Dx") */
        for (int j = before; j <= i; j++)
            bb_args[bb_argc++] = argv[j];
    }
    bb_args[bb_argc] = NULL;

    if (pgdata == NULL)
    {
        fprintf(stderr, "%s: error: no target directory specified (-D/--pgdata)\n",
                progname);
        return 1;
    }
    if (keys_dir == NULL)
        keys_dir = pgdata;

    if (pass_file != NULL)
    {
        passphrase = read_passphrase_file(pass_file);
        if (passphrase == NULL)
            return 1;
    }
    else
    {
        passphrase = getenv(SEAL_PASSPHRASE_ENV);
        if (passphrase == NULL || passphrase[0] == '\0')
        {
            fprintf(stderr, "%s: error: no seal passphrase: use --seal-passphrase-file "
                    "or set the environment variable %s\n",
                    progname, SEAL_PASSPHRASE_ENV);
            return 1;
        }
    }

    /* ── 1. Enumerate databases ──────────────────────────────────────── */
    conn = connect_db(host, port, user, conn_dbname,
                      conn_dbname != NULL ? NULL : "postgres");
    if (conn == NULL)
        return 1;

    res = PQexec(conn,
                 "SELECT datname FROM pg_database "
                 "WHERE datallowconn AND datname <> 'template0' "
                 "ORDER BY datname");
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "%s: error: could not list databases: %s",
                progname, PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    ndbs = PQntuples(res);
    datnames = pg_malloc(ndbs * sizeof(char *));
    for (int i = 0; i < ndbs; i++)
        datnames[i] = pg_strdup(PQgetvalue(res, i, 0));
    PQclear(res);
    PQfinish(conn);

    /* ── 2. Seal each database's keys into memory ────────────────────── */
    bundles = pg_malloc(ndbs * sizeof(SealedBundle));

    for (int i = 0; i < ndbs; i++)
    {
        const char *params[2];

        conn = connect_db(host, port, user, NULL, datnames[i]);
        if (conn == NULL)
            return 1;

        res = PQexec(conn,
                     "SELECT 1 FROM pg_extension WHERE extname = 'pg_vault_tde'");
        if (PQresultStatus(res) != PGRES_TUPLES_OK)
        {
            fprintf(stderr, "%s: error: extension check failed in \"%s\": %s",
                    progname, datnames[i], PQerrorMessage(conn));
            PQclear(res);
            PQfinish(conn);
            return 1;
        }
        if (PQntuples(res) == 0)
        {
            PQclear(res);
            PQfinish(conn);
            continue;               /* no pg_vault_tde here: skip */
        }
        PQclear(res);

        params[0] = passphrase;
        params[1] = label != NULL ? label : "basebackup";
        res = PQexecParams(conn,
                           "SELECT pg_vault_tde_seal_keys_bytea($1, $2)",
                           2, NULL, params, NULL, NULL,
                           1 /* binary result: raw bundle bytes */);
        if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1)
        {
            fprintf(stderr, "%s: error: sealing keys of database \"%s\" failed: %s",
                    progname, datnames[i], PQerrorMessage(conn));
            PQclear(res);
            PQfinish(conn);
            return 1;
        }

        bundles[nbundles].datname = datnames[i];
        bundles[nbundles].len = (size_t) PQgetlength(res, 0, 0);
        bundles[nbundles].data = pg_malloc(bundles[nbundles].len);
        memcpy(bundles[nbundles].data, PQgetvalue(res, 0, 0),
               bundles[nbundles].len);
        nbundles++;

        PQclear(res);
        PQfinish(conn);

        fprintf(stderr, "%s: sealed keys of database \"%s\"\n",
                progname, datnames[i]);
    }

    if (nbundles == 0)
        fprintf(stderr, "%s: warning: no database has the pg_vault_tde extension; "
                "no key bundle will be written\n", progname);

    /* ── 3. Run pg_basebackup ────────────────────────────────────────── */
    pid = fork();
    if (pid == -1)
    {
        fprintf(stderr, "%s: error: fork failed\n", progname);
        return 1;
    }
    if (pid == 0)
    {
        execvp("pg_basebackup", bb_args);
        /* execvp only returns on failure */
        perror("pg_basebackup_tde: error: could not execute pg_basebackup");
        _exit(127);
    }
    if (waitpid(pid, &status, 0) == -1)
    {
        perror("pg_basebackup_tde: error: waitpid failed");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        fprintf(stderr, "%s: error: pg_basebackup failed; no key bundle written\n",
                progname);
        return 1;
    }

    /* ── 4. Write the bundles next to the backup ─────────────────────── */
    for (int i = 0; i < nbundles; i++)
    {
        char   *safe = sanitize_datname(bundles[i].datname);
        char   *path = psprintf("%s/%s%s%s", keys_dir,
                                SEAL_FILE_PREFIX, safe, SEAL_FILE_SUFFIX);
        int     fd;
        ssize_t written;

        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
        {
            fprintf(stderr, "%s: error: could not create \"%s\": %s\n",
                    progname, path, strerror(errno));
            fprintf(stderr, "%s: hint: the backup itself succeeded; re-seal manually "
                    "with pg_vault_tde_seal_keys()\n", progname);
            return 1;
        }
        written = write(fd, bundles[i].data, bundles[i].len);
        if (written < 0 || (size_t) written != bundles[i].len)
        {
            fprintf(stderr, "%s: error: could not write \"%s\": %s\n",
                    progname, path, strerror(errno));
            close(fd);
            unlink(path);
            return 1;
        }
        if (close(fd) != 0)
        {
            fprintf(stderr, "%s: error: could not close \"%s\": %s\n",
                    progname, path, strerror(errno));
            unlink(path);
            return 1;
        }
        fprintf(stderr, "%s: wrote %s\n", progname, path);
        free(safe);
        pfree(path);
    }

    fprintf(stderr, "%s: backup complete, %d key bundle(s) written\n",
            progname, nbundles);
    return 0;
}
