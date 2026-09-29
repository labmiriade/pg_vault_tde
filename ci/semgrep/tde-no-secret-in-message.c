void
report(const char *passphrase, const char *path, const char *pg_vault_tde_vault_token)
{
    // ruleid: tde-no-secret-in-message
    ereport(ERROR, errmsg("wallet %s opened with %s", path, passphrase));
    // ruleid: tde-no-secret-in-message
    elog(LOG, "token %s", pg_vault_tde_vault_token);
    // ruleid: tde-no-secret-in-message
    fprintf(stderr, "%s: passphrase %s\n", progname, passphrase);
    // ok: tde-no-secret-in-message
    ereport(ERROR, errmsg("wrong passphrase for wallet \"%s\"", path));
}
