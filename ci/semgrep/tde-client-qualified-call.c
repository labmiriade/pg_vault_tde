void
seal(PGconn *conn, const char *call)
{
    // ruleid: tde-client-qualified-call
    res = PQexecParams(conn, "SELECT pg_vault_tde_seal_keys_bytea($1, $2)", 2, NULL, params, NULL, NULL, 1);
    // ruleid: tde-client-qualified-call
    res = PQexec(conn, "SELECT pg_vault_tde_health_check()");
    // ok: tde-client-qualified-call
    res = PQexecParams(conn, call, 2, NULL, params, NULL, NULL, 1);
    // ok: tde-client-qualified-call
    res = PQexec(conn, "SELECT n.nspname FROM pg_catalog.pg_extension e WHERE e.extname = 'pg_vault_tde'");
    // ok: tde-client-qualified-call
    res = PQexec(conn, "SHOW pg_vault_tde.kms_provider");
}
