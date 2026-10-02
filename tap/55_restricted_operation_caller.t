# tap/55_restricted_operation_caller.t — the session role is not the caller
# inside a security-restricted operation
#
# The privileged SQL functions ask about the calling role with
# GetOuterUserId() (tde_caller_is_superuser(), and the MAINTAIN check of
# reencrypt_table), because inside their own SECURITY DEFINER wrapper the
# current user is the function's owner (PSQLE-206).  ANALYZE, VACUUM, REINDEX
# and the index expressions they evaluate run as the table's owner in a
# security-restricted operation: the current user is that owner, while
# GetOuterUserId() stays the session role.  A table owner's code evaluated
# during a superuser's maintenance therefore passed checks made about the
# superuser (PSQLE-225).
#
# In a security-restricted operation these functions must refuse: the session
# role is not the caller there, and neither a key operation nor a table rewrite
# belongs inside an index expression.
use strict;
use warnings;
use Test::More tests => 10;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('restricted_caller');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n"
  . "autovacuum = off\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# A table of the superuser's that the other role has no privilege on, and a
# schema of its own for the maintenance target.
$node->safe_psql('postgres', q{
    CREATE ROLE owner_role LOGIN IN ROLE pg_monitor;
    CREATE SCHEMA os AUTHORIZATION owner_role;
    CREATE TABLE public.victim (id int, v text) USING encrypted_heap;
    INSERT INTO public.victim VALUES (1, 'kept');
    -- a DBA grant, so only the superuser check stands between the role and
    -- the key operation
    GRANT EXECUTE ON FUNCTION pg_vault_tde_wallet_lock() TO owner_role;});

# The role's own table, and the expression index whose function runs as the
# role during the superuser's maintenance of it.
$node->safe_psql('postgres', q{
    SET ROLE owner_role;
    CREATE FUNCTION os.probe(i int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS $$
    BEGIN
      BEGIN
        PERFORM public.pg_vault_tde_reencrypt_table('public.victim'::regclass, 100);
        RAISE WARNING 'PROBE rewrite: ALLOWED';
      EXCEPTION WHEN OTHERS THEN RAISE WARNING 'PROBE rewrite: refused';
      END;
      BEGIN
        PERFORM public.pg_vault_tde_wallet_lock();
        RAISE WARNING 'PROBE key: ALLOWED';
      EXCEPTION WHEN OTHERS THEN RAISE WARNING 'PROBE key: refused';
      END;
      RETURN i;
    END $$;
    CREATE TABLE os.t (a int);
    INSERT INTO os.t VALUES (1);
    CREATE INDEX os_t_probe ON os.t (os.probe(a));});

# ── Called directly, the role is refused: the baseline the checks promise ──
{
    my ($rc, undef, $err) = $node->psql('postgres',
        q{SET ROLE owner_role;
          SELECT public.pg_vault_tde_reencrypt_table('public.victim'::regclass, 100);});
    isnt($rc, 0, 'the role cannot rewrite the table it has no privilege on');
}
{
    my ($rc, undef, $err) = $node->psql('postgres',
        'SET ROLE owner_role; SELECT public.pg_vault_tde_wallet_lock();');
    isnt($rc, 0, '... nor run a key operation, despite the EXECUTE grant');
}

# ── The same code, evaluated during the superuser's maintenance ────────────
for my $stmt ('ANALYZE os.t', 'REINDEX TABLE os.t', 'VACUUM FULL os.t')
{
    my (undef, undef, $err) = $node->psql('postgres', $stmt);
    unlike($err, qr/PROBE rewrite: ALLOWED/,
        "$stmt does not lend the session role's privilege to the table owner's code");
    like($err, qr/PROBE key: refused/,
        "... and the key operation is refused there too");
}

# ── A superuser at the top level is unaffected ────────────────────────────
{
    my ($rc, undef, $err) = $node->psql('postgres',
        q{SELECT public.pg_vault_tde_reencrypt_table('public.victim'::regclass, 100);});
    is($rc, 0, 'a superuser still rewrites the table from a plain session')
        or diag("stderr: $err");
}
is($node->safe_psql('postgres', 'SELECT v FROM public.victim'), 'kept',
   '... and the table reads back');

$node->stop;
