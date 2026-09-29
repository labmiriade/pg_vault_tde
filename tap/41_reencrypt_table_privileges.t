# tap/41_reencrypt_table_privileges.t — pg_vault_tde_reencrypt_table()
# rewrites a table only for a role allowed to maintain it
#
# The function rewrites every row: locks, WAL, dead versions until VACUUM.
# The extension script grants EXECUTE on both overloads to pg_monitor, and
# the text overload is SECURITY DEFINER; the C code checked nothing, so a
# monitoring role with no privilege on a table rewrote it, and any future
# GRANT EXECUTE would do the same for another role (PSQLE-205).  The check
# now is core's for VACUUM FULL, CLUSTER and REINDEX: MAINTAIN on the table,
# which its owner, pg_maintain members and superusers hold — asked of the
# calling role, which inside the SECURITY DEFINER overload is not the
# current one.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 9;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('reencrypt_privs');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

# mon: pg_monitor, as shipped.  exec_only: EXECUTE granted, nothing on the
# table.  owner: owns the table.  maint: pg_maintain.  The last three get
# EXECUTE explicitly — it is what a site granting the function would do.
$node->safe_psql('postgres', q{
    CREATE ROLE mon LOGIN IN ROLE pg_monitor;
    CREATE ROLE exec_only LOGIN;
    CREATE ROLE owner LOGIN;
    CREATE ROLE maint LOGIN IN ROLE pg_maintain;
    GRANT EXECUTE ON FUNCTION pg_vault_tde_reencrypt_table(regclass, int),
                              pg_vault_tde_reencrypt_table(text, int)
          TO exec_only, owner, maint;
    CREATE TABLE secret (id int, v text) USING encrypted_heap;
    INSERT INTO secret SELECT g, 'v' || g FROM generate_series(1, 100) g;
    CREATE TABLE secret_truth AS SELECT * FROM secret;
    ALTER TABLE secret OWNER TO owner;
    REVOKE ALL ON secret FROM PUBLIC;
});

sub reencrypt_as
{
    my ($role, $arg) = @_;
    my ($rc, $out, $err) = $node->psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_reencrypt_table($arg)",
        extra_params => ['-U', $role]);
    return ($rc, $err);
}

my ($rc, $err) = reencrypt_as('mon', "'secret'::regclass");
like($err, qr/permission denied for table secret/, 'pg_monitor: refused (regclass overload)');
($rc, $err) = reencrypt_as('mon', "'secret'");
like($err, qr/permission denied for table secret/,
     'pg_monitor: refused (text overload, SECURITY DEFINER)');
($rc, $err) = reencrypt_as('exec_only', "'secret'::regclass");
like($err, qr/permission denied for table secret/,
     'EXECUTE without MAINTAIN on the table: refused');

($rc, $err) = reencrypt_as('owner', "'secret'::regclass");
is($rc, 0, 'the table owner may rewrite it') or diag $err;
($rc, $err) = reencrypt_as('maint', "'secret'");
is($rc, 0, 'a pg_maintain member may rewrite it') or diag $err;
($rc, $err) = reencrypt_as($node->safe_psql('postgres', 'SELECT current_user'), "'secret'::regclass");
is($rc, 0, 'a superuser may rewrite it') or diag $err;

is($node->safe_psql('postgres', q{
       SELECT count(*) FROM (
           (SELECT * FROM secret EXCEPT ALL SELECT * FROM secret_truth)
           UNION ALL
           (SELECT * FROM secret_truth EXCEPT ALL SELECT * FROM secret)) d}), '0',
   'the table still equals its plain twin');

# The rotation worker calls the rewrite directly, not through SQL.
$node->safe_psql('postgres',
    "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('secret')");
ok($node->poll_query_until('postgres', q{
       SELECT status = 'complete' FROM pg_vault_tde_rotation_progress
       WHERE relid = 'secret'::regclass::oid}),
   'rotate_online() still rewrites the table');
is($node->safe_psql('postgres', 'SELECT count(*) FROM secret'), '100',
   'every row reads after the rotation');

$node->stop;
