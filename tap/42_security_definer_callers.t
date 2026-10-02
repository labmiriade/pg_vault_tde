# tap/42_security_definer_callers.t — the key-management functions refuse
# every caller but a superuser, whoever has been granted EXECUTE
#
# Most of them are SECURITY DEFINER and check superuser() — which, inside a
# SECURITY DEFINER function, is asked of the function's owner, the superuser
# who ran CREATE EXTENSION: always true.  Only REVOKE ... FROM PUBLIC kept
# them closed, and pg_vault_tde_wallet_init() is granted to pg_monitor: a
# monitoring role created a database's wallet with a passphrase of its own
# (PSQLE-206).  pg_vault_tde_pkcs11_keygen() checked nothing at all.  The
# check now asks about the calling role (GetOuterUserId()).
#
# A pg_monitor member tries wallet_init() as shipped; a role granted EXECUTE
# on every one of them tries each.  All must be refused, and nothing must
# have been created; a superuser still succeeds.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my @calls = (
    "pg_vault_tde_wallet_init('chosen')",
    "pg_vault_tde_wallet_change_passphrase('test-password', 'chosen')",
    "pg_vault_tde_wallet_unlock('test-password')",
    "pg_vault_tde_wallet_lock()",
    "pg_vault_tde_migrate_vault_to_wallet('test-password')",
    "pg_vault_tde_seal_keys('/tmp/tde_sealed_by_exec', 'seal-pass')",
    "pg_vault_tde_seal_keys_bytea('seal-pass')",
    "pg_vault_tde_unseal_keys('/tmp/tde_sealed_by_exec', 'seal-pass')",
    "pg_vault_tde_pkcs11_keygen()",
    "pg_vault_tde_rotate_kek()",
);

plan tests => 4 + scalar(@calls);

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('secdef_callers');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', q{
    CREATE ROLE mon LOGIN IN ROLE pg_monitor;
    CREATE ROLE exec LOGIN;
    CREATE DATABASE nowallet;
});
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('nowallet', 'CREATE EXTENSION pg_vault_tde;');
for my $db (qw(postgres nowallet))
{
    $node->safe_psql($db, q{
        GRANT EXECUTE ON FUNCTION
            pg_vault_tde_wallet_init(text),
            pg_vault_tde_wallet_change_passphrase(text, text),
            pg_vault_tde_wallet_unlock(text),
            pg_vault_tde_wallet_lock(),
            pg_vault_tde_migrate_vault_to_wallet(text),
            pg_vault_tde_seal_keys(text, text, text),
            pg_vault_tde_seal_keys_bytea(text, text),
            pg_vault_tde_unseal_keys(text, text),
            pg_vault_tde_pkcs11_keygen(),
            pg_vault_tde_rotate_kek()
        TO exec;
    });
}

my $wallet_of = sub {
    my ($db) = @_;
    return $node->safe_psql($db, q{SELECT count(*) FROM pg_ls_dir('/var/lib/pg_vault_tde') d
        WHERE d = (SELECT oid::text FROM pg_database WHERE datname = current_database())});
};

my ($rc, $out, $err) = $node->psql('nowallet', "SELECT pg_vault_tde_wallet_init('chosen')",
                                   extra_params => ['-U', 'mon']);
like($err, qr/requires superuser/, 'pg_monitor: wallet_init() refused');
is($wallet_of->('nowallet'), '0', '... and no wallet was created');

for my $call (@calls)
{
    my $db = $call =~ /wallet_init/ ? 'nowallet' : 'postgres';
    ($rc, $out, $err) = $node->psql($db, "SELECT $call", extra_params => ['-U', 'exec']);
    like($err, qr/requires superuser|superuser required/,
         "EXECUTE granted: $call refused") or diag $err;
}

($rc, $out, $err) = $node->psql('nowallet', "SELECT pg_vault_tde_wallet_init('test-password')");
is($rc, 0, 'a superuser still creates the wallet') or diag $err;
is($wallet_of->('nowallet'), '1', '... which is there');

$node->stop;
