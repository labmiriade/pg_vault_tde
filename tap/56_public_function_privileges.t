# tap/56_public_function_privileges.t — the functions left open to PUBLIC check
# the caller
#
# pg_vault_tde_verify_integrity(), pg_vault_tde_encrypted_size(),
# pg_vault_tde_vault_status() and pg_vault_tde_refresh_token() keep EXECUTE to
# PUBLIC and checked nothing (PSQLE-226).  The first two open, scan and decrypt
# any relation, so they answered about tables the caller cannot read; the other
# two report on the server's KMS configuration and make it renew its Vault
# lease, which is the operator's business.
#
# None of the four is SECURITY DEFINER, so the role whose code is running is
# the caller: the scans ask for SELECT on the relation, the KMS ones for a
# superuser.
use strict;
use warnings;
use Test::More tests => 12;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('public_privs');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

$node->safe_psql('postgres', q{
    CREATE TABLE secret (id int, v text) USING encrypted_heap;
    INSERT INTO secret SELECT g, 'v' || g FROM generate_series(1, 50) g;
    CREATE ROLE plain LOGIN;
    CREATE ROLE reader LOGIN;
    CREATE ROLE mon LOGIN IN ROLE pg_monitor;
    GRANT SELECT ON secret TO reader;});

# ── The scans: SELECT on the relation ─────────────────────────────────────
for my $fn ('pg_vault_tde_verify_integrity', 'pg_vault_tde_encrypted_size')
{
    my ($rc, undef, $err) = $node->psql('postgres',
        "SET ROLE plain; SELECT * FROM $fn('secret'::regclass);");
    isnt($rc, 0, "$fn is refused to a role with no privilege on the table");
    like($err, qr/permission denied/, "... with a permission error");

    # pg_monitor is a monitoring role, not a reader: the check is SELECT.
    my ($mrc) = $node->psql('postgres',
        "SET ROLE mon; SELECT * FROM $fn('secret'::regclass);");
    isnt($mrc, 0, "... and to a pg_monitor member without SELECT");

    # A role that may read the table gets its answer.
    is($node->safe_psql('postgres',
           "SET ROLE reader; SELECT count(*) FROM $fn('secret'::regclass);"),
       '1', "... while a role with SELECT may call it");
}

is($node->safe_psql('postgres',
       "SELECT failed_tuples FROM pg_vault_tde_verify_integrity('secret'::regclass)"),
   '0', 'a superuser still gets a clean verify_integrity');

# ── The KMS ones: superuser ───────────────────────────────────────────────
for my $fn ('pg_vault_tde_vault_status', 'pg_vault_tde_refresh_token')
{
    my ($rc, undef, $err) = $node->psql('postgres',
        "SET ROLE plain; SELECT * FROM $fn();");
    isnt($rc, 0, "$fn is refused to a role that is not a superuser");
}

# A superuser is not stopped by the new check (the local provider may still
# report nothing to renew; only the privilege error must be gone).
{
    my (undef, undef, $err) = $node->psql('postgres', 'SELECT * FROM pg_vault_tde_refresh_token();');
    unlike($err, qr/superuser|permission denied/,
        'a superuser is not refused by the new check');
}

$node->stop;
