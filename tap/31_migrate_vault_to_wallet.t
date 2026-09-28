# tap/31_migrate_vault_to_wallet.t — pg_vault_tde_migrate_vault_to_wallet()
# must leave every migrated table readable under the local wallet
#
# The migration re-wraps each Vault-protected DEK for the local wallet and marks
# its catalog row kms_provider = 'local'.  It used to wrap with a KEK derived
# from the passphrase (local_derive_kek_from_pass()), while the wallet that
# pg_vault_tde_wallet_init() creates — which the migration requires — holds a
# random KEK: no migrated DEK ever unwrapped again, and the Vault-wrapped copy
# had been overwritten (PSQLE-188).  It also accepted any passphrase, and left
# the database on the Vault provider, which cannot unwrap what it had just
# written.
#
# Two halves:
#
#   no Vault   the local provider is active and the catalog rows are marked
#              'vault' by hand, which is all the migration looks at: a wrong
#              passphrase must change nothing, the right one must leave the
#              table readable now and after a restart
#   Vault      the documented flow against a real Vault (VAULT_ADDR, which
#              make ci-tap provides): tables created under Vault, the wallet
#              created, the migration, then a session opened before it, a new
#              session, and a restart must all read every row
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $vault_addr = $ENV{VAULT_ADDR};
plan tests => 8 + ($vault_addr ? 8 : 0);

my ($node, $half);

sub make_table
{
    my ($t) = @_;
    $node->safe_psql('postgres', qq{
        CREATE TABLE $t (id int, val text) USING encrypted_heap;
        INSERT INTO $t SELECT g, '${t}_' || g FROM generate_series(1, 100) g;
        CREATE TABLE ${t}_truth AS SELECT * FROM $t;
    });
}

# Two assertions: every tag verifies, and the contents equal the twin.
sub check_table
{
    my ($t, $when) = @_;
    my ($rc, $out, $err) = $node->psql('postgres',
        "SELECT total_tuples || '|' || failed_tuples "
      . "FROM pg_vault_tde_verify_integrity('$t')");
    is($out, '100|0', "$half $t $when: every tag verifies") or diag $err;
    ($rc, $out, $err) = $node->psql('postgres', qq{
        SELECT count(*) FROM (
            (SELECT * FROM $t EXCEPT ALL SELECT * FROM ${t}_truth)
            UNION ALL
            (SELECT * FROM ${t}_truth EXCEPT ALL SELECT * FROM $t)) d});
    is($out, '0', "$half $t $when: contents equal the plain-heap twin") or diag $err;
}

sub catalog_row
{
    my ($t) = @_;
    return $node->safe_psql('postgres',
        "SELECT kms_provider || '|' || md5(wrapped_dek) FROM pg_vault_tde_catalog "
      . "WHERE relid = '$t'::regclass::oid");
}

# ---- no Vault: the local provider stands in for it --------------------------
$half = 'local';
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
$node = PostgreSQL::Test::Cluster->new('migrate_local');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo mig-pass'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('mig-pass')");
make_table('t');
# The migration picks rows by kms_provider = 'vault' and unwraps them with the
# active provider — the local wallet here, which did wrap them.
$node->safe_psql('postgres',
    "UPDATE pg_vault_tde_catalog SET kms_provider = 'vault' "
  . "WHERE relid = 't'::regclass::oid");

my $before = catalog_row('t');
my ($rc, $out, $err) = $node->psql('postgres',
    "SELECT pg_vault_tde_migrate_vault_to_wallet('not-the-passphrase')");
isnt($rc, 0, 'local: a passphrase that does not open the wallet is refused');
is(catalog_row('t'), $before, 'local: ... and the catalog row is untouched');

($rc, $out, $err) = $node->psql('postgres',
    "SELECT pg_vault_tde_migrate_vault_to_wallet('mig-pass')");
is($rc, 0, 'local: the migration succeeds') or diag $err;
like(catalog_row('t'), qr/^local\|/, 'local: the row is now kms_provider = local');
check_table('t', 'after the migration');
$node->restart;
check_table('t', 'after a restart');
$node->stop;

# ---- Vault: the documented flow ---------------------------------------------
if ($vault_addr)
{
    $half = 'vault';
    system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
    $node = PostgreSQL::Test::Cluster->new('migrate_vault');
    $node->init;
    $node->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'vault'\n" .
        "pg_vault_tde.dev_mode = on\n" .
        "pg_vault_tde.vault_url = '$vault_addr'\n" .
        "pg_vault_tde.vault_token = 'test-token'\n" .
        "pg_vault_tde.vault_transit_mount = 'transit'\n" .
        "pg_vault_tde.vault_key_name = 'pg-tde-dek'\n" .
        "pg_vault_tde.wallet_passphrase_command = 'echo mig-pass'\n");
    $node->start;
    $node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    make_table('t');

    # A session that was already connected, with the Vault provider active.
    my $old = $node->background_psql('postgres', on_error_stop => 0);
    $old->query_safe('SELECT count(*) FROM t');

    $node->safe_psql('postgres',
        "SET pg_vault_tde.kms_provider = 'local'; "
      . "SELECT pg_vault_tde_wallet_init('mig-pass')");

    ($rc, $out, $err) = $node->psql('postgres',
        "SELECT pg_vault_tde_migrate_vault_to_wallet('mig-pass')");
    is($rc, 0, 'vault: the migration succeeds') or diag $err;
    like(catalog_row('t'), qr/^local\|/, 'vault: the row is now kms_provider = local');
    is($node->safe_psql('postgres', q{
            SELECT count(*) FROM pg_db_role_setting s
            JOIN pg_database d ON d.oid = s.setdatabase
            WHERE d.datname = current_database() AND s.setrole = 0
              AND 'pg_vault_tde.kms_provider=local' = ANY (s.setconfig)}), '1',
       'vault: the database now uses the local provider');

    my $n = eval { $old->query_safe('SELECT count(*) FROM t') };
    is($n, '100', 'vault: a session connected before the migration still reads t')
      or diag $@;
    eval { $old->quit; };

    check_table('t', 'in a new session');
    $node->restart;
    check_table('t', 'after a restart');
    $node->stop;
}
