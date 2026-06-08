# tap/09_backup_wrong_key.t - Wrong passphrase and missing wallet scenarios
use strict;
use warnings;
use Test::More tests => 9;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

my $node = PostgreSQL::Test::Cluster->new('wrong_key_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo correct-password'\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('correct-password')");

$node->safe_psql('postgres', q{
    CREATE TABLE keyed_data (id serial, val text) USING encrypted_heap;
    INSERT INTO keyed_data (val) VALUES ('key_test_sentinel');
});

my $dump_file = $node->data_dir . '/wrong_key.dump';
$node->command_ok(
    ['pg_dump_tde', '-o', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'Dump with correct passphrase succeeds');

$node->safe_psql('postgres', 'DROP TABLE keyed_data;');

$node->append_conf('postgresql.conf',
    "pg_vault_tde.wallet_passphrase_command = 'echo wrong-password'\n");
$node->reload;

my $debug = $node->safe_psql('postgres', 'SHOW pg_vault_tde.wallet_passphrase_command');
like($debug, qr/echo wrong-password/);

$node->command_fails(
    ['pg_restore_tde', '-i', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'pg_restore_tde fails when passphrase is wrong (DEK unwrap fails)');

$node->append_conf('postgresql.conf',
    "pg_vault_tde.wallet_passphrase_command = 'echo correct-password'\n");
$node->reload;

$node->command_ok(
    ['pg_restore_tde', '-i', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'pg_restore_tde succeeds after restoring correct passphrase');

my $result = $node->safe_psql('postgres', 'SELECT val FROM keyed_data;');
like($result, qr/key_test_sentinel/, 'Data restored correctly with correct passphrase');

$node->safe_psql('postgres', 'DROP TABLE keyed_data;');

# Remove wallet file: pg_dump_tde must fail
my $wallet_path = $node->safe_psql('postgres',
    "SHOW pg_vault_tde.wallet_path;");
$wallet_path =~ s/^\s+|\s+$//g;

SKIP: {
    skip 'wallet_path is empty, cannot test missing wallet', 2
        unless $wallet_path && -f $wallet_path;

    rename($wallet_path, $wallet_path . '.bak')
        or die "Cannot rename wallet: $!";

    $node->command_fails(
        ['pg_dump_tde', '-o', $node->data_dir . '/no_wallet.dump',
         '-U', 'postgres', '-d', 'postgres'],
        'pg_dump_tde fails when wallet file is missing');

    rename($wallet_path . '.bak', $wallet_path)
        or die "Cannot restore wallet: $!";

    ok(-f $wallet_path, 'Wallet file restored after test');
}

my $nonexistent_wallet = '/nonexistent/path/wallet_' . $$ . '.p12';
$node->safe_psql('postgres',
    "ALTER DATABASE postgres SET pg_vault_tde.wallet_path TO '$nonexistent_wallet'");

$node->command_fails(
    ['pg_dump_tde', '-o', $node->data_dir . '/missing_wallet.dump',
     '-U', 'postgres', '-d', 'postgres'],
    'pg_dump_tde fails when wallet_path is non-existent');

# pg_restore_tde also fails with missing wallet
$node->command_fails(
    ['pg_restore_tde', '-i', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'pg_restore_tde fails when wallet_path is non-existent');

$node->stop;
