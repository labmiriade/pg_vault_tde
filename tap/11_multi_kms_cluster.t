#tap/11_multi_kms_cluster - Test if having differt KMS providers
# for different databases on the same cluster is possibile

use strict;
use warnings;
use Test::More tests => 9;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use IPC::Run qw(run);

my $vault_addr = $ENV{VAULT_ADDR}
    or plan skip_all => 'VAULT_ADDR not set — skipping Vault integration test';

my $node = PostgreSQL::Test::Cluster->new('test_cluster');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" 
);

$node->start;
$node->safe_psql('postgres', 'CREATE DATABASE local_kms;');

$node->safe_psql('local_kms', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('local_kms', q{
    ALTER DATABASE local_kms SET pg_vault_tde.kms_provider = 'local';
    ALTER DATABASE local_kms SET pg_vault_tde.wallet_passphrase_command = 'echo test-password';
});

$node->restart;

$node->safe_psql('local_kms', "SELECT pg_vault_tde_wallet_init('test-password');");

my $local_oid = $node->safe_psql('postgres',
    "SELECT oid FROM pg_database WHERE datname = 'local_kms';"
);
my $local_wallet = $node->data_dir . "/base/$local_oid/pg_vault_tde/wallet.p12";

ok(-e $local_wallet, "wallet for local KMS database exists");

$node->safe_psql('local_kms', 
    'CREATE TABLE test_t (id SERIAL, value TEXT) using encrypted_heap;');
$node->safe_psql('local_kms', 
    "INSERT INTO test_t (value) VALUES (repeat('spippo_spluto_spaperirno', 100));");

ok(1, 'Table on local KMS created and populated successfully');

$node->safe_psql('postgres', 'CREATE DATABASE vault_kms;');

$node->safe_psql('vault_kms', 'CREATE EXTENSION pg_vault_tde');
$node->safe_psql('vault_kms', qq{
    ALTER DATABASE vault_kms SET pg_vault_tde.kms_provider = 'vault';
    ALTER DATABASE vault_kms SET pg_vault_tde.vault_url='$vault_addr';
    ALTER DATABASE vault_kms SET pg_vault_tde.vault_token='test-token';
    ALTER DATABASE vault_kms SET pg_vault_tde.vault_transit_mount='transit';
    ALTER DATABASE vault_kms SET pg_vault_tde.vault_key_name='pg-tde-dek';
});

$node->safe_psql('vault_kms', 
    'CREATE TABLE test_t (id SERIAL, value TEXT) using encrypted_heap');

$node->safe_psql('vault_kms', 
    "INSERT INTO test_t (value) VALUES (repeat('spippo_spluto_spaperirno', 100));");

ok(1, 'Table on vault KMS created and populated successfully');

# --- Run pg_dump_tde on KMS local database and verify output is ciphertext ---
my $local_dump_file = $node->data_dir . '/test_backup_local.dump';
$node->command_ok(['pg_dump_tde', '-o', $local_dump_file, '-U', 'postgres', '-d', 'local_kms'],
                  'pg_dump_tde on local KMS database completes without error');

ok(-f $local_dump_file, 'Dump file for local KMS exists');

my $dump_content = PostgreSQL::Test::Utils::slurp_file($local_dump_file);
unlike($dump_content, qr/spippo_spluto_spaperino/,
       'Local KMS dump file does not contain plaintext sentinel');

# --- Run pg_dump_tde on KMS vault database and verify output is ciphertext ---
my $vault_dump_file = $node->data_dir . '/test_backup_vault.dump';
$node->command_ok(['pg_dump_tde', '-o', $vault_dump_file, '-U', 'postgres', '-d', 'vault_kms'],
                  'pg_dump_tde on vault KMS database completes without error');

ok(-f $vault_dump_file, 'Dump file for vault KMS exists');

$dump_content = PostgreSQL::Test::Utils::slurp_file($vault_dump_file);
unlike($dump_content, qr/spippo_spluto_spaperino/,
       'vault KMS dump file does not contain plaintext sentinel');