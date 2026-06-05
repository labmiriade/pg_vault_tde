# tap/10_backup_cross_db.t - Restore into a different database than the source
use strict;
use warnings;
use Test::More tests => 8;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

my $node = PostgreSQL::Test::Cluster->new('cross_db_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# Source database: 'source_db'
$node->safe_psql('postgres', 'CREATE DATABASE source_db;');
$node->safe_psql('source_db', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('source_db', q{
    CREATE TABLE cross_test (id serial PRIMARY KEY, val text) USING encrypted_heap;
    INSERT INTO cross_test (val) VALUES ('cross_db_sentinel_row1'), ('cross_db_sentinel_row2');
});
ok(1, 'source_db created with TDE table and data');

my $dump_file = $node->data_dir . '/cross_db.dump';
$node->command_ok(
    ['pg_dump_tde', '-o', $dump_file,
     '-U', 'postgres', '-d', 'source_db',
     '-h', $node->host, '-p', $node->port],
    'pg_dump_tde on source_db completes');

ok(-f $dump_file, 'Cross-db dump file exists');

my $dump_content = PostgreSQL::Test::Utils::slurp_file($dump_file);
unlike($dump_content, qr/cross_db_sentinel/, 'Cross-db dump does not contain plaintext sentinel');

# Target database: fresh 'restore_db'
$node->safe_psql('postgres', 'CREATE DATABASE restore_db;');
$node->safe_psql('restore_db', 'CREATE EXTENSION pg_vault_tde;');
ok(1, 'restore_db created and extension initialized');

$node->command_ok(
    ['pg_restore_tde', '-i', $dump_file,
     '-U', 'postgres', '-d', 'restore_db',
     '-h', $node->host, '-p', $node->port],
    'pg_restore_tde into restore_db completes');

# Verify data is present in target database
my $target_result = $node->safe_psql('restore_db', 'SELECT val FROM cross_test ORDER BY id;');
like($target_result, qr/cross_db_sentinel_row1.*cross_db_sentinel_row2/s,
    'Restored data is present in restore_db');

# Verify source database is untouched
my $source_result = $node->safe_psql('source_db', 'SELECT count(*) FROM cross_test;');
is($source_result, '2', 'Source database data is intact after cross-db restore');

$node->stop;
