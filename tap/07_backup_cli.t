# tap/07_backup_cli.t - CLI argument validation: missing required flags, unsupported options, bad connections
use strict;
use warnings;
use Test::More tests => 16;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

my $node = PostgreSQL::Test::Cluster->new('cli_test_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

my $dummy_out  = $node->data_dir . '/cli_dummy.dump';
my $nonexist   = '/tmp/does_not_exist_pgvaulttde_' . $$ . '.dump';

# --- pg_dump_tde negative cases ---

# 1. No arguments at all
$node->command_fails(
    ['pg_dump_tde'],
    'pg_dump_tde with no args exits non-zero');

# 2. Missing -o (output required)
$node->command_fails_like(
    ['pg_dump_tde', '-U', 'postgres', '-d', 'postgres'],
    qr/output|--output|-o/i,
    'pg_dump_tde without -o reports output-required error');

# 3. Parallel jobs (-j) not supported
$node->command_fails_like(
    ['pg_dump_tde', '-j', '4', '-o', $dummy_out, '-U', 'postgres', '-d', 'postgres'],
    qr/-j|parallel|not supported/i,
    'pg_dump_tde -j 4 exits non-zero with unsupported message');

# 4. Invalid host — connection must fail
$node->command_fails(
    ['pg_dump_tde', '-o', $dummy_out, '-h', 'host-xyz-invalid-99999', '-d', 'postgres'],
    'pg_dump_tde with invalid host exits non-zero');

# 5. Non-existent database
$node->command_fails(
    ['pg_dump_tde', '-o', $dummy_out,
     '-h', $node->host, '-p', $node->port,
     '-U', 'postgres', '-d', 'nonexistent_db_xyz_99999'],
    'pg_dump_tde with non-existent database exits non-zero');

# 6. Output path in non-existent directory
$node->command_fails(
    ['pg_dump_tde', '-o', '/nonexistent/dir/pg_vault_tde_' . $$ . '.dump',
     '-U', 'postgres', '-d', 'postgres',
     '-h', $node->host, '-p', $node->port],
    'pg_dump_tde with non-writable output path exits non-zero');

# --- pg_restore_tde negative cases ---

# 7. No arguments at all
$node->command_fails(
    ['pg_restore_tde'],
    'pg_restore_tde with no args exits non-zero');

# 8. Missing -i (input required)
$node->command_fails_like(
    ['pg_restore_tde', '-U', 'postgres', '-d', 'postgres'],
    qr/input|--input|-i/i,
    'pg_restore_tde without -i reports input-required error');

# 9. Parallel jobs (-j) not supported
$node->command_fails_like(
    ['pg_restore_tde', '-j', '4', '-i', $nonexist],
    qr/-j|parallel|not supported/i,
    'pg_restore_tde -j 4 exits non-zero with unsupported message');

# 10. Non-existent input file
$node->command_fails(
    ['pg_restore_tde', '-i', $nonexist, '-U', 'postgres', '-d', 'postgres'],
    'pg_restore_tde with non-existent input file exits non-zero');

# 11. Empty input file (/dev/null)
$node->command_fails(
    ['pg_restore_tde', '-i', '/dev/null',
     '-U', 'postgres', '-d', 'postgres',
     '-h', $node->host, '-p', $node->port],
    'pg_restore_tde with empty input file (/dev/null) exits non-zero');

# 12. pg_dump_tde with wrong port (connection refused)
$node->command_fails(
    ['pg_dump_tde', '-o', $dummy_out,
     '-h', '127.0.0.1', '-p', '19999',
     '-U', 'postgres', '-d', 'postgres'],
    'pg_dump_tde with wrong port (connection refused) exits non-zero');

$node->stop;
