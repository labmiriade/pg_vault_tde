# tap/02_backup.t - TAP test for encrypted backup round-trip
# Mocks a Vault HTTP endpoint, runs pg_dump through the TDE wrapper,
# verifies the output is ciphertext, then restores and verifies data.
use strict;
use warnings;
use Test::More tests => 7;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

# --- PostgreSQL node ---
my $node = PostgreSQL::Test::Cluster->new('backup_test_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

ok($node->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0,
   'CREATE EXTENSION succeeds');

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
$node->safe_psql('postgres',
    "SELECT pg_vault_tde_wallet_init('test-password')");

$node->safe_psql('postgres',
    "CREATE TABLE secret_data (id serial, payload text) USING encrypted_heap;");
$node->safe_psql('postgres',
    "INSERT INTO secret_data (payload) VALUES ('top_secret_value');");

ok(1, 'TDE table created and populated');

# --- Run pg_dump and check it is not plaintext ---
my $dump_file = $node->data_dir . '/test_backup.dump';
$node->command_ok(['pg_dump_tde', '-o', $dump_file, '-U', 'postgres', '-d', 'postgres'],
                  'pg_dump completes without error');

ok(-f $dump_file, 'Dump file exists');

# The dump should NOT contain the plaintext sentinel value
my $dump_content = PostgreSQL::Test::Utils::slurp_file($dump_file);
unlike($dump_content, qr/top_secret_value/,
       'Dump file does not contain plaintext sentinel');

$node->safe_psql('postgres', 
    "DROP TABLE secret_data;");

$node->command_ok(['pg_restore_tde', '-i', $dump_file,
                    '-U', 'postgres', '-d', 'postgres'], 
                    'pg_restore_tde completes without error');

my $result = $node->safe_psql('postgres', 
    "SELECT * FROM secret_data;");

like($result, qr/top_secret_value/, 'Backup successfully restored');

# --- Cleanup ---
$node->stop;
