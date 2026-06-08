# tap/03_backup_vault.t - TAP test for encrypted backup round-trip with Vault KMS
#
# Requires Vault to be running and accessible via VAULT_ADDR env var.
# In CI this is handled by run-tap.sh which starts Vault before invoking prove.
# On a developer workstation you can run it manually after:
#   podman-compose -f ci/dump-compose.yml up -d vault
#   VAULT_ADDR=http://localhost:8200 prove tap/03_backup_vault.t
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

my $vault_addr = $ENV{VAULT_ADDR}
    or plan skip_all => 'VAULT_ADDR not set — skipping Vault integration test';

plan tests => 7;

my $node = PostgreSQL::Test::Cluster->new('backup_vault_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'vault'\n" .
    "pg_vault_tde.dev_mode=on\n" .
    "pg_vault_tde.vault_url='$vault_addr'\n" .
    "pg_vault_tde.vault_token='test-token'\n" .
    "pg_vault_tde.vault_transit_mount='transit'\n" .
    "pg_vault_tde.vault_key_name='pg-tde-dek'\n");
$node->start;

ok($node->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0,
   'CREATE EXTENSION succeeds');

$node->safe_psql('postgres',
    "CREATE TABLE secret_data (id serial, payload text) USING encrypted_heap;");
$node->safe_psql('postgres',
    "INSERT INTO secret_data (payload) VALUES ('top_secret_value');");

ok(1, 'TDE table created and populated');

# --- Run pg_dump_tde and verify output is ciphertext ---
my $dump_file = $node->data_dir . '/test_backup.dump';
$node->command_ok(['pg_dump_tde', '-o', $dump_file, '-U', 'postgres', '-d', 'postgres'],
                  'pg_dump_tde completes without error');

ok(-f $dump_file, 'Dump file exists');

my $dump_content = PostgreSQL::Test::Utils::slurp_file($dump_file);
unlike($dump_content, qr/top_secret_value/,
       'Dump file does not contain plaintext sentinel');

$node->safe_psql('postgres', "DROP TABLE secret_data;");

$node->command_ok(['pg_restore_tde', '-i', $dump_file,
                   '-U', 'postgres', '-d', 'postgres'],
                  'pg_restore_tde completes without error');

my $result = $node->safe_psql('postgres', "SELECT * FROM secret_data;");
like($result, qr/top_secret_value/, 'Backup successfully restored');

$node->stop;
