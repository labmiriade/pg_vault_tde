# tap/14_seal_keys.t - physical backup key sealing (PSQLE-23)
# Seals all wrapped DEKs into an HMAC-signed bundle, verifies round-trip,
# and that tampering / wrong passphrase are rejected.
use strict;
use warnings;
use Test::More tests => 9;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use File::Spec;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('seal_test_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

ok($node->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0,
    'CREATE EXTENSION succeeds');

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

$node->safe_psql('postgres',
    "CREATE TABLE secret_data (id serial, payload text) USING encrypted_heap;");
$node->safe_psql('postgres',
    "INSERT INTO secret_data (payload) VALUES ('top_secret_value');");

# --- Seal ---
my $seal = File::Spec->rel2abs($node->data_dir) . '/keys.sealed';

$node->command_ok(
    ['psql', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c',
    "SELECT pg_vault_tde_seal_keys('$seal', 'seal-pass')"],
    'seal_keys succeeds');
    
ok(-f $seal, 'sealed file exists');

my $bytes = PostgreSQL::Test::Utils::slurp_file($seal);
is(substr($bytes, 0, 7), 'TDESEAL', 'bundle starts with TDESEAL magic');

my $mode = (stat($seal))[2] & 07777;
is($mode, 0600, 'sealed file is 0600');

# --- Round-trip: dirty the generation, unseal, expect it restored ---
$node->safe_psql('postgres',
    "UPDATE pg_vault_tde_catalog SET generation = 999 WHERE wrapped_dek IS NOT NULL;");
$node->safe_psql('postgres',
    "SELECT pg_vault_tde_unseal_keys('$seal', 'seal-pass');");
my $gen = $node->safe_psql('postgres',
    "SELECT generation FROM pg_vault_tde_catalog WHERE wrapped_dek IS NOT NULL LIMIT 1;");
is($gen, '1', 'unseal restored the sealed generation');

# --- Tamper one byte in the row area -> must be rejected ---
my $tampered = File::Spec->rel2abs($node->data_dir) . '/keys.tampered';
my $t = $bytes;
substr($t, 100, 1) = "\xff";
open(my $fh, '>:raw', $tampered) or die $!;
print $fh $t; close $fh;

my ($stderr);
my $rc = $node->psql('postgres',
    "SELECT pg_vault_tde_unseal_keys('$tampered', 'seal-pass')",
    stderr => \$stderr);
isnt($rc, 0, 'tampered bundle is rejected');
like($stderr, qr/HMAC verification failed/, 'tamper produces HMAC error');
# --- Wrong passphrase -> must be rejected ---
my $rc2 = $node->psql('postgres',
    "SELECT pg_vault_tde_unseal_keys('$seal', 'wrong-pass')",
    stderr => \$stderr);
isnt($rc2, 0, 'wrong passphrase is rejected');

$node->stop;

