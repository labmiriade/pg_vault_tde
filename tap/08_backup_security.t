# tap/08_backup_security.t - Cryptographic security properties: no plaintext leakage, IV uniqueness, opaque output
use strict;
use warnings;
use Test::More tests => 8;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

# Offset of first ciphertext byte (header=532 + block_len=4 + version=1 + IV=12)
use constant OFF_CIPHERTEXT => 549;

my $node = PostgreSQL::Test::Cluster->new('security_test_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

$node->safe_psql('postgres', q{
    CREATE TABLE classified (id serial PRIMARY KEY, secret text) USING encrypted_heap;
    INSERT INTO classified (secret) VALUES
        ('top_secret_alpha'),
        ('top_secret_beta'),
        ('classified_gamma');
});

my $dump1 = $node->data_dir . '/security1.dump';
my $dump2 = $node->data_dir . '/security2.dump';

$node->command_ok(
    ['pg_dump_tde', '-o', $dump1, '-U', 'postgres', '-d', 'postgres'],
    'First dump completes');
$node->command_ok(
    ['pg_dump_tde', '-o', $dump2, '-U', 'postgres', '-d', 'postgres'],
    'Second dump completes');

my $c1 = PostgreSQL::Test::Utils::slurp_file($dump1);
my $c2 = PostgreSQL::Test::Utils::slurp_file($dump2);

# No secret data values visible in plaintext
unlike($c1, qr/top_secret_alpha/,   'Dump 1: sentinel alpha not in plaintext');
unlike($c1, qr/top_secret_beta/,    'Dump 1: sentinel beta not in plaintext');
unlike($c1, qr/classified_gamma/,   'Dump 1: sentinel gamma not in plaintext');

# No SQL structural keywords visible (entire pg_dump output is encrypted, not just data)
unlike($c1, qr/CREATE TABLE/i,      'Dump 1: CREATE TABLE DDL not in plaintext');

# IV randomness: same plaintext → different ciphertext in each dump
isnt(substr($c1, OFF_CIPHERTEXT, 64), substr($c2, OFF_CIPHERTEXT, 64),
    'Two dumps of same data produce different ciphertext bytes (random IV per dump)');

# File sizes should be nearly identical (overhead is constant, not proportional to plaintext size)
my $size1 = -s $dump1;
my $size2 = -s $dump2;
my $diff  = abs($size1 - $size2);
# Allow at most 1 block's worth of difference (64KB + overhead) due to buffering
cmp_ok($diff, '<=', 65_565, "Two dumps of same data have similar file size (diff=${diff} bytes)");

$node->stop;
