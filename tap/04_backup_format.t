# tap/04_backup_format.t - Binary format verification and multi-object dump/restore
use strict;
use warnings;
use Test::More tests => 13;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

# Header layout (on-disk, with compiler struct padding on x86-64):
#   magic(10) | pad(2) | format_version(4) | wrapped_dek_len(2) | wrapped_dek(512) | tail_pad(2) = 532 bytes
# The compiler inserts 2 bytes between magic[10] and uint32 format_version (4-byte alignment),
# and 2 bytes of tail padding so sizeof is a multiple of 4.
# First block:   block_len(4) | version_byte(1) | IV(12) | CT(var) | TAG(16)
# => version byte sits at file offset 536 (532 header + 4 block_len)
use constant HEADER_SIZE       => 532;
use constant BLOCK_LEN_SIZE    => 4;
use constant VERSION_BYTE      => 0x02;
use constant TDE_MAGIC         => 'PGVAULTTDE';
use constant FORMAT_VERSION    => 1;
use constant MAX_WRAPPED_DEK   => 512;

my $node = PostgreSQL::Test::Cluster->new('format_test_node');
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

# Two schemas, two encrypted tables each with different column types
$node->safe_psql('postgres', "CREATE SCHEMA s1; CREATE SCHEMA s2;");
$node->safe_psql('postgres', q{
    CREATE TABLE s1.t1 (id serial PRIMARY KEY, val text, num numeric(10,2))
        USING encrypted_heap;
    INSERT INTO s1.t1 (val, num) VALUES ('hello', 3.14), ('world', 2.72);
});
$node->safe_psql('postgres', q{
    CREATE TABLE s2.t2 (id serial PRIMARY KEY, flag bool, ts timestamptz)
        USING encrypted_heap;
    INSERT INTO s2.t2 (flag, ts) VALUES (true, '2024-01-01 00:00:00+00'),
                                        (false, '2025-06-15 12:00:00+00');
});
ok(1, 'Multi-schema TDE tables created and populated');

my $dump_file = $node->data_dir . '/format_test.dump';
$node->command_ok(
    ['pg_dump_tde', '-o', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'pg_dump_tde completes without error');

ok(-f $dump_file, 'Dump file exists on disk');

# --- Binary header verification ---
open(my $fh, '<:raw', $dump_file) or die "Cannot open $dump_file: $!";

read($fh, my $magic, 10);
is($magic, TDE_MAGIC, 'Header magic is PGVAULTTDE');

read($fh, my $pad, 2);  # 2 bytes implicit padding (uint32 alignment)
read($fh, my $ver_bytes, 4);
my ($fmt_ver) = unpack('V', $ver_bytes);
is($fmt_ver, FORMAT_VERSION, 'format_version = 1');

read($fh, my $dek_len_bytes, 2);
my ($dek_len) = unpack('v', $dek_len_bytes);
cmp_ok($dek_len, '>', 0,              'wrapped_dek_len > 0');
cmp_ok($dek_len, '<=', MAX_WRAPPED_DEK, 'wrapped_dek_len <= 512');

close($fh);

my $file_size = -s $dump_file;
cmp_ok($file_size, '>', HEADER_SIZE + BLOCK_LEN_SIZE + 29,
    'Dump file larger than header + minimum block overhead');

# Verify the version byte of the first encrypted block
open(my $fh2, '<:raw', $dump_file) or die "Cannot open $dump_file: $!";
seek($fh2, HEADER_SIZE + BLOCK_LEN_SIZE, 0);
read($fh2, my $vb, 1);
close($fh2);
is(ord($vb), VERSION_BYTE, 'First block version byte = 0x02');

# --- Restore and verify data from both schemas ---
$node->safe_psql('postgres', 'DROP SCHEMA s1 CASCADE; DROP SCHEMA s2 CASCADE;');

$node->command_ok(
    ['pg_restore_tde', '-i', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'pg_restore_tde completes without error');

my $r1 = $node->safe_psql('postgres', 'SELECT val FROM s1.t1 ORDER BY id;');
like($r1, qr/hello.*world/s, 'Data from s1.t1 restored correctly');

my $r2 = $node->safe_psql('postgres', 'SELECT flag FROM s2.t2 ORDER BY id;');
like($r2, qr/t.*f/s, 'Data from s2.t2 restored correctly');

$node->stop;
