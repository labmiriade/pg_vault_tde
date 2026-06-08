# tap/06_backup_corruption.t - Integrity checks: corrupted ciphertext, truncation, wrong magic, IV randomness
use strict;
use warnings;
use Test::More tests => 17;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

# Offset constants matching tde_backup_header C struct layout (little-endian host)
# magic(10) | pad(2) | format_version(4) | wrapped_dek_len(2) | wrapped_dek(512) | tail_pad(2) = 532
# First block: block_len(4) | version_byte(1) | IV(12) | CT(var) | TAG(16)
use constant HEADER_SIZE      => 532;  # sizeof(tde_backup_header) with compiler padding
use constant OFF_FMT_VERSION  => 12;   # offset of format_version (after magic[10] + 2-byte pad)
use constant OFF_DEK_LEN      => 16;   # offset of wrapped_dek_len (after format_version uint32)
use constant OFF_BLOCK_LEN    => 532;  # offset of first block_len field (= HEADER_SIZE)
use constant OFF_VERSION_BYTE => 536;  # HEADER_SIZE + 4 (block_len)
use constant OFF_IV           => 537;  # version_byte + 1
use constant OFF_CIPHERTEXT   => 549;  # HEADER_SIZE + block_len(4) + version_byte(1) + IV(12)

sub slurp_binary {
    my ($path) = @_;
    open(my $fh, '<:raw', $path) or die "Cannot read $path: $!";
    local $/; my $data = <$fh>; close($fh); return $data;
}

sub write_binary {
    my ($path, $data) = @_;
    open(my $fh, '>:raw', $path) or die "Cannot write $path: $!";
    print $fh $data; close($fh);
}

sub flip_byte {
    my ($data, $offset) = @_;
    my $copy = $data;
    substr($copy, $offset, 1) = chr(ord(substr($copy, $offset, 1)) ^ 0xFF);
    return $copy;
}

my $node = PostgreSQL::Test::Cluster->new('corruption_test_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', q{
    CREATE TABLE secret (id serial, val text) USING encrypted_heap;
    INSERT INTO secret (val) VALUES ('corruption_test_sentinel');
});

my $dump_file  = $node->data_dir . '/corruption_base.dump';
my $bad_file   = $node->data_dir . '/bad.dump';

$node->command_ok(
    ['pg_dump_tde', '-o', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'Baseline dump succeeds');

# Verify untampered restore works (baseline)
$node->safe_psql('postgres', 'DROP TABLE secret;');
$node->command_ok(
    ['pg_restore_tde', '-i', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'Baseline restore succeeds (sanity check)');
$node->safe_psql('postgres', 'DROP TABLE secret;');

my $original = slurp_binary($dump_file);

# --- Corruption tests (all must fail) ---

# 1. Empty file
write_binary($bad_file, '');
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: empty file');

# 2. Partial magic (5 bytes)
write_binary($bad_file, substr($original, 0, 5));
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: file truncated to 5 bytes');

# 3. Wrong magic bytes
my $bad_magic = $original;
substr($bad_magic, 0, 10) = 'WRONGMAGIC';
write_binary($bad_file, $bad_magic);
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: wrong magic bytes');

# 4. Corrupted format_version (= 99)
my $bad_ver = $original;
substr($bad_ver, OFF_FMT_VERSION, 4) = pack('V', 99);
write_binary($bad_file, $bad_ver);
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: format_version = 99');

# 5. Corrupted wrapped_dek_len = 0
my $bad_deklen = $original;
substr($bad_deklen, OFF_DEK_LEN, 2) = pack('v', 0);
write_binary($bad_file, $bad_deklen);
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: wrapped_dek_len = 0');

# 6. Header only (no blocks)
write_binary($bad_file, substr($original, 0, HEADER_SIZE));
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: header present but no blocks');

# 7. Truncated mid first block (header + 20 bytes of first block)
write_binary($bad_file, substr($original, 0, HEADER_SIZE + 20));
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: file truncated mid-first-block');

# 8. Bit-flip in ciphertext (first ciphertext byte after IV)
write_binary($bad_file, flip_byte($original, OFF_CIPHERTEXT));
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: bit-flip in ciphertext (GCM auth fails)');

# 9. Bit-flip in GCM tag (last 16 bytes of file)
my $bad_tag = flip_byte($original, length($original) - 16);
write_binary($bad_file, $bad_tag);
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: bit-flip in GCM tag');

# 10. Bit-flip in IV
write_binary($bad_file, flip_byte($original, OFF_IV));
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: bit-flip in IV (GCM auth fails)');

# 11. Corrupted block_len field (wildly oversized)
my $bad_blklen = $original;
substr($bad_blklen, OFF_BLOCK_LEN, 4) = pack('V', 99_999_999);
write_binary($bad_file, $bad_blklen);
$node->command_fails(
    ['pg_restore_tde', '-i', $bad_file, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: block_len set to 99999999');

# 12. Plain pg_dump -Fc output (no TDE header) fed to pg_restore_tde
my $plain_dump = $node->data_dir . '/plain.dump';
$node->command_ok(
    ['pg_dump', '-Fc', '-U', 'postgres', '-d', 'postgres', '-f', $plain_dump],
    'Plain pg_dump -Fc succeeds');
$node->command_fails(
    ['pg_restore_tde', '-i', $plain_dump, '-U', 'postgres', '-d', 'postgres'],
    'Restore fails: plain pg_dump output (no TDE header)');

# 13. IV randomness: two successive dumps of identical data must differ in ciphertext
my $dump2 = $node->data_dir . '/corruption_base2.dump';
$node->command_ok(
    ['pg_dump_tde', '-o', $dump2, '-U', 'postgres', '-d', 'postgres'],
    'Second dump completes');

my $c1 = slurp_binary($dump_file);
my $c2 = slurp_binary($dump2);

# Compare ciphertext area of first block (skip header + block_len + version_byte + IV = 545)
# IVs differ → ciphertext must differ even for same plaintext
isnt(substr($c1, OFF_CIPHERTEXT, 64), substr($c2, OFF_CIPHERTEXT, 64),
    'Two dumps of same data produce different ciphertext (random IVs)');

$node->stop;
