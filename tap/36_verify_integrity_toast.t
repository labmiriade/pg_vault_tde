# tap/36_verify_integrity_toast.t — pg_vault_tde_verify_integrity() must
# count a row whose out-of-line value no longer decrypts
#
# verify_integrity() checked the GCM tag of every row of the table, and never
# looked at the TOAST relation: a value lost under a retired DEK (PSQLE-189)
# or a damaged chunk left the row's own tag intact, so the function reported
# nothing while SELECT failed (PSQLE-196).
#
# One byte is flipped inside the ciphertext of a single TOAST chunk, with the
# server down and data checksums off, as in tap/20 — otherwise the page
# checksum would refuse the page first.  pageinspect gives the chunk's
# offset, so the flip lands in the encrypted data and not in the plaintext
# header.  Exactly one row's value then stops reading; verify_integrity()
# must count that row, keep the total a row count, finish the scan, and find
# nothing on an untouched twin table.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 7;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('verify_toast');
my @initdb_extra;
push @initdb_extra, '--no-data-checksums' if $node->pg_version >= 18;
$node->init(extra => \@initdb_extra);
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
is($node->safe_psql('postgres', 'SHOW data_checksums'), 'off',
   'data page checksums are off, so the GCM tag is the line under test');

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', 'CREATE EXTENSION pageinspect;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
for my $t (qw(vt vt_twin))
{
    $node->safe_psql('postgres', qq{
        CREATE TABLE $t (id int, big text) USING encrypted_heap;
        ALTER TABLE $t ALTER COLUMN big SET STORAGE EXTERNAL;
        INSERT INTO $t SELECT g, repeat(md5(g::text), 400) FROM generate_series(1, 20) g;
    });
}

sub verify
{
    my ($t) = @_;
    my ($rc, $out, $err) = $node->psql('postgres',
        "SELECT total_tuples || '|' || failed_tuples FROM pg_vault_tde_verify_integrity('$t')");
    diag $err if $rc;
    return $out;
}

is(verify('vt'), '20|0', 'before the damage every row verifies');

my $toast = $node->safe_psql('postgres',
    "SELECT reltoastrelid::regclass FROM pg_class WHERE oid = 'vt'::regclass");
my $off = $node->safe_psql('postgres',
    "SELECT lp_off + t_hoff + 100 FROM heap_page_items(get_raw_page('$toast', 0)) WHERE lp = 1");
my $file = $node->data_dir . '/'
         . $node->safe_psql('postgres', "SELECT pg_relation_filepath('$toast')");

$node->stop;
open(my $fh, '+<', $file) or die "open $file: $!";
binmode $fh;
seek($fh, $off, 0) or die "seek: $!";
read($fh, my $byte, 1) == 1 or die "read: $!";
seek($fh, $off, 0) or die "seek: $!";
print $fh chr(ord($byte) ^ 0x01);
close($fh);
$node->start;
$node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

# The premise: one value, and only one, no longer reads.  md5(), not
# length(): in a single-byte encoding length() takes an uncompressed value's
# size from its pointer and never reads a chunk.
my $unreadable = 0;
for my $id (1 .. 20)
{
    my ($rc) = $node->psql('postgres', "SELECT md5(big) FROM vt WHERE id = $id");
    $unreadable++ if $rc;
}
is($unreadable, 1, 'the flip broke exactly one out-of-line value');

my $off_log = -s $node->logfile;
is(verify('vt'), '20|1', 'verify_integrity counts the row whose value no longer decrypts');
is(verify('vt'), '20|1', '... and says the same on a second call');
is(verify('vt_twin'), '20|0', 'an untouched table still verifies');
unlike(slurp_file($node->logfile, $off_log), qr/leak|was not closed|still pinned/i,
       'the failed reads leave no resource behind');

$node->stop;
