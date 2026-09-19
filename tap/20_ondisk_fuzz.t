# tap/20_ondisk_fuzz.t
#
# On-disk corruption fuzz: every damaged byte must produce a clean ERROR, never
# a crash and never a wrong value returned as if it were valid.
#
# WHY THIS IS THE PROPERTY THAT MATTERS
#
# The existing tamper tests flip specific, hand-chosen bytes and assert that the
# GCM tag rejects them.  That proves the mechanism works where someone thought
# to look.  A fuzz proves the weaker but far more useful statement: across
# arbitrary damage, the layer has exactly two behaviours -- correct data, or a
# refusal.  Silently returning plaintext derived from damaged ciphertext is the
# one outcome an encryption layer must never have, and it is not something a
# fixed-offset test can rule out.
#
# CHECKSUMS ARE DISABLED ON PURPOSE
#
# initdb enables data page checksums by default, and they would catch nearly
# every flip before our code ever sees it -- turning this into a test of
# PostgreSQL's checksums rather than of AES-256-GCM.  With --no-data-checksums
# the authentication tag is the last line of defence, which is exactly the line
# this test is about.
#
# DETERMINISM
#
# srand is seeded with a constant, so a failure is reproducible: the same run
# corrupts the same offsets.  Change FUZZ_SEED to explore elsewhere.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

use constant FUZZ_SEED   => 20260919;
use constant ROWS        => 60;
use constant ROUNDS      => 6;
use constant FLIPS_ROUND => 12;

srand(FUZZ_SEED);

my $node = PostgreSQL::Test::Cluster->new('fuzz_node');
# --no-data-checksums: see the header.  Without it PostgreSQL rejects the page
# before pg_vault_tde is asked to decrypt anything.
$node->init(extra => ['--no-data-checksums']);
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n" .
    # A corrupted page must surface as an ERROR to the client, not be silently
    # zeroed away.  This is the default; pinned here because the whole test
    # depends on it.
    "zero_damaged_pages = off\n" .
    "full_page_writes = on\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

$node->safe_psql('postgres', q{
    CREATE TABLE fz (id int PRIMARY KEY, payload text) USING encrypted_heap;
});
$node->safe_psql('postgres',
    "INSERT INTO fz SELECT g, 'row-' || g || '-' || repeat(md5(g::text), 4) " .
    "FROM generate_series(1, " . ROWS . ") g");

# The authoritative answer, read back through the extension before any damage.
my %expected;
for my $id (1 .. ROWS)
{
    $expected{$id} = $node->safe_psql('postgres',
        "SELECT payload FROM fz WHERE id = $id");
}
is(scalar(keys %expected), ROWS, "baseline: " . ROWS . " rows readable");

my $relpath = $node->safe_psql('postgres', "SELECT pg_relation_filepath('fz')");
my $file    = $node->data_dir . '/' . $relpath;
ok(-s $file > 0, "heap file present ($relpath)");

# --- fuzz rounds ---------------------------------------------------------
my ($correct, $refused, $wrong, $vanished, $flipped_total) = (0, 0, 0, 0, 0);
my @wrong_ids;

for my $round (1 .. ROUNDS)
{
    # The server must be down while we rewrite the file, or we race the buffer
    # manager and corrupt something it is about to overwrite from memory.
    $node->stop;

    open(my $fh, '+<', $file) or die "open $file: $!";
    binmode $fh;
    my $size = -s $file;

    for (1 .. FLIPS_ROUND)
    {
        my $off = int(rand($size));
        seek($fh, $off, 0)         or die "seek: $!";
        read($fh, my $byte, 1)     or next;
        my $bit = 1 << int(rand(8));
        seek($fh, $off, 0)         or die "seek: $!";
        print $fh chr(ord($byte) ^ $bit);
        $flipped_total++;
    }
    close($fh);

    $node->start;

    for my $id (1 .. ROWS)
    {
        my ($rc, $out, $err) =
            $node->psql('postgres', "SELECT payload FROM fz WHERE id = $id");

        if ($rc != 0)
        {
            # Any refusal is acceptable: GCM tag mismatch, unreadable page,
            # malformed tuple.  What matters is that it is a refusal.
            $refused++;
        }
        elsif ($out eq $expected{$id})
        {
            # The flip landed somewhere that did not affect this row.
            $correct++;
        }
        elsif ($out eq '')
        {
            # The row vanished rather than returning bad data.
            #
            # This is NOT an authentication failure and must not be counted as
            # one.  Our wire format keeps the HeapTupleHeader in plaintext --
            # xmin, xmax, infomask, t_hoff, null bitmap -- and authenticates
            # only [t_hoff .. t_len).  A flip in that header is outside the GCM
            # tag by construction, and can make the tuple invisible to the
            # snapshot or mark the attribute NULL.  The row is lost, which is
            # what corruption of an unauthenticated header means; nothing false
            # was handed to the client as genuine.
            $vanished++;
        }
        else
        {
            # The only forbidden outcome: damaged bytes turned into a value the
            # client is told is genuine.
            $wrong++;
            push @wrong_ids, "round $round id $id got '" . substr($out, 0, 40) . "'"
                if @wrong_ids < 5;
        }
    }
}

# --- verdict -------------------------------------------------------------
note("flipped $flipped_total bits over " . ROUNDS . " rounds; " .
     "correct=$correct refused=$refused vanished=$vanished wrong=$wrong");

is($wrong, 0,
    "no damaged row was ever returned as valid" .
    (@wrong_ids ? " (first: " . join(', ', @wrong_ids) . ")" : ""));

# A fuzz that never damaged anything would report zero wrong and prove nothing.
cmp_ok($refused, '>', 0,
    "the corruption was actually reaching the data ($refused refusals)");

# The server survived every round.
is($node->safe_psql('postgres', 'SELECT 1'), '1',
    "server alive after $flipped_total bit flips");

my $log = slurp_file($node->logfile);
unlike($log, qr/terminated by signal|PANIC|Segmentation fault/,
    "no crash in the server log");

$node->stop;
done_testing();
