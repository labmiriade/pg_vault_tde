# tap/44_damaged_wallet.t — a damaged, missing or half-written local wallet
# fails cleanly, is never replaced behind the administrator's back, and
# restoring the file brings everything back (PSQLE-208)
#
# The wallet file holds every KEK of a database: if it is lost, so are the
# tables.  Nothing tested what the extension does when the file is not what
# it wrote — a disk that filled up, a restore that copied half of it, an
# editor, a permission change, a crash between writing wallet.p12.new and
# renaming it.  For each damage, after a restart (no key cached anywhere):
# the server starts; reading, writing and creating an encrypted table fail
# with an ERROR, not a crash or a wrong answer; wallet_unlock(), rotate_kek()
# and change_passphrase() fail and leave the file as it was; wallet_init()
# does not replace it.  Then the good file is put back, and after a restart
# every row reads as its plain twin.  A leftover wallet.p12.new and a leftover
# wallet.p12.lock must not get in the way at all.
#
# With the file missing, wallet_init() made a new wallet: a new KEK that opens
# none of the database's keys, under which the next tables were wrapped — so
# putting the real file back lost those instead.  It now refuses while any
# key of the database is wrapped under a local wallet; dropping the tables
# is how to start over.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Digest::MD5 qw(md5_hex);
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('damaged_wallet');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', q{
    SET client_min_messages = error;
    CREATE TABLE secret (id int PRIMARY KEY, v text) USING encrypted_heap;
    INSERT INTO secret SELECT g, repeat(md5(g::text), 1 + g % 300) FROM generate_series(1, 300) g;
    CREATE TABLE truth AS SELECT * FROM secret;
});

my $oid    = $node->safe_psql('postgres', "SELECT oid FROM pg_database WHERE datname = 'postgres'");
my $wallet = "/var/lib/pg_vault_tde/$oid/wallet.p12";
my $good   = slurp_file($wallet);
ok(length($good) > 0, 'the wallet exists');

sub put
{
    my ($path, $bytes) = @_;
    open(my $fh, '>:raw', $path) or die "open $path: $!";
    print $fh $bytes;
    close($fh);
    chmod(0600, $path);
}

sub file_md5 { -e $_[0] ? (-r $_[0] ? md5_hex(slurp_file($_[0])) : 'unreadable') : 'missing' }

sub equals_truth
{
    return $node->safe_psql('postgres', q{
        SELECT count(*) FROM (
            (SELECT * FROM secret EXCEPT ALL SELECT * FROM truth)
            UNION ALL
            (SELECT * FROM truth EXCEPT ALL SELECT * FROM secret)) d});
}

my @damage = (
    [ 'truncated to half',      sub { put($wallet, substr($good, 0, length($good) / 2)) } ],
    [ 'zero bytes',             sub { put($wallet, '') } ],
    [ 'random bytes',           sub { put($wallet, join('', map { chr(int(rand(256))) } 1 .. length($good))) } ],
    [ 'one byte flipped',       sub { my $b = $good; substr($b, length($b) / 2, 1) ^= "\x01"; put($wallet, $b) } ],
    [ 'missing',                sub { unlink($wallet) } ],
    [ 'unreadable',             sub { chmod(0000, $wallet) } ],
);

for my $d (@damage)
{
    my ($what, $break) = @$d;
    $node->stop;
    $break->();
    my $damaged = file_md5($wallet);

    ok($node->start(fail_ok => 1), "$what: the server starts");

    my ($rc, $out, $err) = $node->psql('postgres', 'SELECT count(*) FROM secret');
    ok($rc != 0 && $err =~ /ERROR/, "$what: reading the table fails with an ERROR")
      or diag "rc=$rc out=$out err=$err";
    ($rc, $out, $err) = $node->psql('postgres', "INSERT INTO secret VALUES (1000, 'x')");
    ok($rc != 0 && $err =~ /ERROR/, "$what: writing to it fails with an ERROR")
      or diag "rc=$rc err=$err";
    ($rc, $out, $err) = $node->psql('postgres',
        'CREATE TABLE fresh (id int) USING encrypted_heap');
    ok($rc != 0 && $err =~ /ERROR/, "$what: creating an encrypted table fails with an ERROR")
      or diag "rc=$rc err=$err";

    for my $call ("pg_vault_tde_wallet_unlock('test-password')",
                  'pg_vault_tde_rotate_kek()',
                  "pg_vault_tde_wallet_change_passphrase('test-password', 'other')",
                  "pg_vault_tde_wallet_init('other')")
    {
        ($rc, $out, $err) = $node->psql('postgres', "SELECT $call");
        (my $fn = $call) =~ s/\(.*//;
        ok($rc != 0, "$what: $fn fails") or diag "err=$err";
        is(file_md5($wallet), $damaged, "$what: ... and leaves the file as it was");
    }

    $node->stop;
    chmod(0600, $wallet) if -e $wallet;
    put($wallet, $good);
    $node->start;
    is(equals_truth(), '0', "$what: with the file restored, every row reads");
}

# Leftovers of an interrupted write: a wallet.p12.new (a crash before the
# rename) and a wallet.p12.lock.  Neither may matter.
$node->stop;
put("$wallet.new", substr($good, 0, 100));
put("$wallet.lock", '');
$node->start;
is(equals_truth(), '0', 'leftover .new and .lock: every row reads');
my ($rc, $out, $err) = $node->psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');
is($rc, 0, 'leftover .new and .lock: rotate_kek() succeeds') or diag $err;
ok(!-e "$wallet.new", '... and the .new file is gone');
$node->restart;
is(equals_truth(), '0', '... and after a restart every row still reads');
($rc, $out, $err) = $node->psql('postgres',
    "SELECT pg_vault_tde_wallet_change_passphrase('test-password', 'test-password')");
is($rc, 0, 'change_passphrase() succeeds with the leftover .lock') or diag $err;
$node->restart;
is(equals_truth(), '0', '... and every row reads after it');

# The refusal says why, and starting over is still possible: with the
# tables dropped, nothing is wrapped under the lost wallet.
$node->stop;
unlink($wallet);
$node->start;
($rc, $out, $err) = $node->psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
like($err, qr/no wallet at .*, but \d+ key\(s\) of this database are wrapped under a local wallet/,
     'wallet missing: wallet_init() says why it refuses');
($rc, $out, $err) = $node->psql('postgres', 'DROP TABLE secret');
is($rc, 0, 'wallet missing: the encrypted table can be dropped') or diag $err;
($rc, $out, $err) = $node->psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
is($rc, 0, '... after which wallet_init() makes a new wallet') or diag $err;
$node->safe_psql('postgres', q{
    SET client_min_messages = error;
    CREATE TABLE secret USING encrypted_heap AS SELECT * FROM truth;
});
$node->restart;
is(equals_truth(), '0', '... which works across a restart');

$node->stop;
done_testing();
