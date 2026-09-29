# tap/32_rotate_online_toast.t — out-of-line values must survive
# pg_vault_tde_rotate_online()
#
# The rotation worker rewrites every row with tuple_update().  Its pre-TOAST
# hands the old tuple to toast_tuple_init(), which reuses an unchanged external
# value as it is: the row was re-encrypted under DEK N+1, its TOAST chunks were
# left under DEK N.  The catalog only keeps the current key, so N lived on in
# the shared-memory cache alone, and the values became unreadable at the next
# restart or the next rotation (PSQLE-189).
#
# One table, three kinds of out-of-line value next to short ones and NULLs:
#
#   ext   STORAGE EXTERNAL, stored uncompressed
#   cmp   EXTENDED, compressed and still too large, stored compressed
#   gone  a dropped column: nothing reads it, but its chunks stay in the
#         TOAST relation
#
# Checked after each step: every tag verifies, the contents equal a plain-heap
# twin, and the TOAST relation holds as many live chunks as before and every
# one of them decrypts (the old chunks are deleted, not orphaned, and none is
# left under a key the catalog no longer has).  Steps: rotation #1, a
# restart, rotation #2, a restart — the first restart is the common case, the
# second rotation drops the key the first one left behind.
#
# The whole scenario runs once per KMS provider the environment offers, as in
# tap/29: local always; vault when VAULT_ADDR is set; pkcs11 when SoftHSM2 is
# installed.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use File::Temp qw(tempdir);
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $vault_addr = $ENV{VAULT_ADDR};
my ($module) = grep { $_ && -e $_ } (
    $ENV{SOFTHSM2_MODULE} // (),
    '/usr/lib/softhsm/libsofthsm2.so',
    '/usr/lib64/pkcs11/libsofthsm2.so',
    '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so');

my @providers = ('local');
push @providers, 'vault'  if $vault_addr;
push @providers, 'pkcs11' if $module;
plan tests => 19 * scalar(@providers);

my ($node, $p, $toast, $chunks);

# A started node on provider $p, with the extension and its KEK in place.
sub new_node
{
    my $n = PostgreSQL::Test::Cluster->new("rotate_toast_$p");
    $n->init;
    my $conf = "shared_preload_libraries = 'pg_vault_tde'\n";

    if ($p eq 'local')
    {
        $conf .= "pg_vault_tde.kms_provider = 'local'\n"
               . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n";
        system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
    }
    elsif ($p eq 'vault')
    {
        $conf .= "pg_vault_tde.kms_provider = 'vault'\n"
               . "pg_vault_tde.dev_mode = on\n"
               . "pg_vault_tde.vault_url = '$vault_addr'\n"
               . "pg_vault_tde.vault_token = 'test-token'\n"
               . "pg_vault_tde.vault_transit_mount = 'transit'\n"
               . "pg_vault_tde.vault_key_name = 'pg-tde-dek'\n";
    }
    else
    {
        # The postmaster, and so the rotation worker, reads the PIN with getenv().
        my $hsmdir = tempdir(CLEANUP => 1);
        mkdir "$hsmdir/tokens" or die "mkdir $hsmdir/tokens: $!";
        open my $cf, '>', "$hsmdir/softhsm2.conf" or die $!;
        print $cf "directories.tokendir = $hsmdir/tokens\n";
        print $cf "objectstore.backend = file\n";
        close $cf;
        $ENV{SOFTHSM2_CONF}     = "$hsmdir/softhsm2.conf";
        $ENV{PG_TDE_PKCS11_PIN} = '1234';
        system('softhsm2-util', '--init-token', '--free',
               '--label', 'pgtde-toast',
               '--so-pin', '12345', '--pin', '1234') == 0
          or die 'softhsm2-util --init-token failed';
        $conf .= "pg_vault_tde.kms_provider = 'pkcs11'\n"
               . "pg_vault_tde.pkcs11_library = '$module'\n"
               . "pg_vault_tde.pkcs11_token_label = 'pgtde-toast'\n";
    }

    $n->append_conf('postgresql.conf', $conf);
    $n->start;
    $n->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    if ($p eq 'local')
    {
        $n->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
        $n->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
    }
    elsif ($p eq 'pkcs11')
    {
        $n->safe_psql('postgres', 'SELECT pg_vault_tde_pkcs11_keygen();');
    }
    return $n;
}

# Three assertions: every tag verifies, the contents equal the twin, and the
# TOAST relation holds as many live chunks as it started with.
sub check_table
{
    my ($when) = @_;
    my ($rc, $out, $err) = $node->psql('postgres',
        "SELECT total_tuples || '|' || failed_tuples "
      . "FROM pg_vault_tde_verify_integrity('tr')");
    is($out, '30|0', "$p $when: every tag verifies") or diag $err;
    ($rc, $out, $err) = $node->psql('postgres', q{
        SELECT count(*) FROM (
            (SELECT * FROM tr EXCEPT ALL SELECT * FROM tr_truth)
            UNION ALL
            (SELECT * FROM tr_truth EXCEPT ALL SELECT * FROM tr)) d});
    is($out, '0', "$p $when: contents equal the plain-heap twin") or diag $err;
    ($rc, $out, $err) = $node->psql('postgres', "SELECT count(*) FROM $toast");
    is($out, $chunks, "$p $when: the TOAST relation holds $chunks live chunks")
      or diag $err;
}

sub rotate
{
    my ($label) = @_;
    $node->safe_psql('postgres',
        "DELETE FROM pg_vault_tde_rotation_progress WHERE relid = 'tr'::regclass::oid");
    $node->safe_psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('tr')");
    $node->poll_query_until('postgres', q{
        SELECT status IN ('complete', 'failed')
        FROM pg_vault_tde_rotation_progress
        WHERE relid = 'tr'::regclass::oid})
      or die "$label never finished";
    is($node->safe_psql('postgres',
           "SELECT status FROM pg_vault_tde_rotation_progress "
         . "WHERE relid = 'tr'::regclass::oid"), 'complete', "$p: $label completes");
}

sub restart
{
    $node->restart;
    $node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')")
      if $p eq 'local';
}

sub scenario
{
    # ext: out of line on even rows, short on odd ones, NULL on every fifth.
    # cmp: half hex, half runs of '-' — compresses by about half and is still
    # far above the TOAST target; NULL on every third row.
    # gone: out of line on odd rows, dropped before anything is checked.
    $node->safe_psql('postgres', q{
        CREATE TABLE tr (id int, small text, ext text, cmp text, gone text)
            USING encrypted_heap;
        ALTER TABLE tr ALTER COLUMN ext SET STORAGE EXTERNAL;
        ALTER TABLE tr ALTER COLUMN gone SET STORAGE EXTERNAL;
        INSERT INTO tr
        SELECT g, 'row_' || g,
               CASE WHEN g % 5 = 0 THEN NULL
                    WHEN g % 2 = 0 THEN repeat(md5(g::text), 400)
                    ELSE 'short_' || g END,
               CASE WHEN g % 3 = 0 THEN NULL
                    ELSE (SELECT string_agg(md5((g * 1000 + i)::text) || repeat('-', 32), '')
                          FROM generate_series(1, 400) i) END,
               CASE WHEN g % 2 = 1 THEN repeat(md5((-g)::text), 400) END
        FROM generate_series(1, 30) g;
        ALTER TABLE tr DROP COLUMN gone;
        CREATE TABLE tr_truth AS SELECT * FROM tr;
    });
    $toast = $node->safe_psql('postgres',
        "SELECT reltoastrelid::regclass FROM pg_class WHERE oid = 'tr'::regclass");
    $chunks = $node->safe_psql('postgres', "SELECT count(*) FROM $toast");
    ok($chunks > 0, "$p: the TOAST relation holds chunks ($chunks)");
    is($node->safe_psql('postgres', q{
           SELECT count(*) FROM tr
           WHERE pg_column_compression(cmp) = 'pglz' AND pg_column_size(cmp) > 4000}),
       '20', "$p: every cmp value is stored compressed and out of line");
    check_table('before any rotation');

    rotate('rotation #1');
    check_table('after rotation #1');
    restart();
    check_table('after rotation #1 and a restart');

    rotate('rotation #2');
    check_table('after rotation #2');
    restart();
    check_table('after rotation #2 and a restart');
}

for (@providers)
{
    $p    = $_;
    $node = new_node();
    scenario();
    $node->stop;
}
