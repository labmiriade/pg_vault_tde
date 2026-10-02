# tap/30_rotate_kek_atomicity.t — a KEK rotation that does not commit, or
# that other sessions did not see, must not cost any table — with every KMS
# provider
#
# pg_vault_tde_rotate_kek() re-wraps every DEK in pg_vault_tde_catalog, which
# is transactional, and changes the key store, which is not: the local wallet
# file, the Vault transit key, the keys on the token.  With the local provider
# the file held a single KEK and was rewritten before the COMMIT, so a
# rotation that rolled back, failed later in its statement, or died in a crash
# left the catalog wrapped under a KEK that no longer existed (PSQLE-185).
# Vault and PKCS#11 keep every KEK version and tag each wrapped DEK with its
# own, which should make them safe by construction; nothing tested it
# (PSQLE-209).
#
# One fresh node per scenario, so a failure in one cannot leak into the next:
#
#   commit     the control: a rotation that commits
#   rollback   BEGIN; rotate_kek(); ROLLBACK
#   abort      rotate_kek() then an error in the same statement, no BEGIN
#   crash      rotate_kek() has returned, the transaction is still open, and
#              the server stops immediately
#   stale      a session read the tables before another session rotated the
#              KEK (local: it had unlocked the wallet): it reads, then creates
#              and fills a new table
#   concurrent a CREATE TABLE waits on a rotation that then aborts
#   timeout    the rotation has changed the key store and waits for the
#              catalog when statement_timeout cancels it; the same session
#              then rotates again, and so does another one
#
# The errors that abort a statement after rotate_kek() are 1/(random()*0)::int
# rather than 1/0: a constant 1/0 is folded at plan time, so the statement fails
# before the rotation ever runs and the scenario tests nothing.
#
# Every table is compared with a plain-heap twin right after the scenario and
# after a restart, which is when a key that existed only in some process's
# memory is gone.  The whole set runs once per provider the environment
# offers: local always; vault when VAULT_ADDR is set (make ci-tap starts one);
# pkcs11 when SoftHSM2 is installed.
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
plan tests => 41 * scalar(@providers);

my ($node, $p, $case);

sub new_node
{
    ($case) = @_;
    $node = PostgreSQL::Test::Cluster->new("kek_${p}_$case");
    $node->init;
    my $conf = "shared_preload_libraries = 'pg_vault_tde'\n";

    if ($p eq 'local')
    {
        system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
        $conf .= "pg_vault_tde.kms_provider = 'local'\n"
               . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n";
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
        # A token of its own per node; the postmaster reads the PIN with getenv().
        my $hsmdir = tempdir(CLEANUP => 1);
        mkdir "$hsmdir/tokens" or die "mkdir $hsmdir/tokens: $!";
        open my $cf, '>', "$hsmdir/softhsm2.conf" or die $!;
        print $cf "directories.tokendir = $hsmdir/tokens\n";
        print $cf "objectstore.backend = file\n";
        close $cf;
        $ENV{SOFTHSM2_CONF}     = "$hsmdir/softhsm2.conf";
        $ENV{PG_TDE_PKCS11_PIN} = '1234';
        system('softhsm2-util', '--init-token', '--free', '--label', 'pgtde-kek',
               '--so-pin', '12345', '--pin', '1234') == 0
          or die 'softhsm2-util --init-token failed';
        $conf .= "pg_vault_tde.kms_provider = 'pkcs11'\n"
               . "pg_vault_tde.pkcs11_library = '$module'\n"
               . "pg_vault_tde.pkcs11_token_label = 'pgtde-kek'\n";
    }

    $node->append_conf('postgresql.conf', $conf);
    $node->start;
    $node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    $node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')")
      if $p eq 'local';
    $node->safe_psql('postgres', 'SELECT pg_vault_tde_pkcs11_keygen()')
      if $p eq 'pkcs11';
}

sub make_table
{
    my ($t) = @_;
    $node->safe_psql('postgres', qq{
        CREATE TABLE $t (id int, val text) USING encrypted_heap;
        INSERT INTO $t SELECT g, '${t}_' || g FROM generate_series(1, 100) g;
        CREATE TABLE ${t}_truth AS SELECT * FROM $t;
    });
}

# Two assertions: every tag verifies, and the contents equal the twin.
sub check_table
{
    my ($t, $when) = @_;
    my ($rc, $out, $err) = $node->psql('postgres',
        "SELECT total_tuples || '|' || failed_tuples "
      . "FROM pg_vault_tde_verify_integrity('$t')");
    is($out, '100|0', "$p $case $t $when: every tag verifies") or diag $err;
    ($rc, $out, $err) = $node->psql('postgres', qq{
        SELECT count(*) FROM (
            (SELECT * FROM $t EXCEPT ALL SELECT * FROM ${t}_truth)
            UNION ALL
            (SELECT * FROM ${t}_truth EXCEPT ALL SELECT * FROM $t)) d});
    is($out, '0', "$p $case $t $when: contents equal the plain-heap twin") or diag $err;
}

sub check_now_and_after_restart
{
    my @tables = @_;
    check_table($_, 'right after') for @tables;
    $node->restart;
    check_table($_, 'after a restart') for @tables;
}

# A named sub sees the file's $p, not a foreach alias of it: assign it.
for my $prov (@providers)
{
    $p = $prov;
    # ---- commit: the control ------------------------------------------------
    new_node('commit');
    make_table('t');
    my ($rc, $out, $err) = $node->psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');
    is($rc, 0, "$p commit: rotate_kek() succeeds") or diag $err;
    check_now_and_after_restart('t');
    $node->stop;

    # ---- rollback -----------------------------------------------------------
    new_node('rollback');
    make_table('t');
    $node->psql('postgres', 'BEGIN; SELECT pg_vault_tde_rotate_kek(); ROLLBACK;');
    check_now_and_after_restart('t');
    $node->stop;

    # ---- abort: the statement fails after rotate_kek() returned -------------
    new_node('abort');
    make_table('t');
    ($rc, $out, $err) = $node->psql('postgres',
        'SELECT pg_vault_tde_rotate_kek(), 1/(random()*0)::int');
    like($err, qr/division by zero/, "$p abort: the statement failed after the rotation");
    check_now_and_after_restart('t');
    $node->stop;

    # ---- crash: the rotation is done, the transaction is not ----------------
    new_node('crash');
    make_table('t');
    {
        my $s = $node->background_psql('postgres', on_error_stop => 0);
        $s->query_until(qr/rotating/, q{
\echo rotating
SELECT pg_vault_tde_rotate_kek(), pg_sleep(300);
});
        ok($node->poll_query_until('postgres', q{
                SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                               WHERE wait_event = 'PgSleep'
                                 AND query LIKE '%rotate_kek%')}),
           "$p crash: rotate_kek() returned and its transaction is still open");
        $node->stop('immediate');
        eval { $s->quit; };
    }
    $node->start;
    check_table('t', 'after the crash');
    $node->stop;

    # ---- stale: another session read the tables before the rotation ---------
    new_node('stale');
    make_table('t');
    {
        my $b = $node->background_psql('postgres', on_error_stop => 0);
        $b->query_safe("SELECT pg_vault_tde_wallet_unlock('test-password')")
          if $p eq 'local';
        $b->query_safe('SELECT count(*) FROM t');

        $node->safe_psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');

        my $n = eval { $b->query_safe('SELECT count(*) FROM t') };
        is($n, '100', "$p stale: the session reads t after the other session rotated the KEK")
          or diag $@;
        eval {
            $b->query_safe(q{
                CREATE TABLE t_new (id int, val text) USING encrypted_heap;
                INSERT INTO t_new SELECT g, 't_new_' || g FROM generate_series(1, 100) g;
                CREATE TABLE t_new_truth AS SELECT * FROM t_new;
            });
        };
        diag "$p stale: creating t_new failed: $@" if $@;
        eval { $b->quit; };
    }
    check_now_and_after_restart('t', 't_new');
    $node->stop;

    # ---- concurrent: a CREATE TABLE waits on a rotation that aborts ---------
    new_node('concurrent');
    make_table('t');
    {
        my $a = $node->background_psql('postgres', on_error_stop => 0);
        $a->query_until(qr/rotating/, q{
\echo rotating
SELECT pg_vault_tde_rotate_kek(), pg_sleep(2), 1/(random()*0)::int;
});
        $node->poll_query_until('postgres', q{
            SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                           WHERE wait_event = 'PgSleep' AND query LIKE '%rotate_kek%')})
          or die 'rotation never reached its pause';
        # Waits on the rotation's lock on pg_vault_tde_catalog, then registers
        # its DEK once the rotation has aborted.
        $node->safe_psql('postgres', q{
            CREATE TABLE t_cc (id int, val text) USING encrypted_heap;
            INSERT INTO t_cc SELECT g, 't_cc_' || g FROM generate_series(1, 100) g;
            CREATE TABLE t_cc_truth AS SELECT * FROM t_cc;
        });
        eval { $a->quit; };
    }
    check_now_and_after_restart('t', 't_cc');
    $node->stop;

    # ---- timeout: cancelled after the key store changed, then retried -------
    # The rewrap takes ShareRowExclusiveLock on pg_vault_tde_catalog after the
    # provider has made the new KEK: a SHARE lock held elsewhere makes it wait
    # there until statement_timeout cancels it.
    new_node('timeout');
    make_table('t');
    {
        my $l = $node->background_psql('postgres', on_error_stop => 0);
        $l->query_safe('BEGIN; LOCK TABLE pg_vault_tde_catalog IN SHARE MODE;');
        my $r = $node->background_psql('postgres', on_error_stop => 0);
        $r->query_safe('SELECT count(*) FROM t');
        $r->query("SET statement_timeout = '1s'; SELECT pg_vault_tde_rotate_kek();");
        like($r->{stderr}, qr/canceling statement due to statement timeout/,
             "$p timeout: the rotation was cancelled while it waited for the catalog");
        $l->query_safe('COMMIT');
        $l->quit;

        $r->{stderr} = '';
        $r->query('SET statement_timeout = 0; SELECT pg_vault_tde_rotate_kek();');
        is($r->{stderr}, '', "$p timeout: the same session rotates again");
        $r->quit;
        ($rc, $out, $err) = $node->psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');
        is($rc, 0, "$p timeout: and so does a new session") or diag $err;
    }
    check_now_and_after_restart('t');
    $node->stop;
}
