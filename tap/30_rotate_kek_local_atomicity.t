# tap/30_rotate_kek_local_atomicity.t — a local-wallet KEK rotation that does
# not commit, or that other sessions did not see, must not cost any table
#
# pg_vault_tde_rotate_kek() re-wraps every DEK in pg_vault_tde_catalog, which
# is transactional, and replaces the wallet file, which is not.  With the local
# provider the file held a single KEK and was rewritten before the COMMIT, so a
# rotation that rolled back, failed later in its statement, or died in a crash
# left the catalog wrapped under a KEK that no longer existed (PSQLE-185).
# A session that had unlocked the wallet also kept the old KEK in its own
# memory, and went on using it after another session's rotation.
#
# One fresh node per scenario, so a failure in one cannot leak into the next:
#
#   commit     the control: a rotation that commits
#   rollback   BEGIN; rotate_kek(); ROLLBACK
#   abort      rotate_kek() then an error in the same statement, no BEGIN
#   crash      rotate_kek() has returned, the transaction is still open, and
#              the server stops immediately
#   stale      a session unlocked the wallet before another session rotated
#              the KEK: it reads, then creates and fills a new table
#   concurrent a CREATE TABLE waits on a rotation that then aborts
#
# The errors that abort a statement after rotate_kek() are 1/(random()*0)::int
# rather than 1/0: a constant 1/0 is folded at plan time, so the statement fails
# before the rotation ever runs and the scenario tests nothing.
#
# Every table is compared with a plain-heap twin right after the scenario and
# after a restart, which is when a key that existed only in some process's
# memory is gone.
use strict;
use warnings;
use Test::More tests => 34;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my ($node, $case);

sub new_node
{
    ($case) = @_;
    system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
    $node = PostgreSQL::Test::Cluster->new("kek_$case");
    $node->init;
    $node->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'local'\n" .
        "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
    $node->start;
    $node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    $node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
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
    is($out, '100|0', "$case $t $when: every tag verifies") or diag $err;
    ($rc, $out, $err) = $node->psql('postgres', qq{
        SELECT count(*) FROM (
            (SELECT * FROM $t EXCEPT ALL SELECT * FROM ${t}_truth)
            UNION ALL
            (SELECT * FROM ${t}_truth EXCEPT ALL SELECT * FROM $t)) d});
    is($out, '0', "$case $t $when: contents equal the plain-heap twin") or diag $err;
}

sub check_now_and_after_restart
{
    my @tables = @_;
    check_table($_, 'right after') for @tables;
    $node->restart;
    check_table($_, 'after a restart') for @tables;
}

# ---- commit: the control ----------------------------------------------------
new_node('commit');
make_table('t');
my ($rc, $out, $err) = $node->psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');
is($rc, 0, 'commit: rotate_kek() succeeds') or diag $err;
check_now_and_after_restart('t');
$node->stop;

# ---- rollback ---------------------------------------------------------------
new_node('rollback');
make_table('t');
$node->psql('postgres', 'BEGIN; SELECT pg_vault_tde_rotate_kek(); ROLLBACK;');
check_now_and_after_restart('t');
$node->stop;

# ---- abort: the statement fails after rotate_kek() returned -----------------
new_node('abort');
make_table('t');
($rc, $out, $err) = $node->psql('postgres',
    'SELECT pg_vault_tde_rotate_kek(), 1/(random()*0)::int');
like($err, qr/division by zero/, 'abort: the statement failed after the rotation');
check_now_and_after_restart('t');
$node->stop;

# ---- crash: the rotation is done, the transaction is not --------------------
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
       'crash: rotate_kek() returned and its transaction is still open');
    $node->stop('immediate');
    eval { $s->quit; };
}
$node->start;
check_table('t', 'after the crash');
$node->stop;

# ---- stale: another session holds the old KEK ------------------------------
new_node('stale');
make_table('t');
{
    my $b = $node->background_psql('postgres', on_error_stop => 0);
    $b->query_safe("SELECT pg_vault_tde_wallet_unlock('test-password')");
    $b->query_safe('SELECT count(*) FROM t');

    $node->safe_psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');

    my $n = eval { $b->query_safe('SELECT count(*) FROM t') };
    is($n, '100', 'stale: the session reads t after the other session rotated the KEK')
      or diag $@;
    eval {
        $b->query_safe(q{
            CREATE TABLE t_new (id int, val text) USING encrypted_heap;
            INSERT INTO t_new SELECT g, 't_new_' || g FROM generate_series(1, 100) g;
            CREATE TABLE t_new_truth AS SELECT * FROM t_new;
        });
    };
    diag "stale: creating t_new failed: $@" if $@;
    eval { $b->quit; };
}
check_now_and_after_restart('t', 't_new');
$node->stop;

# ---- concurrent: a CREATE TABLE waits on a rotation that aborts ------------
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
