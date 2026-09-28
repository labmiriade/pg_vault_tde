# tap/29_rotate_online_concurrent_access.t — a table that is read or written
# while pg_vault_tde_rotate_online() runs must stay readable afterwards
#
# The rotation worker runs one transaction: zero_rel_dek() demotes the shmem
# cache entry, update_rel_dek() rewrites the catalog row with DEK N+1, and
# reencrypt_table() rewrites every row.  Between the first two steps the
# cache holds no live DEK while the catalog, as every other transaction sees
# it, still says N.  Any backend that touches the table in that window reloads
# the cache from the catalog — and puts DEK N back as the current key.  The
# worker then re-encrypted with whatever the cache held, and the key it left
# behind was never persisted: rows became unreadable at once, or at the next
# restart once the shmem copy was gone (PSQLE-184).
#
# The window is held open deterministically: a session locks the relation's
# pg_vault_tde_catalog row FOR UPDATE, so the worker stops in
# CatalogTupleUpdate() — after zero_rel_dek(), before the catalog changes.
# Three tables, each rotated with a different visitor in that window:
#
#   rot_ctl  nobody               the control; must pass on any version
#   rot_rd   a SELECT             readers reload the cache too
#   rot_wr   an INSERT + COMMIT   the writer runs in its own session, since a
#                                 fixed rotation may make it wait
#
# A fourth table has no pause: its writer's transaction is already open when
# the rotation starts, and commits after.
#
#   rot_if   in-flight INSERT     a rotation that waits for writers must take
#                                 its snapshot after the wait, or the row it
#                                 waited for is left out of the re-encryption
#
# Each table is compared against a plain-heap twin after the rotation, after a
# second rotation (which cannot decrypt rows left two generations behind), and
# after a restart (which drops everything that lived only in shared memory).
use strict;
use warnings;
use Test::More tests => 39;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('rotate_conc_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

my %rows = (rot_ctl => 1000, rot_rd => 1000, rot_wr => 1005, rot_if => 1005);
for my $t (sort keys %rows) {
    $node->safe_psql('postgres', qq{
        CREATE TABLE $t (id int, val text) USING encrypted_heap;
        INSERT INTO $t SELECT g, 'row_' || g || repeat('x', 50)
            FROM generate_series(1, 1000) g;
        CREATE TABLE ${t}_truth AS SELECT * FROM $t;
    });
}
# The writers' rows, known to the truth tables from the start.
$node->safe_psql('postgres',
    "INSERT INTO ${_}_truth SELECT g, 'win_' || g FROM generate_series(1001, 1005) g")
  for qw(rot_wr rot_if);

# Two assertions: every tag verifies, and the contents equal the twin.
sub check_table
{
    my ($t, $when) = @_;
    my ($rc, $out, $err) = $node->psql('postgres',
        "SELECT total_tuples || '|' || failed_tuples "
      . "FROM pg_vault_tde_verify_integrity('$t')");
    is($out, "$rows{$t}|0", "$t $when: every tag verifies") or diag $err;
    ($rc, $out, $err) = $node->psql('postgres', qq{
        SELECT count(*) FROM (
            (SELECT * FROM $t EXCEPT ALL SELECT * FROM ${t}_truth)
            UNION ALL
            (SELECT * FROM ${t}_truth EXCEPT ALL SELECT * FROM $t)) d});
    is($out, '0', "$t $when: contents equal the plain-heap twin") or diag $err;
}

sub wait_for_rotation
{
    my ($t) = @_;
    $node->poll_query_until('postgres', qq{
        SELECT status IN ('complete', 'failed')
        FROM pg_vault_tde_rotation_progress
        WHERE relid = '$t'::regclass::oid})
      or die "rotation of $t never finished";
    return $node->safe_psql('postgres',
        "SELECT status FROM pg_vault_tde_rotation_progress "
      . "WHERE relid = '$t'::regclass::oid");
}

sub start_rotation
{
    my ($t) = @_;
    $node->safe_psql('postgres',
        "DELETE FROM pg_vault_tde_rotation_progress WHERE relid = '$t'::regclass::oid");
    $node->safe_psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('$t')");
}

# ---- Rotation #1, with a visitor in the window ------------------------------
for my $t (qw(rot_ctl rot_rd rot_wr)) {
    # Warm the cache, so the worker demotes a live entry.
    $node->safe_psql('postgres', "SELECT count(*) FROM $t");

    my $blocker = $node->background_psql('postgres');
    $blocker->query_safe('BEGIN');
    $blocker->query_safe(
        "SELECT 1 FROM pg_vault_tde_catalog WHERE relid = '$t'::regclass::oid FOR UPDATE");

    start_rotation($t);
    ok($node->poll_query_until('postgres', q{
            SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                           WHERE backend_type = 'pg_vault_tde rotation'
                             AND wait_event_type = 'Lock')}),
       "$t: the worker is held between zero_rel_dek() and update_rel_dek()");

    my $writer;
    if ($t eq 'rot_rd')
    {
        $node->safe_psql('postgres', "SELECT count(*) FROM $t");
    }
    elsif ($t eq 'rot_wr')
    {
        $writer = $node->background_psql('postgres');
        $writer->query_safe('SET client_min_messages = warning');
        $writer->query_until(qr/window_insert_sent/, q{
\echo window_insert_sent
INSERT INTO rot_wr SELECT g, 'win_' || g FROM generate_series(1001, 1005) g;
});
    }

    $blocker->query_safe('COMMIT');
    $blocker->quit;

    is(wait_for_rotation($t), 'complete', "$t: rotation #1 completes");
    if ($writer)
    {
        # Waits for the INSERT if the rotation made it queue.
        $writer->query_safe('SELECT 1');
        $writer->quit;
    }
    is($node->safe_psql('postgres',
           "SELECT generation FROM pg_vault_tde_catalog "
         . "WHERE relid = '$t'::regclass::oid"), '2',
       "$t: catalog advanced to generation 2");
    check_table($t, 'after rotation #1');
}

# ---- Rotation #1 with a writer already in flight ---------------------------
{
    my $t = 'rot_if';
    $node->safe_psql('postgres', "SELECT count(*) FROM $t");

    my $writer = $node->background_psql('postgres');
    $writer->query_safe('SET client_min_messages = warning');
    $writer->query_safe('BEGIN');
    $writer->query_safe(
        "INSERT INTO $t SELECT g, 'win_' || g FROM generate_series(1001, 1005) g");

    start_rotation($t);
    # A rotation that waits for writers is now queued behind this one; one that
    # does not has already run.  Either way, commit only once it has got there.
    $node->poll_query_until('postgres', qq{
        SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                       WHERE backend_type = 'pg_vault_tde rotation'
                         AND wait_event_type = 'Lock')
            OR EXISTS (SELECT 1 FROM pg_vault_tde_rotation_progress
                       WHERE relid = '$t'::regclass::oid
                         AND status IN ('complete', 'failed'))})
      or die "rotation of $t neither waited nor finished";
    $writer->query_safe('COMMIT');
    $writer->quit;

    is(wait_for_rotation($t), 'complete', "$t: rotation #1 completes");
    is($node->safe_psql('postgres',
           "SELECT generation FROM pg_vault_tde_catalog "
         . "WHERE relid = '$t'::regclass::oid"), '2',
       "$t: catalog advanced to generation 2");
    check_table($t, 'after rotation #1');
}

# ---- Rotation #2, nobody in the window ------------------------------------
for my $t (qw(rot_ctl rot_rd rot_wr rot_if)) {
    start_rotation($t);
    is(wait_for_rotation($t), 'complete', "$t: rotation #2 completes");
    check_table($t, 'after rotation #2');
}

# ---- Restart: whatever lived only in shared memory is gone ------------------
$node->restart;
$node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
check_table($_, 'after a restart') for qw(rot_ctl rot_rd rot_wr rot_if);

$node->stop;
