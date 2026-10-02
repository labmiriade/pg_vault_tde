# tap/39_index_build_old_snapshot.t — an index built while an older snapshot
# is open must not make that snapshot miss rows or see wrong ones
#
# CREATE INDEX on encrypted_heap runs the TAM's own build scan, because keys
# must be computed from decrypted rows.  heapam's scan reads with SnapshotAny:
# it indexes recently dead tuples, which an older snapshot can still see, and
# when a HOT chain's indexed column changed along the chain it sets
# ii_BrokenHotChain, so that transactions older than the index do not use it
# (indcheckxmin).  The TAM's scan read with a fresh MVCC snapshot and did
# neither (PSQLE-201).
#
# A REPEATABLE READ transaction takes its snapshot; another session then
# deletes ten rows and HOT-updates the indexed column of ten others (no index
# on it yet, so the updates stay HOT); then CREATE INDEX.  The old transaction
# queries through the index — index scans forced — and must see what a plain
# heap twin shows it: the deleted rows, and the updated ones with their old
# values only.  A fresh session is the control.
#
# Then the case heapam never meets: two rotations while an old snapshot stays
# open leave its row versions under a DEK generation nobody holds any more.
# They are recently dead, so the build must index them and cannot decrypt
# them; it must still build, and mark the index unusable for old snapshots
# (indcheckxmin) instead, so that new sessions get the right rows.
#
# Last, a parallel build: the workers run the same scan over a parallel scan
# the leader opened.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 16;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('index_old_snapshot');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.allow_plaintext_index = on\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

my $counts = q{
    SET enable_seqscan = off; SET enable_bitmapscan = off;
    SELECT (SELECT count(*) FROM %t WHERE k BETWEEN 1 AND 10) || ',' ||
           (SELECT count(*) FROM %t WHERE k BETWEEN 11 AND 20) || ',' ||
           (SELECT count(*) FROM %t WHERE k BETWEEN 1011 AND 1020)};

# Returns [what the old snapshot sees, what a fresh session sees].
sub scenario
{
    my ($t, $am) = @_;
    (my $q = $counts) =~ s/%t/$t/g;
    $node->safe_psql('postgres', qq{
        CREATE TABLE $t (id int, k int) USING $am WITH (fillfactor = 50);
        INSERT INTO $t SELECT g, g FROM generate_series(1, 100) g;
    });

    my $old = $node->background_psql('postgres');
    $old->query_safe('BEGIN ISOLATION LEVEL REPEATABLE READ');
    $old->query_safe("SELECT count(*) FROM $t");

    $node->safe_psql('postgres', "DELETE FROM $t WHERE id <= 10");
    $node->safe_psql('postgres', "UPDATE $t SET k = k + 1000 WHERE id BETWEEN 11 AND 20");
    $node->safe_psql('postgres', "SET client_min_messages = error; CREATE INDEX ${t}_k ON $t (k)");

    my $seen_old = $old->query_safe($q);
    $old->query_safe('COMMIT');
    $old->quit;
    chomp $seen_old;
    my $seen_new = $node->safe_psql('postgres', $q);
    return [ (split /\n/, $seen_old)[-1], $seen_new ];
}

my $h = scenario('ih', 'heap');
my $e = scenario('ie', 'encrypted_heap');

is($h->[0], '10,10,0', 'heap: the old snapshot sees the deleted rows and the old values');
is($h->[1], '0,0,10',  'heap: a fresh session sees the new state');
# The premise of the second case: the updates stayed HOT on both tables.
for my $t (qw(ih ie))
{
    is($node->safe_psql('postgres',
           "SELECT n_tup_hot_upd FROM pg_stat_user_tables WHERE relname = '$t'"),
       '10', "$t: the ten updates stayed HOT");
}

is((split /,/, $e->[0])[0], (split /,/, $h->[0])[0],
   'encrypted_heap: the old snapshot finds the rows deleted after it, as on heap');
is((split /,/, $e->[0])[1], (split /,/, $h->[0])[1],
   'encrypted_heap: the old snapshot finds the HOT-updated rows by their old values, as on heap');
is((split /,/, $e->[0])[2], (split /,/, $h->[0])[2],
   'encrypted_heap: the old snapshot does not see them under their new values, as on heap');
is($e->[1], $h->[1], 'encrypted_heap: a fresh session sees what it sees on heap');

# ---- two rotations under an open old snapshot, then CREATE INDEX ----------
$node->safe_psql('postgres', q{
    SET client_min_messages = error;
    CREATE TABLE ir (id int, k int) USING encrypted_heap;
    INSERT INTO ir SELECT g, g FROM generate_series(1, 100) g;
    -- With an index the rotations' rewrites are not HOT: every retired
    -- version must then be indexed, and decrypted, by the build below.
    CREATE INDEX ir_id ON ir (id);
});
my $old = $node->background_psql('postgres');
$old->query_safe('BEGIN ISOLATION LEVEL REPEATABLE READ');
$old->query_safe('SELECT count(*) FROM ir');
for my $n (1, 2)
{
    $node->safe_psql('postgres',
        "DELETE FROM pg_vault_tde_rotation_progress WHERE relid = 'ir'::regclass::oid");
    $node->safe_psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('ir')");
    $node->poll_query_until('postgres', q{
        SELECT status IN ('complete', 'failed') FROM pg_vault_tde_rotation_progress
        WHERE relid = 'ir'::regclass::oid}) or die "rotation #$n never finished";
}
is($node->safe_psql('postgres',
       "SELECT status FROM pg_vault_tde_rotation_progress WHERE relid = 'ir'::regclass::oid"),
   'complete', 'encrypted_heap: two rotations complete under the open snapshot');
$node->safe_psql('postgres', 'SELECT pg_stat_force_next_flush()');
is($node->safe_psql('postgres',
       "SELECT n_tup_hot_upd FROM pg_stat_user_tables WHERE relname = 'ir'"), '0',
   'encrypted_heap: none of the rotations\' rewrites stayed HOT');
my ($rc, $out, $err) = $node->psql('postgres',
    'SET client_min_messages = error; CREATE INDEX ir_k ON ir (k)');
is($rc, 0, 'encrypted_heap: CREATE INDEX builds although old versions no longer decrypt')
  or diag $err;
is($node->safe_psql('postgres',
       "SELECT indcheckxmin FROM pg_index WHERE indexrelid = 'ir_k'::regclass"), 't',
   'encrypted_heap: ... and marks the index unusable for older snapshots');
is($node->safe_psql('postgres', q{
       SET enable_seqscan = off; SET enable_bitmapscan = off;
       SELECT count(*) FROM ir WHERE k BETWEEN 1 AND 100}), '100',
   'encrypted_heap: a new session finds every row through it');
$old->query_safe('ROLLBACK');
$old->quit;

# ---- a parallel build -------------------------------------------------------
$node->safe_psql('postgres', 'CREATE EXTENSION amcheck');
$node->safe_psql('postgres', q{
    CREATE TABLE ip (id int, k int, pad text) USING encrypted_heap;
    INSERT INTO ip SELECT g, g % 1000, repeat('p', 50) FROM generate_series(1, 300000) g;
    DELETE FROM ip WHERE id % 10 = 0;
    ALTER TABLE ip SET (parallel_workers = 2);
});
($rc, $out, $err) = $node->psql('postgres', q{
    SET client_min_messages = debug1;
    SET max_parallel_maintenance_workers = 2;
    SET maintenance_work_mem = '64MB';
    CREATE INDEX ip_k ON ip (k);
    CREATE UNIQUE INDEX ip_id ON ip (id)});
like($err, qr/building index "ip_id" on table "ip" with request for 2 parallel workers/,
     'encrypted_heap: CREATE INDEX runs in parallel');
($rc, $out, $err) = $node->psql('postgres',
    "SELECT bt_index_check('ip_k', true), bt_index_check('ip_id', true)");
is($rc, 0, 'encrypted_heap: amcheck heapallindexed passes on the parallel builds') or diag $err;
is($node->safe_psql('postgres', q{
       SET enable_seqscan = off; SET enable_bitmapscan = off;
       SELECT count(*) FROM ip WHERE k BETWEEN 0 AND 999}), '270000',
   'encrypted_heap: every live row is reachable through the parallel-built index');

$node->stop;
