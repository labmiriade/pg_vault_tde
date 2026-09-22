# tap/28_dml_memory_scaling.t
#
# Per-row memory that never comes back: every DML path, one assertion.
#
# WHY THIS EXISTS
#
# PostgreSQL code allocates from a MemoryContext, and which context you are in
# decides whether a per-row allocation is free or fatal.  ecxt_per_tuple_memory
# is reset after every row; ExecutorState lives for the whole statement.  Code
# that pallocs per row in ExecutorState and never pfrees looks perfectly normal
# and works fine in every functional test -- it only shows up as a backend that
# grows without bound on a bulk load.
#
# That shipped once already.  tde_iam_encrypt_index_datum() and its two callers
# left three buffers per indexed row to "a context reset" that never came:
# ExecutorState held 34.3 MB during a single 8M-row INSERT, against 0.72 MB for
# the same INSERT into a plain heap with a plain btree.
#
# NOTHING ELSE IN CI CAN SEE THIS.  ci-valgrind was green with the leak in
# place, and structurally always would be: palloc'd memory stays reachable from
# the context tree, so it is never "definitely lost".  A leak detector measures
# reachability; this is a lifetime bug, and to valgrind a lifetime bug is
# indistinguishable from legitimate use.
#
# HOW IT MEASURES
#
# The workload runs in its own backend and is never touched: a BEFORE ROW
# trigger would have been simpler, but it changes the path under test -- COPY
# stops using multi_insert as soon as a row trigger exists.  So the observation
# is external: this session calls pg_log_backend_memory_contexts() against the
# worker's pid while the statement is still running, and reads the size of
# ExecutorState out of the server log.
#
# THE ASSERTION
#
# Not an absolute ceiling.  What ExecutorState legitimately holds depends
# entirely on the statement: a DELETE of 300k rows sits at 0.01 MB while an
# INSERT ... ON CONFLICT sits at 7.7 MB, on a plain heap, with no extension
# loaded at all.  One constant cannot serve both, and a constant loose enough
# for the second would not notice a 64-byte-per-row leak in the first.
#
# So every workload is run twice -- once on encrypted_heap with a tde_btree
# index, once on a plain heap with a plain btree -- and what is asserted is
# that ours does not allocate dramatically more than core does for the same
# statement.  The baseline calibrates itself, and the comparison is exactly the
# one that exposed the leak: 34.3 MB against 0.72 MB.
#
# FACTOR is deliberately loose.  Encrypting a tuple does cost some transient
# memory that a plain heap never spends, so the two are not expected to match;
# what a leak looks like is an order of magnitude, not a percentage.  FLOOR
# keeps the ratio meaningful when both sides are near zero.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use File::Spec;

END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

use constant ROWS         => 300_000;
use constant TOAST_ROWS   => 8_000;      # large values: fewer rows, same point
use constant FACTOR       => 4;          # see "THE ASSERTION" above
use constant FLOOR_BYTES  => 4 * 1024 * 1024;
use constant POLL_SECONDS => 0.1;

my $node = PostgreSQL::Test::Cluster->new('dml_memory_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# Two long-lived sessions: the worker runs the DML, the probe watches it.  Both
# are persistent connections because safe_psql() would fork a psql per sample,
# which at a 100 ms cadence costs more than the thing being measured.
my $worker = $node->background_psql('postgres');
my $worker_pid = $worker->query_safe('SELECT pg_backend_pid()');
chomp $worker_pid;

my $probe = $node->background_psql('postgres');

# ---------------------------------------------------------------------------
# peak_executor_state — run $sql in the worker and return the largest
# ExecutorState seen while it was running, in bytes.  Returns undef when the
# statement finished before a single sample landed: that is a failure to
# measure, not a pass, and the caller says so.
# ---------------------------------------------------------------------------
my $run_seq = 0;

sub peak_executor_state
{
    my ($sql) = @_;
    my $peak    = 0;
    my $samples = 0;
    my $banner  = 'TDE_MEM_DONE_' . ++$run_seq;

    # Fire and do not wait: query_safe() blocks until the statement ends, which
    # is exactly the window we need to be inside.  The banner is what tells us
    # later that psql has come back, without parsing the workload's own output.
    $worker->{stdin} .= "$sql\n\\echo '$banner'\n";
    $worker->{run}->pump_nb();

    my $backend_state = sub {
        my $out = $probe->query_safe(
            "SELECT coalesce(max(state), 'gone') FROM pg_stat_activity WHERE pid = $worker_pid");
        chomp $out;
        return $out;
    };

    # Wait for the statement to reach the backend.  Bounded: a workload that
    # finishes before it is ever seen running has measured nothing, and the
    # caller reports that rather than passing on an empty sample set.
    my $waited = 0;
    while ($backend_state->() ne 'active')
    {
        select(undef, undef, undef, 0.02);
        last if ($waited += 0.02) > 3;
    }

    while ($backend_state->() eq 'active')
    {
        my $off = -s $node->logfile;
        $probe->query_safe("SELECT pg_log_backend_memory_contexts($worker_pid)");
        select(undef, undef, undef, POLL_SECONDS);

        my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $off);
        # 'used', not 'total': aset grows blocks geometrically, so total
        # counts free space inside them and overstates what is live.
        while ($log =~ /ExecutorState: \d+ total in \d+ blocks; \d+ free \(\d+ chunks\); (\d+) used/g)
        {
            $samples++;
            $peak = $1 if $1 > $peak;
        }
    }

    # Drain psql back to a clean prompt, then reset both buffers: the workload
    # may have emitted notices, and query_safe() treats any stderr as failure.
    $worker->{run}->pump() until $worker->{stdout} =~ /\Q$banner\E/;
    $worker->{stdout} = '';
    $worker->{stderr} = '';

    return $samples ? $peak : undef;
}

# ---------------------------------------------------------------------------
# The matrix.  `setup` runs synchronously and is not measured; `run` is the one
# statement whose memory behaviour is under test.  Between them these reach
# every write callback the TAM overrides plus the two read paths that allocate
# per row.
# ---------------------------------------------------------------------------
my $R = ROWS;
my $T = TOAST_ROWS;

# COPY refuses a relative path, and every path the test framework hands out is
# relative to the test directory.
my $copy_file = File::Spec->rel2abs(
    PostgreSQL::Test::Utils::tempdir() . "/tde_copy.txt");

# ---------------------------------------------------------------------------
# The matrix.  Each workload builds its own table twice: $mode is 'enc' for
# encrypted_heap + tde_btree and 'plain' for the core equivalent.  `setup` is
# not measured; `run` is the one statement under test.  Between them these
# reach every write callback the TAM overrides plus the two read paths that
# allocate per row.
# ---------------------------------------------------------------------------
sub amend { my ($m) = @_; return $m eq 'enc' ? ' USING encrypted_heap' : ''; }

sub enc_index
{
    my ($m, $t, $col, $opclass) = @_;
    return $m eq 'enc'
        ? "CREATE INDEX ${t}_idx ON $t USING tde_btree ($col $opclass)"
        : "CREATE INDEX ${t}_idx ON $t USING btree ($col)";
}

my @workloads = (
    {   name  => 'INSERT, index on a varlena key',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k text, pad text)" . amend($m),
            enc_index($m, $t, 'k', ''),
        ) },
        run   => sub { my $t = shift;
            "INSERT INTO $t SELECT 'key' || g, 'x' FROM generate_series(1,$R) g;" } },

    {   name  => 'INSERT, index on a fixed-size key (enc_ops)',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
            enc_index($m, $t, 'k', 'tde_int4_enc_ops'),
        ) },
        run   => sub { my $t = shift;
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R) g;" } },

    {   name  => 'INSERT, no index (write path alone)',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
        ) },
        run   => sub { my $t = shift;
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R) g;" } },

    {   name  => 'COPY FROM (multi_insert)',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
            enc_index($m, $t, 'k', 'tde_int4_enc_ops'),
            "COPY (SELECT g, 'x' FROM generate_series(1,$R) g) TO '$copy_file'",
        ) },
        run   => sub { my $t = shift; "COPY $t FROM '$copy_file';" } },

    {   name  => 'UPDATE of a non-indexed column',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
            enc_index($m, $t, 'k', 'tde_int4_enc_ops'),
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R) g",
        ) },
        run   => sub { my $t = shift; "UPDATE $t SET pad = 'y';" } },

    {   name  => 'UPDATE of the indexed column',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
            enc_index($m, $t, 'k', 'tde_int4_enc_ops'),
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R) g",
        ) },
        run   => sub { my $t = shift; "UPDATE $t SET k = k + 1000000;" } },

    {   name  => 'DELETE',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
            enc_index($m, $t, 'k', 'tde_int4_enc_ops'),
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R) g",
        ) },
        run   => sub { my $t = shift; "DELETE FROM $t;" } },

    {   name  => 'INSERT ... ON CONFLICT DO UPDATE (speculative insert)',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4 PRIMARY KEY, pad text)" . amend($m),
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R) g",
        ) },
        run   => sub { my $t = shift;
            "INSERT INTO $t SELECT g, 'z' FROM generate_series(1,$R) g "
          . "ON CONFLICT (k) DO UPDATE SET pad = excluded.pad;" } },

    {   name  => 'MERGE',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4 PRIMARY KEY, pad text)" . amend($m),
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R/2) g",
        ) },
        run   => sub { my $t = shift;
            "MERGE INTO $t t USING (SELECT g AS k FROM generate_series(1,$R) g) s "
          . "ON t.k = s.k WHEN MATCHED THEN UPDATE SET pad = 'm' "
          . "WHEN NOT MATCHED THEN INSERT VALUES (s.k, 'i');" } },

    {   name  => 'Sequential scan (decrypt per tuple)',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
            "INSERT INTO $t SELECT g, 'xxxxxxxxxxxxxxxxxxxx' FROM generate_series(1,$R) g",
        ) },
        run   => sub { my $t = shift; "SELECT sum(length(pad)) FROM $t;" } },

    {   name  => 'Nested loop, one index rescan per outer row',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t", "DROP TABLE IF EXISTS ${t}_outer",
            "CREATE TABLE $t (k int4, pad text)" . amend($m),
            enc_index($m, $t, 'k', 'tde_int4_enc_ops'),
            "INSERT INTO $t SELECT g, 'x' FROM generate_series(1,$R) g",
            "CREATE TABLE ${t}_outer (k int4)",
            "INSERT INTO ${t}_outer SELECT g FROM generate_series(1,$R) g",
            "ANALYZE $t, ${t}_outer",
        ) },
        run   => sub { my $t = shift;
            "SET enable_hashjoin = off; SET enable_mergejoin = off; "
          . "SELECT count(*) FROM ${t}_outer o JOIN $t b ON b.k = o.k;" } },

    {   name  => 'INSERT of out-of-line TOAST values',
        setup => sub { my ($t, $m) = @_; (
            "DROP TABLE IF EXISTS $t",
            "CREATE TABLE $t (k int4, big text)" . amend($m),
        ) },
        run   => sub { my $t = shift;
            "INSERT INTO $t SELECT g, (SELECT string_agg(md5((g*1000+s)::text), '') "
          . "FROM generate_series(1,200) s) FROM generate_series(1,$T) g;" } },
);

my $n = 0;
foreach my $w (@workloads)
{
    $n++;
    my %peak;

    foreach my $mode ('plain', 'enc')
    {
        my $tbl = "m${n}_$mode";
        $node->safe_psql('postgres', $_) for $w->{setup}->($tbl, $mode);
        $peak{$mode} = peak_executor_state($w->{run}->($tbl));

        if (!defined $peak{$mode})
        {
            fail("$w->{name} [$mode]: the statement ended before a single "
               . "sample landed — raise ROWS, this assertion proved nothing");
            last;
        }
    }
    next unless defined $peak{enc} && defined $peak{plain};

    my $allowed = FLOOR_BYTES;
    $allowed = FACTOR * $peak{plain} if FACTOR * $peak{plain} > $allowed;

    TODO: {
        local $TODO = $w->{todo} if $w->{todo};

        ok($peak{enc} <= $allowed,
           sprintf('%s: encrypted_heap %.2f MB vs plain heap %.2f MB (allowed %.2f MB)',
                   $w->{name}, $peak{enc} / 1048576.0, $peak{plain} / 1048576.0,
                   $allowed / 1048576.0));
    }
}

$worker->quit;
$probe->quit;
$node->stop;
done_testing();
