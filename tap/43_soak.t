# tap/43_soak.t — a long randomized run: writes, rotations, rewrites and
# immediate stops, with a plain heap twin as the oracle (PSQLE-207)
#
# Every bug of the PSQLE-184…206 series needed several conditions at once:
# writes, out-of-line values, dropped columns, rotations, rewrites, restarts.
# This test puts them together at random for as long as it is asked to.
#
# Skipped unless PG_VAULT_TDE_SOAK=1 — make ci-soak sets it, and the Bitbucket
# custom pipeline "soak" runs it.  Parameters (environment):
#
#   SOAK_MINUTES  how long to run (default 5)
#   SOAK_ROUNDS   stop after this many rounds, whichever comes first
#   SOAK_SEED     the random seed (default: the time); printed at the start,
#                 so that a failure can be replayed exactly
#
# One round: 100 transactions, each applying the same random statement to the
# encrypted table and to its heap twin — INSERT ... ON CONFLICT DO UPDATE, an
# UPDATE that keeps, replaces, inlines or nulls an out-of-line value, a
# DELETE — then one random maintenance step: nothing, VACUUM, VACUUM FULL,
# CLUSTER, REINDEX, rotate_online() (the twin gets the UPDATE of every row a
# rotation performs), rotate_kek(), or an immediate stop and restart.  After
# every round: contents, whole rows, the out-of-line values each TOAST
# relation holds, verify_integrity(), amcheck heapallindexed on every btree,
# and index lookups against a sequential scan.  The first failure stops the
# run and prints its seed and round.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Time::HiRes qw(time);

plan skip_all => 'soak test: set PG_VAULT_TDE_SOAK=1 (make ci-soak)'
  unless $ENV{PG_VAULT_TDE_SOAK};

END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

# || rather than //: a variable a Bitbucket prompt leaves blank arrives empty.
my $seed    = $ENV{SOAK_SEED}    || int(time);
my $minutes = $ENV{SOAK_MINUTES} || 5;
my $rounds  = $ENV{SOAK_ROUNDS}  || 1_000_000;
srand($seed);
diag "soak: seed=$seed minutes=$minutes max_rounds=$rounds";

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('soak');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.allow_plaintext_index = on\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde; CREATE EXTENSION amcheck;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

$node->safe_psql('postgres', q{
    CREATE FUNCTION toast_values(regclass) RETURNS bigint LANGUAGE plpgsql AS $$
    DECLARE n bigint;
    BEGIN
        EXECUTE format('SELECT count(DISTINCT chunk_id) FROM %s',
                       (SELECT reltoastrelid::regclass FROM pg_class WHERE oid = $1))
        INTO n;
        RETURN n;
    END $$;
});
for my $am (qw(encrypted_heap heap))
{
    my $t = $am eq 'heap' ? 'twin' : 'enc';
    $node->safe_psql('postgres', qq{
        SET client_min_messages = error;
        CREATE TABLE $t (id int PRIMARY KEY, k int, s text, big text, cmp text, gone text)
            USING $am;
        ALTER TABLE $t ALTER COLUMN big SET STORAGE EXTERNAL;
        ALTER TABLE $t ALTER COLUMN gone SET STORAGE EXTERNAL;
        INSERT INTO $t
        SELECT g, g % 97, 's' || g,
               CASE WHEN g % 3 = 0 THEN repeat(md5(g::text), 400) END,
               CASE WHEN g % 5 = 0 THEN (SELECT string_agg(md5((g * 1000 + i)::text) || repeat('-', 32), '')
                                         FROM generate_series(1, 200) i) END,
               CASE WHEN g % 7 = 0 THEN repeat(md5((-g)::text), 400) END
        FROM generate_series(1, 500) g;
        ALTER TABLE $t DROP COLUMN gone;
        CREATE INDEX ${t}_k ON $t (k);
        CREATE INDEX ${t}_k_even ON $t (k) WHERE k % 2 = 0;
    });
}
$node->safe_psql('postgres',
    'SET client_min_messages = error; CREATE INDEX enc_s ON enc USING tde_btree (s)');

my $next_id = 501;

# One random statement, as a template on %t, with literals drawn from the RNG
# so that both tables get the same values.
sub random_statement
{
    my $id  = 1 + int(rand($next_id));
    my $val = int(rand(1_000_000));
    my $op  = int(rand(7));
    if ($op == 0)
    {
        my $new = $next_id++;
        return "INSERT INTO %t VALUES ($new, $val % 97, 's$new', "
             . "repeat(md5('$val'), 400), NULL) "
             . "ON CONFLICT (id) DO UPDATE SET big = excluded.big";
    }
    return "INSERT INTO %t VALUES ($id, $val % 97, 's$id', NULL, 'short_$val') "
         . "ON CONFLICT (id) DO UPDATE SET cmp = excluded.cmp" if $op == 1;
    return "UPDATE %t SET k = k + 1 WHERE id = $id" if $op == 2;
    return "UPDATE %t SET big = repeat(md5('$val'), 400) WHERE id = $id" if $op == 3;
    return "UPDATE %t SET cmp = repeat('x', 6000) WHERE id = $id" if $op == 4;
    return "UPDATE %t SET big = NULL, cmp = 'n$val' WHERE id = $id" if $op == 5;
    return "DELETE FROM %t WHERE id = $id";
}

sub both
{
    my ($tmpl) = @_;
    (my $e = $tmpl) =~ s/%t/enc/g;
    (my $h = $tmpl) =~ s/%t/twin/g;
    return "$e; $h;";
}

sub rotate
{
    $node->safe_psql('postgres',
        "DELETE FROM pg_vault_tde_rotation_progress WHERE relid = 'enc'::regclass::oid");
    $node->safe_psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('enc')");
    $node->poll_query_until('postgres', q{
        SELECT status IN ('complete', 'failed') FROM pg_vault_tde_rotation_progress
        WHERE relid = 'enc'::regclass::oid}) or die 'rotation never finished';
    my $status = $node->safe_psql('postgres',
        "SELECT status FROM pg_vault_tde_rotation_progress WHERE relid = 'enc'::regclass::oid");
    die "rotation ended '$status'" unless $status eq 'complete';
    $node->safe_psql('postgres', 'UPDATE twin SET id = id');
}

my @maintenance = (
    [ 'nothing',       sub { } ],
    [ 'VACUUM',        sub { $node->safe_psql('postgres', 'VACUUM enc; VACUUM twin') } ],
    [ 'VACUUM FULL',   sub { $node->safe_psql('postgres', 'VACUUM FULL enc; VACUUM FULL twin') } ],
    [ 'CLUSTER',       sub { $node->safe_psql('postgres', 'CLUSTER enc USING enc_pkey; CLUSTER twin USING twin_pkey') } ],
    [ 'REINDEX',       sub { $node->safe_psql('postgres', 'REINDEX TABLE enc; REINDEX TABLE twin') } ],
    [ 'rotate_online', \&rotate ],
    [ 'rotate_kek',    sub { $node->safe_psql('postgres', 'SELECT pg_vault_tde_rotate_kek()') } ],
    [ 'immediate stop', sub {
        $node->stop('immediate');
        $node->start;
        $node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
    } ],
);

# Every check of a round, as [name, got, expected].
sub checks
{
    my @c;
    my $q = sub { $node->safe_psql('postgres', $_[0]) };
    push @c, ['contents equal the twin', $q->(q{
        SELECT count(*) FROM (
            (SELECT * FROM enc EXCEPT ALL SELECT * FROM twin)
            UNION ALL
            (SELECT * FROM twin EXCEPT ALL SELECT * FROM enc)) d}), '0'];
    push @c, ['whole rows read as on the twin',
              $q->('SELECT coalesce(sum(length(t::text)), 0) FROM enc t'),
              $q->('SELECT coalesce(sum(length(t::text)), 0) FROM twin t')];
    push @c, ['TOAST values as on the twin',
              $q->("SELECT toast_values('enc')"), $q->("SELECT toast_values('twin')")];
    push @c, ['verify_integrity finds nothing',
              $q->("SELECT failed_tuples FROM pg_vault_tde_verify_integrity('enc')"), '0'];
    push @c, ['amcheck heapallindexed on every btree', $q->(q{
        SELECT count(bt_index_check(i, true))
        FROM unnest(ARRAY['enc_pkey', 'enc_k', 'enc_k_even']::regclass[]) i}), '3'];
    my $k = int(rand(97));
    my $idx = 'SET enable_seqscan = off; SET enable_bitmapscan = off; ';
    my $seq = 'SET enable_indexscan = off; SET enable_indexonlyscan = off; SET enable_bitmapscan = off; ';
    push @c, ['index lookups answer as a sequential scan',
              $q->($idx . "SELECT count(*) || ',' || (SELECT count(*) FROM enc WHERE k = $k AND k % 2 = 0) "
                  . "|| ',' || (SELECT count(*) FROM enc WHERE s = 's$k') FROM enc WHERE k = $k"),
              $q->($seq . "SELECT count(*) || ',' || (SELECT count(*) FROM enc WHERE k = $k AND k % 2 = 0) "
                  . "|| ',' || (SELECT count(*) FROM enc WHERE s = 's$k') FROM enc WHERE k = $k")];
    return @c;
}

my $deadline = time + 60 * $minutes;
my $round = 0;
while ($round < $rounds && time < $deadline)
{
    $round++;
    my $sql = '';
    $sql .= 'BEGIN; ' . both(random_statement()) . " COMMIT;\n" for 1 .. 100;
    my ($rc, $out, $err) = $node->psql('postgres', $sql);
    if ($rc)
    {
        fail("round $round: the workload runs");
        diag "seed=$seed round=$round: $err";
        BAIL_OUT("soak failed at round $round (seed $seed)");
    }

    my ($name, $action) = @{ $maintenance[int(rand(@maintenance))] };
    eval { $action->(); 1 } or do {
        fail("round $round: $name");
        diag "seed=$seed round=$round: $@";
        BAIL_OUT("soak failed at round $round (seed $seed)");
    };

    for my $c (checks())
    {
        my ($what, $got, $expected) = @$c;
        next if $got eq $expected;
        is($got, $expected, "round $round, after $name: $what");
        diag "seed=$seed round=$round; server log: " . $node->logfile;
        BAIL_OUT("soak failed at round $round (seed $seed)");
    }
    pass("round $round, after $name: every check holds");
}

diag "soak: $round rounds, seed $seed";
ok($round > 0, 'at least one round ran');
$node->stop;
done_testing();
