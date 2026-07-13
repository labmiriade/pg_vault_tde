# tap/13_index_concurrently.t
#
# CREATE INDEX CONCURRENTLY / REINDEX INDEX CONCURRENTLY on an encrypted_heap
# table WHILE another session commits rows (PSQLE-114).
#
# Why TAP and not isolation: CONCURRENTLY runs multiple transactions and cannot
# run inside a transaction block, so the isolation tester cannot drive it. TAP
# lets an independent backend commit rows during the build.
#
# What it guards: the validation phase (pg_vault_tde_index_validate_scan) must
# insert rows committed during the build with correctly AES-256-SIV-encrypted
# keys, and must not double-insert (the in_index[] look-back).  The assertion
# "rows via index scan == rows via seq scan" fails if any row is missing
# (validate skipped it) or duplicated (in_index[] wrong).
#
# Determinism: without injection points (not enabled in this build) we cannot
# force a commit into the build->validate window, so committed inserts (plus
# HOT updates, to grow HOT chains that stress the in_index[] merge) are spread
# over the whole build to make overlap likely.  The test never false-fails when
# the window is missed.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use IPC::Run qw(start);

END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

# --- node ---
my $node = PostgreSQL::Test::Cluster->new('cic_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n" .
    # tde_btree opts out of parallel index build (amcanbuildparallel = false,
    # see pg_vault_tde_iam.c tde_iam_init): a real parallel worker opens its
    # own uncoerced copy of the index relation, and core code (sortsupport.c
    # PrepareSortSupportFromIndexRel) errors out on the non-btree relam.
    # Bias hard towards parallel workers here anyway, so this test would
    # catch a regression if that opt-out is ever accidentally removed.
    "max_parallel_maintenance_workers = 4\n" .
    "min_parallel_table_scan_size = 0\n" .
    "parallel_setup_cost = 0\n" .
    "parallel_tuple_cost = 0\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# --- encrypted table large enough that the build takes a moment ---
$node->safe_psql('postgres',
    "CREATE TABLE cic_conc (id int, secret text) USING encrypted_heap");
$node->safe_psql('postgres',
    "INSERT INTO cic_conc SELECT g, 'base_'||g FROM generate_series(1,300000) g");

# --- background inserter script: AUTOCOMMITTED inserts (one per statement) so
#     rows actually commit *during* the build; a single DO/txn would commit all
#     at once.  Interleave HOT updates on the non-indexed column to build HOT
#     chains, and pg_sleep to spread the work across the whole build. ---
my $tmp = PostgreSQL::Test::Utils::tempdir;
my $script = "$tmp/inserter.sql";
{
    open(my $fh, '>', $script) or die "open $script: $!";
    for my $i (900_001 .. 903_000) {          # 3000 markers
        print $fh "INSERT INTO cic_conc VALUES ($i, 'marker_$i');\n";
        # HOT update on a base row (secret is not indexed => HOT-eligible)
        my $base = ($i % 300_000) + 1;
        print $fh "UPDATE cic_conc SET secret = secret WHERE id = $base;\n"
            if ($i % 5 == 0);
        print $fh "SELECT pg_sleep(0.002);\n";  # ~6s total
    }
    close($fh);
}

sub run_concurrent_load_during
{
    my ($ddl, $label) = @_;

    # start the inserter (non-blocking)
    my @psql = ('psql', '-X', '-v', 'ON_ERROR_STOP=0',
                '-d', $node->connstr('postgres'), '-f', $script);
    my $h = start(\@psql);

    # run the CONCURRENTLY command in the foreground; must not error
    my ($rc, $stdout, $stderr) = $node->psql('postgres', $ddl);
    is($rc, 0, "$label succeeds under concurrent writes")
        or diag("stderr: $stderr");

    $h->finish;   # wait for the inserter to drain
}

# correctness: index scan and seq scan must see the SAME rows.
# idx < seq  => a committed row was skipped by validation;
# idx > seq  => a duplicate index entry (in_index[] look-back wrong).
sub index_matches_seq
{
    my ($label) = @_;
    my $seq = $node->safe_psql('postgres',
        "SET enable_indexscan=off; SET enable_bitmapscan=off; SELECT count(*) FROM cic_conc");
    my $idx = $node->safe_psql('postgres',
        "SET enable_seqscan=off; SELECT count(*) FROM cic_conc WHERE id > 0");
    is($idx, $seq, "$label: index scan == seq scan (no missing, no duplicate)");
}

# --- phase 1: CREATE INDEX CONCURRENTLY under load ---
run_concurrent_load_during(
    'CREATE INDEX CONCURRENTLY cic_conc_idx ON cic_conc USING tde_btree (id)',
    'CREATE INDEX CONCURRENTLY');
is($node->safe_psql('postgres',
       "SELECT indisvalid FROM pg_index WHERE indexrelid='cic_conc_idx'::regclass"),
   't', 'index is valid after CIC');
index_matches_seq('CIC');
is($node->safe_psql('postgres',
       "SET enable_seqscan=off; SELECT secret FROM cic_conc WHERE id = 901500"),
   'marker_901500', 'CIC: concurrently-inserted row is indexed with correct plaintext');

# --- phase 2: REINDEX INDEX CONCURRENTLY under a fresh burst (same code path) ---
# reset the markers so the same script can be replayed with the same ids
$node->safe_psql('postgres', "DELETE FROM cic_conc WHERE id > 900000");
run_concurrent_load_during(
    'REINDEX INDEX CONCURRENTLY cic_conc_idx',
    'REINDEX INDEX CONCURRENTLY');
is($node->safe_psql('postgres',
       "SELECT indisvalid FROM pg_index WHERE indexrelid='cic_conc_idx'::regclass"),
   't', 'index is valid after REINDEX CONCURRENTLY');
is($node->safe_psql('postgres',
       "SELECT count(*) FROM pg_class WHERE relname LIKE 'cic_conc%ccnew%'"),
   '0', 'REINDEX CONCURRENTLY leaves no orphan _ccnew index');
index_matches_seq('REINDEX');

$node->stop;
done_testing();
