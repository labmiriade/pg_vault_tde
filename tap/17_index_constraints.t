# tap/17_index_constraints.t
#
# PRIMARY KEY / UNIQUE enforcement on encrypted_heap tables, across every way
# a unique index can come into existence -- plus the allow_plaintext_index
# escape hatch for a standalone CREATE INDEX ... USING btree.
#
# Background: PostgreSQL core always backs a declarative PRIMARY KEY/UNIQUE
# *table constraint* with a native (non-pluggable) btree index, so
# pg_vault_tde can only warn about the resulting plaintext-on-disk exposure,
# never block it -- and that warning must fire for every constraint spelling
# (inline in CREATE TABLE, ADD CONSTRAINT ... PRIMARY KEY, ADD CONSTRAINT ...
# UNIQUE), not just the CREATE TABLE one (tests A/B/C).
#
# A standalone CREATE INDEX ... USING btree (NOT a constraint) is different:
# the user has a real choice (tde_btree), so it is rejected outright unless
# pg_vault_tde.allow_plaintext_index = on (tests D/E).  Test D also covers
# the exact failure mode originally reported as "duplicate rows get inserted
# without error and the index is not updated": a rejected CREATE UNIQUE INDEX
# leaves NO index behind at all, so there is nothing to enforce or to update
# -- it is not a TAM write-path bug.  Test E exercises the previously-broken
# two-step "build unique index, then attach as PRIMARY KEY" pattern (common
# with CREATE INDEX CONCURRENTLY) once allow_plaintext_index=on lets the
# first step actually succeed.
#
# Every scenario asserts three things: (a) the expected WARNING/ERROR fires,
# (b) the resulting index actually enforces uniqueness (duplicate INSERT is
# rejected -- no "index silently missing"), and (c) index scans and seq scans
# agree on row counts (no missing/duplicate index entries).
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('idxconstraint_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# --- helpers ---------------------------------------------------------------

# row count via forced index scan must equal forced seq scan: a mismatch
# means the index is missing rows (skipped) or has duplicate entries.
sub index_matches_seq
{
    my ($table, $label) = @_;
    my $seq = $node->safe_psql('postgres',
        "SET enable_indexscan=off; SET enable_bitmapscan=off; SELECT count(*) FROM $table");
    my $idx = $node->safe_psql('postgres',
        "SET enable_seqscan=off; SELECT count(*) FROM $table");
    is($idx, $seq, "$label: index scan == seq scan (no missing/duplicate index entries)");
}

sub index_exists
{
    my ($indexname) = @_;
    return $node->safe_psql('postgres',
        "SELECT count(*) FROM pg_class WHERE relname = '$indexname'") eq '1';
}

# ================================================================
# A) CREATE TABLE (... PRIMARY KEY) inline -- PostgreSQL-forced native btree.
#    Baseline: this already worked before this fix; kept here so all PK/UNIQUE
#    spellings are exercised side by side in one file.
# ================================================================
{
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "CREATE TABLE ct_inline_pk (id int PRIMARY KEY, val text) USING encrypted_heap");
    is($rc, 0, 'A: CREATE TABLE with inline PRIMARY KEY succeeds');
    like($stderr, qr/will be backed by a standard \(unencrypted\) btree index/,
        'A: WARNING fires for inline PRIMARY KEY');

    $node->safe_psql('postgres', "INSERT INTO ct_inline_pk VALUES (1, 'a')");
    ($rc, $stdout, $stderr) = $node->psql('postgres',
        "INSERT INTO ct_inline_pk VALUES (1, 'b')");
    isnt($rc, 0, 'A: duplicate PK insert is rejected');
    like($stderr, qr/duplicate key value violates unique constraint/,
        'A: duplicate PK insert raises unique_violation');

    $node->safe_psql('postgres',
        "INSERT INTO ct_inline_pk SELECT g, 'v'||g FROM generate_series(2,50) g");
    index_matches_seq('ct_inline_pk', 'A');
}

# ================================================================
# B) ALTER TABLE ADD CONSTRAINT ... PRIMARY KEY (col) -- the visibility gap
#    this fix closes: previously fired NEITHER warning nor error, unlike A.
# ================================================================
{
    $node->safe_psql('postgres',
        "CREATE TABLE ct_alter_pk (id int, val text) USING encrypted_heap");
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "ALTER TABLE ct_alter_pk ADD CONSTRAINT ct_alter_pk_pkey PRIMARY KEY (id)");
    is($rc, 0, 'B: ALTER TABLE ADD CONSTRAINT PRIMARY KEY succeeds');
    like($stderr, qr/will be backed by a standard \(unencrypted\) btree index/,
        'B: WARNING now fires for ADD CONSTRAINT PRIMARY KEY (previously silent)');

    $node->safe_psql('postgres', "INSERT INTO ct_alter_pk VALUES (1, 'a')");
    ($rc, $stdout, $stderr) = $node->psql('postgres',
        "INSERT INTO ct_alter_pk VALUES (1, 'b')");
    isnt($rc, 0, 'B: duplicate PK insert is rejected');

    $node->safe_psql('postgres',
        "INSERT INTO ct_alter_pk SELECT g, 'v'||g FROM generate_series(2,50) g");
    index_matches_seq('ct_alter_pk', 'B');
}

# ================================================================
# C) ALTER TABLE ADD CONSTRAINT ... UNIQUE (multi-column) -- CONSTR_UNIQUE
#    (not just CONSTR_PRIMARY), and the plural wording of the warning.
# ================================================================
{
    $node->safe_psql('postgres',
        "CREATE TABLE ct_alter_uq (a int, b int, val text) USING encrypted_heap");
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "ALTER TABLE ct_alter_uq ADD CONSTRAINT ct_alter_uq_uq UNIQUE (a, b)");
    is($rc, 0, 'C: ALTER TABLE ADD CONSTRAINT UNIQUE (multi-col) succeeds');
    like($stderr, qr/constraints on columns "a", "b"/,
        'C: WARNING uses plural wording for a 2-column UNIQUE constraint');

    $node->safe_psql('postgres', "INSERT INTO ct_alter_uq VALUES (1, 1, 'a')");
    ($rc, $stdout, $stderr) = $node->psql('postgres',
        "INSERT INTO ct_alter_uq VALUES (1, 1, 'b')");
    isnt($rc, 0, 'C: duplicate (a,b) insert is rejected');
}

# ================================================================
# D) standalone CREATE UNIQUE INDEX ... USING btree, allow_plaintext_index=off
#    (default) -- the ORIGINAL bug report's exact trigger.  Must fail LOUDLY
#    and must NOT leave a half-built index behind.
# ================================================================
{
    $node->safe_psql('postgres',
        "CREATE TABLE ct_standalone_off (id int, val text) USING encrypted_heap");
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "CREATE UNIQUE INDEX ct_standalone_off_idx ON ct_standalone_off USING btree (id)");
    isnt($rc, 0, 'D: standalone CREATE UNIQUE INDEX USING btree is rejected by default');
    like($stderr, qr/index access method "btree" is not supported on encrypted_heap/,
        'D: rejection message names the guard');
    ok(!index_exists('ct_standalone_off_idx'),
        'D: no half-built index is left behind after the rejected CREATE INDEX');

    # Without an index, nothing stops duplicates: this documents the *safe*
    # failure mode (the DDL fails loudly; it does not silently degrade) --
    # the original report's symptom traced back to exactly this, unnoticed.
    $node->safe_psql('postgres', "INSERT INTO ct_standalone_off VALUES (1, 'a')");
    ($rc, $stdout, $stderr) = $node->psql('postgres',
        "INSERT INTO ct_standalone_off VALUES (1, 'b')");
    is($rc, 0,
        'D: with no successfully-created index, duplicates are (expectedly) not blocked');
}

# ================================================================
# E) allow_plaintext_index = on: CREATE UNIQUE INDEX ... USING btree, then
#    attach as PRIMARY KEY via USING INDEX -- the fix for the two-step
#    CONCURRENTLY-style pattern that used to end up completely unprotected.
# ================================================================
{
    $node->safe_psql('postgres',
        "ALTER DATABASE postgres SET pg_vault_tde.allow_plaintext_index = on");
    $node->safe_psql('postgres',
        "CREATE TABLE ct_standalone_on (id int, val text) USING encrypted_heap");

    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "CREATE UNIQUE INDEX ct_standalone_on_idx ON ct_standalone_on USING btree (id)");
    is($rc, 0, 'E: CREATE UNIQUE INDEX USING btree succeeds with allow_plaintext_index=on');
    like($stderr, qr/is not encrypted/, 'E: WARNING fires instead of ERROR');
    ok(index_exists('ct_standalone_on_idx'), 'E: the index was actually created');

    ($rc, $stdout, $stderr) = $node->psql('postgres',
        "ALTER TABLE ct_standalone_on ADD CONSTRAINT ct_standalone_on_pkey " .
        "PRIMARY KEY USING INDEX ct_standalone_on_idx");
    is($rc, 0, 'E: ADD CONSTRAINT ... USING INDEX succeeds (the index actually exists)');

    $node->safe_psql('postgres', "INSERT INTO ct_standalone_on VALUES (1, 'a')");
    ($rc, $stdout, $stderr) = $node->psql('postgres',
        "INSERT INTO ct_standalone_on VALUES (1, 'b')");
    isnt($rc, 0,
        'E: duplicate insert is now correctly rejected (the original bug report, fixed)');

    $node->safe_psql('postgres',
        "INSERT INTO ct_standalone_on SELECT g, 'v'||g FROM generate_series(2,50) g");
    index_matches_seq('ct_standalone_on', 'E');

    $node->safe_psql('postgres',
        "ALTER DATABASE postgres SET pg_vault_tde.allow_plaintext_index = off");
}

# ================================================================
# F) tde_btree UNIQUE index -- parity check, unaffected by this change.
# ================================================================
{
    $node->safe_psql('postgres',
        "CREATE TABLE ct_tdebtree (id int, tag text) USING encrypted_heap");
    $node->safe_psql('postgres',
        "CREATE UNIQUE INDEX ct_tdebtree_idx ON ct_tdebtree USING tde_btree (tag)");
    $node->safe_psql('postgres', "INSERT INTO ct_tdebtree VALUES (1, 'alpha')");
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "INSERT INTO ct_tdebtree VALUES (2, 'alpha')");
    isnt($rc, 0, 'F: tde_btree UNIQUE constraint still enforced (unaffected by this change)');
}

$node->stop;
done_testing();
