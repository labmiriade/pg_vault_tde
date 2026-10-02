# tap/23_rotation_generation_drift.t — a failed rotation must not strand the
# shmem cache a generation ahead of the catalog
#
# The generation of a relation's DEK lives in two places: the
# pg_vault_tde_catalog row, which rolls back with its transaction, and the
# TdeRelDekMap entry in shared memory, which rolls back with nothing.
#
# zero_rel_dek() used to bump the shmem copy while update_rel_dek() bumped the
# catalog copy inside the rotation's transaction.  Abort that transaction and
# the two disagreed for the lifetime of the cluster: catalog at N, shmem at
# N+1.  Reads still resolved (they landed on prev_dek), which is what made it
# quiet — but every row written afterwards was tagged N+1 while encrypted
# under DEK N, and the NEXT rotation then moved shmem to N+2 and could match
# neither branch for the oldest rows.  Those rows stopped decrypting, and the
# relation could no longer be rotated at all.
#
# The shmem generation is now only read next to a live DEK, is only ever
# written alongside the DEK it describes, and is no longer bumped by
# zero_rel_dek() — so an aborted rotation leaves an entry that simply
# re-reads the catalog.
#
# Fault injection: delete the catalog row after the cache is warm.  The BGW
# gets through zero_rel_dek() (which reads the warm cache) and then fails in
# update_rel_dek(), which needs the row it no longer finds — an abort at
# exactly the step that used to strand the generation.
use strict;
use warnings;
use Test::More tests => 8;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('gen_drift_node');
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

$node->safe_psql('postgres', q{
    CREATE TABLE drift (id int, val text) USING encrypted_heap;
    INSERT INTO drift SELECT g, 'old_' || g FROM generate_series(1, 20) g;
});

# Warm the cache, so zero_rel_dek() succeeds and the abort lands on
# update_rel_dek() — the window this test is about.
is($node->safe_psql('postgres', 'SELECT count(*) FROM drift'), '20',
   'baseline: 20 rows readable, cache warm');

# ---- Rotation #1: made to fail after zero_rel_dek() -----------------------
$node->safe_psql('postgres', q{
    CREATE TABLE saved_row AS
        SELECT * FROM pg_vault_tde_catalog WHERE relid = 'drift'::regclass::oid;
    DELETE FROM pg_vault_tde_catalog WHERE relid = 'drift'::regclass::oid;
});

$node->safe_psql('postgres', q{
    DO $$
    DECLARE st text;
    BEGIN
        PERFORM pg_vault_tde_rotate_online('drift'::regclass);
        FOR i IN 1..100 LOOP
            SELECT status INTO st FROM pg_vault_tde_rotation_progress
            WHERE relid = 'drift'::regclass::oid;
            EXIT WHEN st IN ('complete', 'failed');
            PERFORM pg_sleep(0.1);
        END LOOP;
        IF st IS DISTINCT FROM 'failed' THEN
            RAISE EXCEPTION 'expected the injected rotation to fail, got %',
                COALESCE(st, 'none');
        END IF;
    END $$;
});
ok(1, 'rotation #1 aborted after zero_rel_dek(), as injected');

# Put the catalog back exactly as it was: generation 1, the original DEK.
$node->safe_psql('postgres', q{
    INSERT INTO pg_vault_tde_catalog SELECT * FROM saved_row;
    DROP TABLE saved_row;
});
is($node->safe_psql('postgres',
       "SELECT generation FROM pg_vault_tde_catalog "
     . "WHERE relid = 'drift'::regclass::oid"), '1',
   'catalog is back at generation 1 after the abort');

# The rows written before the failed rotation must still read.
is($node->safe_psql('postgres', 'SELECT count(*) FROM drift'), '20',
   'pre-abort rows still readable');

# ---- The poison step: write while the caches could be out of step --------
# In the broken version these rows were tagged N+1 from the stale shmem
# generation while encrypted under DEK N.
$node->safe_psql('postgres',
    "INSERT INTO drift SELECT g, 'mid_' || g FROM generate_series(21, 30) g");
is($node->safe_psql('postgres', 'SELECT count(*) FROM drift'), '30',
   'rows written after the abort are readable');

# ---- Rotation #2 must succeed and leave everything readable --------------
# Clear rotation #1's terminal row first: the poll below matches on a terminal
# status, and the stale 'failed' would satisfy it before the new BGW has even
# written 'running'.
$node->safe_psql('postgres',
    "DELETE FROM pg_vault_tde_rotation_progress "
  . "WHERE relid = 'drift'::regclass::oid");

my ($rc, $out, $err) = $node->psql('postgres', q{
    DO $$
    DECLARE st text;
    BEGIN
        PERFORM pg_vault_tde_rotate_online('drift'::regclass);
        FOR i IN 1..100 LOOP
            SELECT status INTO st FROM pg_vault_tde_rotation_progress
            WHERE relid = 'drift'::regclass::oid;
            EXIT WHEN st IN ('complete', 'failed');
            PERFORM pg_sleep(0.1);
        END LOOP;
        IF st IS DISTINCT FROM 'complete' THEN
            RAISE EXCEPTION 'rotation #2 ended with status %',
                COALESCE(st, 'none');
        END IF;
    END $$;
});
is($rc, 0, 'rotation #2 succeeds after the aborted one')
    or diag "psql stderr: $err";

is($node->safe_psql('postgres', 'SELECT count(*) FROM drift'), '30',
   'every row survived the aborted rotation plus a real one');
is($node->safe_psql('postgres',
       "SELECT val FROM drift WHERE id = 1"), 'old_1',
   'the oldest row — the first to break — still decrypts');

$node->stop;
