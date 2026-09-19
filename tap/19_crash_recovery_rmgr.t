# tap/19_crash_recovery_rmgr.t
#
# WAL replay of encrypted TOAST chunks after an unclean shutdown.
#
# WHY THIS TEST EXISTS
#
# pg_vault_tde registers a custom resource manager (pg_vault_tde_rmgr.c) and
# routes encrypted TOAST chunk inserts through it via tde_toast_wal_insert()
# when pg_vault_tde.toast_custom_rmgr is on.  Its rm_redo callback,
# tde_rmgr_redo(), runs in exactly one situation: WAL replay.  Crash recovery,
# PITR, or a standby applying the stream.
#
# Before this file, no test in the suite ever replayed that WAL.  Grepping
# tap/, sql/ and test/ for TDE_RMGR_ID or tde_rmgr returned nothing, and the
# $node->restart calls elsewhere are *clean* shutdowns, which checkpoint first
# and therefore replay nothing.  So the redo path shipped as code that only
# ever executed on a customer's machine, during recovery, when the cost of
# being wrong is highest.
#
# The GUC is off by default, which makes the gap easier to miss rather than
# less important: it is an opt-in feature whose recovery half was untested.
#
# HOW IT WORKS
#
# stop('immediate') is the load-bearing detail.  It kills the postmaster
# without a shutdown checkpoint, so the records written since the last
# checkpoint MUST be replayed on the next start.  A plain restart() would
# checkpoint on the way down and prove nothing.
#
# STORAGE EXTERNAL plus incompressible payloads is the other one: with the
# default EXTENDED storage PostgreSQL compresses these values and keeps them
# inline, no TOAST chunks are written, and the custom rmgr is never reached.
# The test asserts a non-empty TOAST relation so it cannot pass vacuously.
#
# Both branches of toast.c:354 are covered: custom rmgr on (tde_toast_wal_insert
# -> RM_TDE) and off (heap_insert -> RM_HEAP).  The second is the control: if
# only the first fails, the bug is in our rmgr, not in the encryption.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $ROWS = 200;

# Incompressible payload: md5 hex strings concatenated.  ~12 kB per row, well
# past TOAST_TUPLE_THRESHOLD, and PGLZ cannot shrink it back inline.  Takes the
# seed as an expression so the same generator serves both the bulk load (seeded
# by the generate_series column) and the single post-recovery row (seeded by a
# literal) -- they must produce different bytes per row, or md5 over the whole
# column would not notice a row being replayed as a copy of its neighbour.
sub payload
{
    my ($seed) = @_;
    return "(SELECT string_agg(md5(g2::text || ($seed)::text), '') " .
           " FROM generate_series(1, 380) g2)";
}

sub run_case
{
    my ($label, $custom_rmgr) = @_;

    my $node = PostgreSQL::Test::Cluster->new("rmgr_$label");
    $node->init;
    $node->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'local'\n" .
        "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n" .
        "pg_vault_tde.toast_custom_rmgr = $custom_rmgr\n" .
        # Keep checkpoints out of the way: we need the inserts to still be in
        # WAL, unreplayed, when the postmaster is killed.
        "checkpoint_timeout = 1h\n" .
        "max_wal_size = 4GB\n");
    $node->start;

    $node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
    $node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

    $node->safe_psql('postgres', qq{
        CREATE TABLE rmgr_t (id int primary key, big text) USING encrypted_heap;
        ALTER TABLE rmgr_t ALTER COLUMN big SET STORAGE EXTERNAL;
    });

    # Checkpoint AFTER the DDL but BEFORE the data: the table must exist in a
    # checkpointed state so that what replay has to reconstruct is exactly the
    # TOAST traffic we care about.
    $node->safe_psql('postgres', 'CHECKPOINT');

    $node->safe_psql('postgres',
        "INSERT INTO rmgr_t SELECT g, " . payload('g') .
        " FROM generate_series(1, $ROWS) g");

    # Guard against a vacuous run: if the payload stayed inline there are no
    # TOAST chunks, the custom rmgr was never reached, and replaying proves
    # nothing about it.
    my $toast_bytes = $node->safe_psql('postgres', q{
        SELECT pg_relation_size(reltoastrelid)
        FROM pg_class WHERE oid = 'rmgr_t'::regclass});
    cmp_ok($toast_bytes, '>', 8192,
        "[$label] payload really went out of line ($toast_bytes bytes of TOAST)");

    my $before = $node->safe_psql('postgres',
        "SELECT count(*) || ':' || md5(string_agg(big, '' ORDER BY id)) FROM rmgr_t");

    # --- the crash -------------------------------------------------------
    # immediate = SIGQUIT, no shutdown checkpoint.  Everything above is now
    # only in WAL.
    my $log_offset = -s $node->logfile;
    $node->stop('immediate');
    $node->start;

    is($node->safe_psql('postgres', 'SELECT 1'), '1',
        "[$label] server came back up after an unclean shutdown");

    # Without this the test would still pass if the shutdown had been clean and
    # nothing was replayed -- i.e. if it silently stopped testing recovery.
    ok($node->log_contains(qr/database system was not properly shut down/,
                           $log_offset),
        "[$label] WAL was actually replayed, not skipped");

    my $after = $node->safe_psql('postgres',
        "SELECT count(*) || ':' || md5(string_agg(big, '' ORDER BY id)) FROM rmgr_t");

    is($after, $before,
        "[$label] $ROWS encrypted TOAST rows byte-identical after WAL replay");

    # Replay reconstructed the pages; the relation must still be writable and
    # readable through the normal path, not merely intact on disk.
    $node->safe_psql('postgres',
        "INSERT INTO rmgr_t SELECT " . ($ROWS + 1) . ", " . payload($ROWS + 1));
    my $n = $node->safe_psql('postgres', 'SELECT count(*) FROM rmgr_t');
    is($n, $ROWS + 1, "[$label] table still writable after recovery");

    $node->stop;
}

# custom rmgr ON: the path under test (tde_toast_wal_insert -> tde_rmgr_redo)
run_case('custom', 'on');

# custom rmgr OFF: control.  Same data through heap_insert/RM_HEAP.  If this
# one fails too, the fault is in encryption or TOAST, not in our resource
# manager.
run_case('heapam', 'off');

done_testing();
