# encrypted_rewrite_concurrency.spec
#
# Concurrency around the heaviest TAM path: the relation rewrite
# (VACUUM FULL / CLUSTER -> pg_vault_tde_relation_copy_for_cluster).
#
# What makes these worth a spec rather than a SQL test:
#
#   - relation_copy_for_cluster swaps OldTable->rd_tableam to stock heapam for
#     the whole scan and restores it afterwards.  RelationData is per-backend,
#     so the swap itself cannot be seen by another session -- but that claim
#     has never been exercised with a second session actually reading the same
#     relation while the rewrite runs.  These permutations do exactly that.
#
#   - a rewrite changes relfilenode.  A reader holding an older snapshot must
#     keep seeing consistent, correctly decrypted rows across it.
#
# NOT covered here, deliberately: the DEK becoming unavailable mid-flight.
# run-isolation.sh starts its container with pg_vault_tde.wallet_dev_mode_passphrase
# set, so pg_vault_tde_wallet_lock() is undone by the next DEK request and every
# such permutation would pass without ever reaching an error path.  That needs
# its own harness (a container without the GUC, as make ci-errorpath uses);
# shipping it here would be a test that always passes and checks nothing.
#
# Naming: steps are prefixed by session so the permutation lines read as a
# timeline.

setup
{
    CREATE EXTENSION IF NOT EXISTS pg_vault_tde;
    DO $$
    BEGIN
        EXECUTE format('ALTER DATABASE %I SET client_min_messages = error',
                       current_database());
    END $$;
    DO $$
    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_isolation');
    EXCEPTION WHEN OTHERS THEN NULL;
    END $$;

    CREATE TABLE tde_rw (id int PRIMARY KEY, payload text) USING encrypted_heap;
    -- STORAGE EXTERNAL so the rewrite has real TOAST chunks to migrate
    -- between the old and the new relfilenode, not just inline values.
    ALTER TABLE tde_rw ALTER COLUMN payload SET STORAGE EXTERNAL;
    INSERT INTO tde_rw
    SELECT g, repeat('payload_' || g || '_', 400) FROM generate_series(1, 50) g;
}

teardown
{
    DROP TABLE IF EXISTS tde_rw;
}

# A reader that pins a snapshot before the rewrite and reads across it.
session "reader"
setup { SET client_min_messages = error; }
step "r_begin"   { BEGIN ISOLATION LEVEL REPEATABLE READ; }
step "r_read"    { SELECT count(*) AS rows,
                          count(*) FILTER (WHERE payload =
                              repeat('payload_' || id || '_', 400)) AS intact
                   FROM tde_rw; }
step "r_commit"  { COMMIT; }

# The rewrite itself.  Both entry points reach relation_copy_for_cluster.
session "rewriter"
setup { SET client_min_messages = error; }
step "w_vacfull" { VACUUM FULL tde_rw; }
step "w_cluster" { CLUSTER tde_rw USING tde_rw_pkey; }

# An ordinary writer, to check the table is still usable around a rewrite.
session "writer"
setup { SET client_min_messages = error; }
step "i_begin"   { BEGIN; }
step "i_insert"  { INSERT INTO tde_rw VALUES (1000, repeat('late_', 400)); }
step "i_commit"  { COMMIT; }
step "i_abort"   { ROLLBACK; }

# --- a reader spanning a rewrite ------------------------------------------
# The reader must see 50 intact rows before and after, across a relfilenode
# change performed by another backend.
permutation "r_begin" "r_read" "w_vacfull" "r_read" "r_commit"
permutation "r_begin" "r_read" "w_cluster" "r_read" "r_commit"

# --- a rewrite racing an uncommitted writer -------------------------------
# VACUUM FULL needs AccessExclusiveLock, so it waits for the writer; the row
# must be present and readable once both have finished.
permutation "i_begin" "i_insert" "w_vacfull" "i_commit" "r_read"
permutation "i_begin" "i_insert" "w_vacfull" "i_abort"  "r_read"
