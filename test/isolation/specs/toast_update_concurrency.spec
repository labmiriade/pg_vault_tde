# toast_update_concurrency.spec
#
# An UPDATE that replaces an out-of-line value, racing another transaction on
# the same row.
#
# The TAM must TOAST the new row before encrypting it, so it runs its own
# toaster before heap_update() — and that toaster also deleted the old
# value's chunks.  Core deletes them inside heap_update(), once the row is
# known to be updatable.  Here heap_update() can still find the row updated
# or deleted by a concurrent transaction, and READ COMMITTED then either
# retries on the newer version or skips the row: the chunks were already
# gone, though the newer version — or the row the UPDATE skipped — still
# pointed at them (PSQLE-193).  The loss shows once VACUUM removes the
# chunks; until then TOAST reads still see them.
#
# Every permutation ends with VACUUM and a check that reads every value and
# counts the out-of-line values the TOAST relation still holds: two per live
# row, one for each external column — fewer is a loss, more is a leak.

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

    CREATE TABLE tde_tu (id int PRIMARY KEY, flag int, big text, keep text)
        USING encrypted_heap;
    ALTER TABLE tde_tu ALTER COLUMN big SET STORAGE EXTERNAL;
    ALTER TABLE tde_tu ALTER COLUMN keep SET STORAGE EXTERNAL;
    INSERT INTO tde_tu VALUES (1, 0, repeat('big_v1_', 1000), repeat('keep_', 1000));

    -- Out-of-line values the TOAST relation holds, live rows or not.
    CREATE FUNCTION tde_tu_values() RETURNS bigint LANGUAGE plpgsql AS $$
    DECLARE n bigint;
    BEGIN
        EXECUTE format('SELECT count(DISTINCT chunk_id) FROM %s',
                       (SELECT reltoastrelid::regclass FROM pg_class
                        WHERE oid = 'tde_tu'::regclass))
        INTO n;
        RETURN n;
    END $$;
}

teardown
{
    DROP TABLE IF EXISTS tde_tu;
    DROP FUNCTION IF EXISTS tde_tu_values();
}

session "u1"
setup { SET client_min_messages = error; }
step "u1_begin"  { BEGIN; }
step "u1_flag"   { UPDATE tde_tu SET flag = 1 WHERE id = 1; }
step "u1_big"    { UPDATE tde_tu SET big = repeat('big_u1_', 1000) WHERE id = 1; }
step "u1_delete" { DELETE FROM tde_tu WHERE id = 1; }
step "u1_commit" { COMMIT; }
step "u1_abort"  { ROLLBACK; }

session "u2"
setup { SET client_min_messages = error; }
step "u2_big"     { UPDATE tde_tu SET big = repeat('big_u2_', 1000) WHERE id = 1; }
step "u2_big_if0" { UPDATE tde_tu SET big = repeat('big_u2_', 1000) WHERE id = 1 AND flag = 0; }

session "check"
setup { SET client_min_messages = error; }
step "c_vacuum" { VACUUM tde_tu; }
step "c_check"  { SELECT id, flag, left(big, 7) AS big, length(big) AS big_len,
                         keep = repeat('keep_', 1000) AS keep_ok,
                         tde_tu_values() AS toast_values
                  FROM tde_tu ORDER BY id; }
step "c_values" { SELECT tde_tu_values() AS toast_values; }

# No concurrency: the control.
permutation "u2_big" "c_vacuum" "c_check"

# The row changes under the waiting UPDATE, which re-checks its WHERE on the
# newer version and skips it: big must still read as v1.
permutation "u1_begin" "u1_flag" "u2_big_if0" "u1_commit" "c_vacuum" "c_check"

# The waiting UPDATE goes ahead on the newer version: keep, which neither
# transaction changed, must read, and nothing may be left behind.
permutation "u1_begin" "u1_flag" "u2_big" "u1_commit" "c_vacuum" "c_check"

# Both replace the same out-of-line value; the second one wins.
permutation "u1_begin" "u1_big" "u2_big" "u1_commit" "c_vacuum" "c_check"
permutation "u1_begin" "u1_big" "u2_big" "u1_abort" "c_vacuum" "c_check"

# The row is deleted under the waiting UPDATE, which then updates nothing:
# no row, and no value left in the TOAST relation.
permutation "u1_begin" "u1_delete" "u2_big" "u1_commit" "c_vacuum" "c_check" "c_values"
