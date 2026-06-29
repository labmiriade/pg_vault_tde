setup
{
    CREATE EXTENSION IF NOT EXISTS pg_vault_tde;
    ALTER DATABASE tde_isolation SET client_min_messages = error;
    DO $$
    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_isolation');
    EXCEPTION WHEN OTHERS THEN NULL;
    END $$;
}

teardown
{
    DROP TABLE IF EXISTS tde_iso_test;
    DROP EXTENSION IF EXISTS pg_vault_tde;
}

session "setupper"

step "su_setup"
{
    CREATE TABLE tde_iso_test (
        id serial PRIMARY KEY,
        data text
    ) USING encrypted_heap;

    INSERT INTO tde_iso_test (data)
    SELECT 'initial_value_' || g FROM generate_series(1, 100) g;
}

session "reader"
step "rx_begin"  { BEGIN ISOLATION LEVEL REPEATABLE READ; }
step "rx_read1"  { SELECT data FROM tde_iso_test WHERE id = 1; }
step "rx_read2"  { SELECT id FROM tde_iso_test WHERE data = 'Isolation_test'; }
step "rx_commit" { COMMIT; }

session "rotator"
step "rot_rotate" { SELECT pg_vault_tde_rotate_online('tde_iso_test'); }

session "writer"

step "wx_begin"  { BEGIN; --Read committed}
step "wx_write"  { INSERT INTO tde_iso_test (data) VALUES ('Isolation_test'); }
step "wx_update" { UPDATE tde_iso_test SET data = 'Updated' WHERE id = 50; }
step "wx_commit" { COMMIT; }
step "wx_abort"  { ROLLBACK; }

session "vacuumer"
step "vacuum"    { VACUUM tde_iso_test; }

permutation "su_setup" "rx_begin" "rx_read1" "rot_rotate" "wx_begin" "wx_write" "wx_commit" "rx_read2" "rx_commit"
permutation "su_setup" "wx_begin" "wx_write" "rot_rotate" "wx_commit" "rx_read2"
permutation "su_setup" "wx_begin" "wx_write" "rot_rotate" "rx_begin" "rx_read2" "wx_commit" "rx_read2" "rx_commit"
permutation "su_setup" "wx_begin" "wx_update" "rot_rotate" "wx_abort"
permutation "su_setup" "vacuum" "rot_rotate"
permutation "su_setup" "rot_rotate" "vacuum"
