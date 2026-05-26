setup
{
    CREATE EXTENSION IF NOT EXISTS pg_vault_tde;

    -- Initialise an in-memory test DEK so DML on encrypted_heap works
    -- without requiring a live Vault or a local wallet.
    SELECT pg_vault_tde_set_test_dek();

    CREATE TABLE tde_iso_test (
        id   serial PRIMARY KEY,
        data text
    ) USING encrypted_heap;

    INSERT INTO tde_iso_test (data)
    SELECT 'initial_value_' || g FROM generate_series(1, 100) g;
}

teardown
{
    SELECT pg_vault_tde_rotate_key();
    DROP TABLE IF EXISTS tde_iso_test;
    DROP EXTENSION IF EXISTS pg_vault_tde;
}

session "reader"

step "reader_begin"
{
    BEGIN ISOLATION LEVEL REPEATABLE READ;
}

step "reader_snap"
{
    SELECT count(*) FROM tde_iso_test;
}

step "reader_end"
{
    COMMIT;
}

session "rotator"

step "rotator_rotate"
{
    SELECT pg_vault_tde_rotate_key();
}

session "writer"

step "writer_insert"
{
    INSERT INTO tde_iso_test (data) VALUES ('post_rotation_value');
}

step "writer_verify"
{
    SELECT data FROM tde_iso_test WHERE data = 'post_rotation_value';
}

permutation "reader_begin" "reader_snap" "rotator_rotate" "reader_end" "writer_insert" "writer_verify"
permutation "reader_begin" "rotator_rotate" "reader_snap" "reader_end" "writer_insert" "writer_verify"
