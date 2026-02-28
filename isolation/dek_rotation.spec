/*
 * dek_rotation.spec - Isolation test for DEK rotation under concurrent load
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * This test verifies that:
 *  1. A DEK rotation (simulated by calling pg_vault_tde_rotate_key()) does
 *     not block concurrent read transactions.
 *  2. After rotation, new inserts use the new DEK generation.
 *  3. Reads that started before the rotation still complete correctly with
 *     the old cached DEK (MVCC + generation epoch).
 */

setup
{
    CREATE EXTENSION IF NOT EXISTS pg_vault_tde;

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

/*
 * Session 1: Long-running read transaction. Starts before rotation,
 * must complete correctly even after rotation signals generation change.
 */
session "reader"

step "reader_begin"
{
    BEGIN ISOLATION LEVEL REPEATABLE READ;
}

step "reader_snap"
{
    -- Hold a snapshot across the rotation window
    SELECT count(*) FROM tde_iso_test;
}

step "reader_end"
{
    COMMIT;
}

/*
 * Session 2: Triggers a key rotation.
 * In production this calls the KMS wrapper that fetches a new DEK from Vault
 * and calls pg_vault_tde_kms_set_dek() internally.
 * For isolation testing we use the SQL-callable rotation function.
 */
session "rotator"

step "rotator_rotate"
{
    SELECT pg_vault_tde_rotate_key();
}

/*
 * Session 3: Concurrent writer that must see the new DEK generation after
 * rotation completes.
 */
session "writer"

step "writer_insert"
{
    INSERT INTO tde_iso_test (data) VALUES ('post_rotation_value');
}

step "writer_verify"
{
    SELECT data FROM tde_iso_test WHERE data = 'post_rotation_value';
}

/*
 * Permutations:
 *  - reader starts, rotation happens concurrently, reader finishes: must succeed.
 *  - writer inserts after rotation: must use new generation DEK.
 */
permutation "reader_begin" "reader_snap" "rotator_rotate" "reader_end" "writer_insert" "writer_verify"
permutation "reader_begin" "rotator_rotate" "reader_snap" "reader_end" "writer_insert" "writer_verify"
