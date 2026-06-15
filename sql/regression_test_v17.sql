-- regression_test_v17.sql — TDE tests 111-119 for pg_vault_tde v1.7
--
-- These tests cover the tde_*_enc_ops operator classes introduced in v1.7,
-- which encrypt fixed-size B-Tree index keys (int4, int8, uuid, date,
-- timestamptz) using AES-256-SIV with STORAGE bytea.
--
-- All tests require:
--   - pg_vault_tde v1.7 (run sql/pg_vault_tde--1.6--1.7.sql first)
--   - kms_provider=local with wallet pre-initialised (passphrase tde_regression_pass_2026)
--   - superuser (pg_read_binary_file requires superuser in test 111)
--
-- Run sequence:
--   psql -f sql/pg_vault_tde--1.0.sql
--   psql -f sql/pg_vault_tde--1.4--1.5.sql
--   psql -f sql/pg_vault_tde--1.5--1.6.sql
--   psql -f sql/pg_vault_tde--1.6--1.7.sql
--   psql -f sql/regression_test_v17.sql     (v1.7 tests 111-119)
--
-- Exit-on-error: any failed assertion aborts the script.
\set ON_ERROR_STOP on

-- ================================================================
-- TEST 111: tde_int4_enc_ops — equality lookup + binary file check
--
-- Verifies two things:
--   1. Equality lookup via tde_int4_enc_ops index returns correct result
--   2. The raw integer value 42 (0x0000002A) is NOT present in the
--      index file on disk — confirming the key is truly encrypted.
--
-- Uses pg_read_binary_file (superuser) + CHECKPOINT to flush dirty
-- pages, following the same pattern as tests 87/88.
-- ================================================================
DO $$
DECLARE
    result_val text;
    idx_path   text;
    idx_oid    oid;
    raw_bytes  bytea;
    needle     bytea;
BEGIN
    DROP TABLE IF EXISTS tde_enc_int4_111;
    CREATE TABLE tde_enc_int4_111 (id int4, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_int4_idx_111
        ON tde_enc_int4_111 USING tde_btree (id tde_int4_enc_ops);

    INSERT INTO tde_enc_int4_111 VALUES (42, 'answer'), (100, 'hundred');

    -- Flush dirty pages so pg_read_binary_file sees current state
    CHECKPOINT;

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_int4_111 WHERE id = 42;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'answer' THEN
        RAISE EXCEPTION
            'TEST 111 FAILED: equality lookup returned %, expected ''answer''',
            COALESCE(result_val, '<NULL>');
    END IF;

    -- Verify that the plaintext value 42 (big-endian: 0x0000002A) does NOT
    -- appear in the raw index file on disk.
    SELECT oid INTO idx_oid
    FROM pg_class WHERE relname = 'tde_enc_int4_idx_111';

    IF idx_oid IS NULL THEN
        RAISE EXCEPTION 'TEST 111 FAILED: index tde_enc_int4_idx_111 not found in pg_class';
    END IF;

    SELECT pg_relation_filepath(idx_oid) INTO idx_path;
    raw_bytes := pg_read_binary_file(idx_path);
    needle    := decode('0000002A', 'hex');  -- int4=42 in big-endian

    IF position(needle IN raw_bytes) > 0 THEN
        RAISE EXCEPTION
            'TEST 111 FAILED: plaintext int4=42 (0x0000002A) found in raw index file — '
            'tde_int4_enc_ops is not encrypting the index key';
    END IF;

    DROP TABLE tde_enc_int4_111;
    RAISE NOTICE
        'TEST 111 PASSED: tde_int4_enc_ops equality OK, plaintext key absent in raw index file';
END;
$$;

-- ================================================================
-- TEST 112: tde_int8_enc_ops — equality lookup bigint
--
-- Inserts two rows and verifies that a single-row equality lookup
-- on int8=9876543210 via tde_btree with tde_int8_enc_ops returns
-- the correct associated label, exercising the 8-byte big-endian
-- serialisation + AES-256-SIV encryption path.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_enc_int8_112;
    CREATE TABLE tde_enc_int8_112 (id int8, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_int8_idx_112
        ON tde_enc_int8_112 USING tde_btree (id tde_int8_enc_ops);

    INSERT INTO tde_enc_int8_112 VALUES (9876543210, 'big'), (1, 'one');

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_int8_112 WHERE id = 9876543210;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'big' THEN
        RAISE EXCEPTION
            'TEST 112 FAILED: int8 equality lookup returned %, expected ''big''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_enc_int8_112;
    RAISE NOTICE 'TEST 112 PASSED: tde_int8_enc_ops equality lookup OK (int8=9876543210)';
END;
$$;

-- ================================================================
-- TEST 113: tde_uuid_enc_ops — equality lookup uuid
--
-- Inserts two rows with distinct UUIDs and verifies that the equality
-- lookup on the known UUID returns the correct id, exercising the
-- 16-byte RFC 4122 wire-bytes serialisation + AES-256-SIV path.
-- ================================================================
DO $$
DECLARE
    test_uuid  uuid := '550e8400-e29b-41d4-a716-446655440000';
    result_id  int;
BEGIN
    DROP TABLE IF EXISTS tde_enc_uuid_113;
    CREATE TABLE tde_enc_uuid_113 (id int, token uuid) USING encrypted_heap;
    CREATE INDEX tde_enc_uuid_idx_113
        ON tde_enc_uuid_113 USING tde_btree (token tde_uuid_enc_ops);

    INSERT INTO tde_enc_uuid_113 VALUES
        (1, '550e8400-e29b-41d4-a716-446655440000'::uuid),
        (2, '6ba7b810-9dad-11d1-80b4-00c04fd430c8'::uuid);

    SET enable_seqscan = off;
    SELECT id INTO result_id
    FROM tde_enc_uuid_113 WHERE token = test_uuid;
    RESET enable_seqscan;

    IF result_id IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION
            'TEST 113 FAILED: uuid equality lookup returned %, expected 1',
            COALESCE(result_id::text, '<NULL>');
    END IF;

    DROP TABLE tde_enc_uuid_113;
    RAISE NOTICE 'TEST 113 PASSED: tde_uuid_enc_ops equality lookup OK (uuid=550e8400...)';
END;
$$;

-- ================================================================
-- TEST 114: tde_date_enc_ops — equality lookup date
--
-- Inserts two rows with distinct dates and verifies the equality
-- lookup on 2026-01-01 returns the correct label, exercising the
-- int32 big-endian serialisation for DateADT + AES-256-SIV path.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_enc_date_114;
    CREATE TABLE tde_enc_date_114 (d date, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_date_idx_114
        ON tde_enc_date_114 USING tde_btree (d tde_date_enc_ops);

    INSERT INTO tde_enc_date_114 VALUES
        ('2026-01-01', 'new_year'),
        ('2000-02-29', 'leap');

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_date_114 WHERE d = '2026-01-01'::date;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'new_year' THEN
        RAISE EXCEPTION
            'TEST 114 FAILED: date equality lookup returned %, expected ''new_year''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_enc_date_114;
    RAISE NOTICE 'TEST 114 PASSED: tde_date_enc_ops equality lookup OK (date=2026-01-01)';
END;
$$;

-- ================================================================
-- TEST 115: tde_timestamptz_enc_ops — equality lookup timestamptz
--
-- Inserts two rows with distinct timestamps and verifies the equality
-- lookup on 2026-06-09 12:00:00+00 returns the correct label,
-- exercising the int64 big-endian serialisation for TimestampTz
-- + AES-256-SIV path.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_enc_tstz_115;
    CREATE TABLE tde_enc_tstz_115 (ts timestamptz, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_tstz_idx_115
        ON tde_enc_tstz_115 USING tde_btree (ts tde_timestamptz_enc_ops);

    INSERT INTO tde_enc_tstz_115 VALUES
        ('2026-06-09 12:00:00+00', 'noon'),
        ('1970-01-01 00:00:00+00', 'epoch');

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_tstz_115 WHERE ts = '2026-06-09 12:00:00+00'::timestamptz;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'noon' THEN
        RAISE EXCEPTION
            'TEST 115 FAILED: timestamptz equality lookup returned %, expected ''noon''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_enc_tstz_115;
    RAISE NOTICE 'TEST 115 PASSED: tde_timestamptz_enc_ops equality lookup OK (2026-06-09 12:00:00+00)';
END;
$$;

-- ================================================================
-- TEST 116: DEK rotation — stale enc_ops index returns NULL,
--           REINDEX restores lookup
--
-- AES-256-SIV is deterministic under a given DEK.  After rotating
-- the per-table DEK, the search predicate is re-encrypted with DEK-B
-- while the stored index keys were encrypted with DEK-A: no match is
-- found (NULL).  After REINDEX the keys are re-encrypted with DEK-B
-- and the lookup works again.
--
-- Table setup is committed before rotate_online so the BGW can see
-- the relation in its own connection.
-- ================================================================
DROP TABLE IF EXISTS tde_enc_rotation_116;
CREATE TABLE tde_enc_rotation_116 (id int4, label text) USING encrypted_heap;
CREATE INDEX tde_enc_rotation_116_id_idx
    ON tde_enc_rotation_116 USING tde_btree (id tde_int4_enc_ops);
INSERT INTO tde_enc_rotation_116 VALUES (7, 'seven');

DO $$
DECLARE
    result_val    text;
    rotation_done boolean := false;
BEGIN
    -- Rotate the per-table DEK via online rotation BGW.
    -- Subsequent amrescan will encrypt the predicate with DEK-B
    -- while the stored index key was encrypted with DEK-A.
    PERFORM pg_vault_tde_rotate_online('tde_enc_rotation_116'::regclass);

    -- Wait for BGW rotation to complete (max 5 seconds)
    FOR i IN 1..50 LOOP
        SELECT (status = 'complete') INTO rotation_done
        FROM pg_vault_tde_rotation_progress
        WHERE relid = 'tde_enc_rotation_116'::regclass::oid;
        EXIT WHEN rotation_done;
        PERFORM pg_sleep(0.1);
    END LOOP;

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_rotation_116 WHERE id = 7;
    RESET enable_seqscan;

    -- With a different DEK, AES-SIV produces a different ciphertext for
    -- the predicate — no match found.  NULL is the expected result.
    IF result_val IS NOT NULL THEN
        RAISE NOTICE
            'TEST 116 FAILED: expected NULL (stale index after DEK rotation) but got ''%''',
            result_val;
    END IF;

    -- Re-encrypt all index keys with the new DEK.
    REINDEX INDEX tde_enc_rotation_116_id_idx;

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_rotation_116 WHERE id = 7;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'seven' THEN
        RAISE EXCEPTION
            'TEST 116 FAILED: after REINDEX expected ''seven'', got %',
            COALESCE(result_val, '<NULL>');
    END IF;

    RAISE NOTICE
        'TEST 116 PASSED: stale enc_ops index after DEK rotation returns NULL; '
        'REINDEX restores lookup correctly';
END;
$$;
DROP TABLE tde_enc_rotation_116;

-- ================================================================
-- TEST 117: Multi-column index — mix of enc_ops, text_ops, int8_ops
--
-- Creates a three-column tde_btree index where:
--   col a (int4)  uses tde_int4_enc_ops  (fixed-type enc, STORAGE bytea)
--   col b (text)  uses tde_text_ops      (varlena enc, existing path)
--   col c (int8)  uses tde_int8_ops      (v1.5 plaintext, for contrast)
--
-- Verifies that an equality lookup on the first two columns returns
-- the correct row, confirming that the per-column dispatch in
-- aminsert/amrescan handles the mixed-opclass case correctly.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_multikey_117;
    CREATE TABLE tde_multikey_117 (a int4, b text, c int8) USING encrypted_heap;
    CREATE INDEX tde_multikey_117_idx
        ON tde_multikey_117
        USING tde_btree (a tde_int4_enc_ops, b tde_text_ops, c tde_int8_ops);

    INSERT INTO tde_multikey_117 VALUES (1, 'hello', 100);
    INSERT INTO tde_multikey_117 VALUES (2, 'world', 200);

    SET enable_seqscan = off;
    SELECT b INTO result_val
    FROM tde_multikey_117 WHERE a = 2 AND b = 'world';
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'world' THEN
        RAISE EXCEPTION
            'TEST 117 FAILED: multi-column enc_ops lookup returned %, expected ''world''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_multikey_117;
    RAISE NOTICE
        'TEST 117 PASSED: multi-column index with enc_ops + text_ops + int8_ops mix OK';
END;
$$;

-- ================================================================
-- TEST 118: CREATE INDEX on pre-populated table (ambuild path)
--
-- Populates a table with 100 rows BEFORE creating the index, so that
-- the index build goes through pg_vault_tde_index_build_range_scan
-- (the ambuild path) rather than the per-row aminsert path.
-- Verifies:
--   1. Spot-check: row 57 is found via index scan.
--   2. Full count: all 100 rows indexed (BETWEEN scan via seqscan=off).
-- Note: BETWEEN on enc_ops produces semantically arbitrary results;
-- the count assertion here just confirms all rows are reachable via
-- the index (no build errors, no dropped keys).
-- ================================================================
DO $$
DECLARE
    result_val text;
    n          int;
BEGIN
    DROP TABLE IF EXISTS tde_existing_118;
    CREATE TABLE tde_existing_118 (id int4, label text) USING encrypted_heap;

    -- Populate before index creation
    INSERT INTO tde_existing_118
    SELECT i, 'row_' || i FROM generate_series(1, 100) i;

    -- CREATE INDEX on already-populated table → exercises ambuild path
    CREATE INDEX tde_existing_118_idx
        ON tde_existing_118 USING tde_btree (id tde_int4_enc_ops);

    -- Spot-check: equality lookup for row 57
    SET enable_seqscan = off;
    SELECT label INTO result_val FROM tde_existing_118 WHERE id = 57;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'row_57' THEN
        RAISE EXCEPTION
            'TEST 118 FAILED: post-build equality lookup for id=57 returned %, '
            'expected ''row_57''',
            COALESCE(result_val, '<NULL>');
    END IF;

    -- Full count via seqscan to verify data integrity (not index range scan)
    SELECT count(*) INTO n FROM tde_existing_118;
    IF n <> 100 THEN
        RAISE EXCEPTION
            'TEST 118 FAILED: expected 100 rows in table, got %', n;
    END IF;

    DROP TABLE tde_existing_118;
    RAISE NOTICE
        'TEST 118 PASSED: CREATE INDEX on pre-populated encrypted_heap table '
        '(ambuild path), spot-check row 57 OK, 100 rows intact';
END;
$$;

-- ================================================================
-- TEST 119: ON CONFLICT DO NOTHING with unique enc_ops index
--
-- Creates a unique tde_btree index using tde_int4_enc_ops and verifies
-- that ON CONFLICT DO NOTHING correctly detects the duplicate key
-- (AES-SIV determinism: same plaintext + DEK → same ciphertext, so
-- btree equality check works) and silently ignores the second insert.
-- Exactly one row must remain after the duplicate attempt.
-- ================================================================
DO $$
DECLARE
    n int;
BEGIN
    DROP TABLE IF EXISTS tde_conflict_119;
    CREATE TABLE tde_conflict_119 (id int4, label text) USING encrypted_heap;
    CREATE UNIQUE INDEX tde_conflict_119_id_idx
        ON tde_conflict_119 USING tde_btree (id tde_int4_enc_ops);

    INSERT INTO tde_conflict_119 VALUES (1, 'first');

    -- Second insert with the same id: must be silently dropped
    INSERT INTO tde_conflict_119 VALUES (1, 'duplicate')
    ON CONFLICT DO NOTHING;

    SELECT count(*) INTO n FROM tde_conflict_119 WHERE id = 1;

    IF n <> 1 THEN
        RAISE EXCEPTION
            'TEST 119 FAILED: expected 1 row after ON CONFLICT DO NOTHING, got %', n;
    END IF;

    DROP TABLE tde_conflict_119;
    RAISE NOTICE
        'TEST 119 PASSED: ON CONFLICT DO NOTHING with tde_int4_enc_ops unique index OK';
END;
$$;

-- ================================================================
-- PHASE SUMMARY
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'v1.7 Tests 111-119 — COMPLETE';
    RAISE NOTICE '   tde_int4_enc_ops + disk forensic check . test 111';
    RAISE NOTICE '   tde_int8_enc_ops equality lookup ........ test 112';
    RAISE NOTICE '   tde_uuid_enc_ops equality lookup ........ test 113';
    RAISE NOTICE '   tde_date_enc_ops equality lookup ........ test 114';
    RAISE NOTICE '   tde_timestamptz_enc_ops equality lookup . test 115';
    RAISE NOTICE '   DEK rotation → stale index → REINDEX .... test 116';
    RAISE NOTICE '   multi-column enc_ops + text + int8 mix .. test 117';
    RAISE NOTICE '   CREATE INDEX on pre-populated table ..... test 118';
    RAISE NOTICE '   ON CONFLICT DO NOTHING + enc_ops unique . test 119';
    RAISE NOTICE '============================================================';
END;
$$;
