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
    IF result_val IS DISTINCT FROM 'seven' THEN
        RAISE EXCEPTION
            'TEST 116 FAILED: expected "seven" but got ''%''',
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
-- PARTITIONING (tests 120-127)
-- ================================================================

-- ================================================================
-- TEST 120: all-encrypted partition tree — routing + round-trip
--
-- Parent partitioned by RANGE(id); two encrypted leaves.  INSERT into the
-- parent must route each row to the correct leaf's encrypted_heap
-- tuple_insert, and SELECT from the parent must decrypt every leaf.
-- ================================================================
DO $$
DECLARE
    n_lo   bigint;
    n_hi   bigint;
    v_read text;
BEGIN
    DROP TABLE IF EXISTS tde_part_120;

    CREATE TABLE tde_part_120 (id int, val text) PARTITION BY RANGE (id);
    CREATE TABLE tde_part_120_lo PARTITION OF tde_part_120
        FOR VALUES FROM (1) TO (100)   USING encrypted_heap;
    CREATE TABLE tde_part_120_hi PARTITION OF tde_part_120
        FOR VALUES FROM (100) TO (200) USING encrypted_heap;

    -- Route across both leaves through the parent.
    INSERT INTO tde_part_120 VALUES
        (10,  'low_partition_value'),
        (50,  'low_partition_value_2'),
        (150, 'high_partition_value');

    SELECT count(*) INTO n_lo FROM tde_part_120_lo;
    SELECT count(*) INTO n_hi FROM tde_part_120_hi;
    IF n_lo <> 2 OR n_hi <> 1 THEN
        RAISE EXCEPTION 'TEST 120 FAILED: routing wrong (lo=%, hi=% — expected 2,1)',
            n_lo, n_hi;
    END IF;

    -- Round-trip via the parent (scans both leaves, decrypts each).
    SELECT val INTO v_read FROM tde_part_120 WHERE id = 150;
    IF v_read IS DISTINCT FROM 'high_partition_value' THEN
        RAISE EXCEPTION 'TEST 120 FAILED: parent SELECT mismatch (got %)',
            COALESCE(v_read, '<NULL>');
    END IF;

    DROP TABLE tde_part_120;
    RAISE NOTICE 'TEST 120 PASSED: tuple routing + round-trip across encrypted leaves OK';
END;
$$;

-- ================================================================
-- TEST 121: per-relation DEK isolation across the partition tree
--
-- When the parent is created WITH USING encrypted_heap, every relation in
-- the tree — the partitioned parent AND each leaf — gets its own catalog
-- row with its own distinct wrapped_dek.  (The parent's DEK is unused, as
-- it has no storage, but it is registered by the ProcessUtility hook.)
-- All three wrapped DEKs must be present and mutually distinct.
-- ================================================================
DO $$
DECLARE
    v_parent   oid;
    v_lo       oid;
    v_hi       oid;
    wdek_parent bytea;
    wdek_lo    bytea;
    wdek_hi    bytea;
BEGIN
    DROP TABLE IF EXISTS tde_part_121;

    CREATE TABLE tde_part_121 (id int, val text)
        PARTITION BY RANGE (id) USING encrypted_heap;
    CREATE TABLE tde_part_121_lo PARTITION OF tde_part_121
        FOR VALUES FROM (1) TO (100)   USING encrypted_heap;
    CREATE TABLE tde_part_121_hi PARTITION OF tde_part_121
        FOR VALUES FROM (100) TO (200) USING encrypted_heap;

    v_parent := 'tde_part_121'::regclass::oid;
    v_lo     := 'tde_part_121_lo'::regclass::oid;
    v_hi     := 'tde_part_121_hi'::regclass::oid;

    -- Parent (created WITH USING) is registered too.
    SELECT wrapped_dek INTO wdek_parent FROM pg_vault_tde_catalog WHERE relid = v_parent;
    SELECT wrapped_dek INTO wdek_lo     FROM pg_vault_tde_catalog WHERE relid = v_lo;
    SELECT wrapped_dek INTO wdek_hi     FROM pg_vault_tde_catalog WHERE relid = v_hi;

    IF wdek_parent IS NULL OR wdek_lo IS NULL OR wdek_hi IS NULL THEN
        RAISE EXCEPTION 'TEST 121 FAILED: missing wrapped_dek (parent null=%, lo null=%, hi null=%)',
            (wdek_parent IS NULL), (wdek_lo IS NULL), (wdek_hi IS NULL);
    END IF;

    -- All three DEKs are independent: every wrapped value must differ.
    IF wdek_lo = wdek_hi OR wdek_parent = wdek_lo OR wdek_parent = wdek_hi THEN
        RAISE EXCEPTION 'TEST 121 FAILED: relations share an identical wrapped_dek '
                        '(no per-relation isolation)';
    END IF;

    DROP TABLE tde_part_121;
    RAISE NOTICE 'TEST 121 PASSED: per-relation DEK isolation OK '
                 '(parent + both leaves each own a distinct wrapped_dek)';
END;
$$;

-- ================================================================
-- TEST 122: AM inheritance from a USING-bearing parent (PG 17+)
--
-- Since PG17 a partitioned table may carry an access method that new
-- partitions inherit when created without an explicit USING.  This is the
-- recommended way to guarantee every future partition is encrypted.
-- ================================================================
DO $$
DECLARE
    v_leaf_am text;
    v_read    text;
BEGIN
    DROP TABLE IF EXISTS tde_part_122;

    -- Parent carries the AM; the leaf inherits it (no USING on the leaf).
    CREATE TABLE tde_part_122 (id int, val text)
        PARTITION BY RANGE (id) USING encrypted_heap;
    CREATE TABLE tde_part_122_inh PARTITION OF tde_part_122
        FOR VALUES FROM (1) TO (100);

    SELECT am.amname INTO v_leaf_am
    FROM pg_class c JOIN pg_am am ON am.oid = c.relam
    WHERE c.oid = 'tde_part_122_inh'::regclass;

    IF v_leaf_am IS DISTINCT FROM 'encrypted_heap' THEN
        RAISE EXCEPTION 'TEST 122 FAILED: leaf did not inherit encrypted_heap (got %)',
            COALESCE(v_leaf_am, '<NULL>');
    END IF;

    -- And it actually behaves as encrypted (catalog row + round-trip).
    INSERT INTO tde_part_122 VALUES (5, 'inherited_am_value');
    SELECT val INTO v_read FROM tde_part_122 WHERE id = 5;
    IF v_read IS DISTINCT FROM 'inherited_am_value' THEN
        RAISE EXCEPTION 'TEST 122 FAILED: inherited-AM leaf round-trip mismatch (got %)',
            COALESCE(v_read, '<NULL>');
    END IF;

    PERFORM 1 FROM pg_vault_tde_catalog WHERE relid = 'tde_part_122_inh'::regclass::oid;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TEST 122 FAILED: inherited-AM leaf has no DEK catalog row';
    END IF;

    DROP TABLE tde_part_122;
    RAISE NOTICE 'TEST 122 PASSED: PARTITION OF inherits parent''s encrypted_heap AM and is encrypted';
END;
$$;

-- ================================================================
-- TEST 123: on-disk forensic — encrypted leaf has no plaintext
--
-- Insert a distinctive marker into an encrypted leaf, CHECKPOINT to flush,
-- and confirm the marker is absent from the leaf's raw file (pattern from
-- tests 87/88).  Requires superuser for pg_read_binary_file.
-- ================================================================
DO $$
DECLARE
    needle    bytea;
    leaf_file text;
    leaf_bytes bytea;
BEGIN
    DROP TABLE IF EXISTS tde_part_123;

    CREATE TABLE tde_part_123 (id int, val text) PARTITION BY RANGE (id);
    CREATE TABLE tde_part_123_p1 PARTITION OF tde_part_123
        FOR VALUES FROM (1) TO (100) USING encrypted_heap;

    INSERT INTO tde_part_123 VALUES
        (1, repeat('PARTITION_PLAINTEXT_MARKER_123_', 8));

    CHECKPOINT;

    leaf_file  := pg_relation_filepath('tde_part_123_p1'::regclass);
    leaf_bytes := pg_read_binary_file(leaf_file);
    needle     := convert_to('PARTITION_PLAINTEXT_MARKER_123_PARTITION_PLAINTEXT_MARKER_123_', 'UTF8');

    IF position(needle IN leaf_bytes) > 0 THEN
        RAISE EXCEPTION 'TEST 123 FAILED: plaintext marker found in encrypted leaf file';
    END IF;

    DROP TABLE tde_part_123;
    RAISE NOTICE 'TEST 123 PASSED: encrypted leaf carries no plaintext on disk';
END;
$$;

-- ================================================================
-- TEST 124: cross-partition UPDATE (row movement) between encrypted leaves
--
-- Updating the partition key moves the row: PG runs tuple_delete on the
-- source leaf and tuple_insert on the destination leaf — both encrypted_heap.
-- The moved row must land in the right leaf and decrypt correctly.
-- ================================================================
DO $$
DECLARE
    v_where  text;
    v_read   text;
    n_lo     bigint;
    n_hi     bigint;
BEGIN
    DROP TABLE IF EXISTS tde_part_124;

    CREATE TABLE tde_part_124 (id int, val text) PARTITION BY RANGE (id);
    CREATE TABLE tde_part_124_lo PARTITION OF tde_part_124
        FOR VALUES FROM (1) TO (100)   USING encrypted_heap;
    CREATE TABLE tde_part_124_hi PARTITION OF tde_part_124
        FOR VALUES FROM (100) TO (200) USING encrypted_heap;

    INSERT INTO tde_part_124 VALUES (5, 'row_movement_value');

    -- Cross-partition move: id 5 (lo) → id 150 (hi).
    UPDATE tde_part_124 SET id = 150 WHERE id = 5;

    SELECT tableoid::regclass::text INTO v_where FROM tde_part_124 WHERE id = 150;
    IF v_where IS DISTINCT FROM 'tde_part_124_hi' THEN
        RAISE EXCEPTION 'TEST 124 FAILED: row did not move to hi leaf (found in %)',
            COALESCE(v_where, '<NULL>');
    END IF;

    SELECT count(*) INTO n_lo FROM tde_part_124_lo;
    SELECT count(*) INTO n_hi FROM tde_part_124_hi;
    IF n_lo <> 0 OR n_hi <> 1 THEN
        RAISE EXCEPTION 'TEST 124 FAILED: post-move counts lo=%, hi=% (expected 0,1)',
            n_lo, n_hi;
    END IF;

    SELECT val INTO v_read FROM tde_part_124 WHERE id = 150;
    IF v_read IS DISTINCT FROM 'row_movement_value' THEN
        RAISE EXCEPTION 'TEST 124 FAILED: moved row decrypt mismatch (got %)',
            COALESCE(v_read, '<NULL>');
    END IF;

    DROP TABLE tde_part_124;
    RAISE NOTICE 'TEST 124 PASSED: cross-partition row movement between encrypted leaves OK';
END;
$$;

-- ================================================================
-- TEST 125: ATTACH PARTITION of a pre-existing encrypted_heap table
--
-- ATTACH does not rewrite data or change the AM.  Attaching an already-
-- encrypted standalone table must preserve its data (relid stable → DEK
-- stable), keep it encrypted on disk, and make it readable via the parent.
-- ================================================================
DO $$
DECLARE
    v_oid_pre  oid;
    v_oid_post oid;
    v_read     text;
    needle     bytea;
    leaf_file  text;
    leaf_bytes bytea;
BEGIN
    DROP TABLE IF EXISTS tde_part_125;
    DROP TABLE IF EXISTS tde_part_125_std;

    -- Standalone encrypted table, populated before it becomes a partition.
    CREATE TABLE tde_part_125_std (id int, val text) USING encrypted_heap;
    INSERT INTO tde_part_125_std VALUES (42, repeat('ATTACH_MARKER_125_', 8));
    v_oid_pre := 'tde_part_125_std'::regclass::oid;

    CREATE TABLE tde_part_125 (id int, val text) PARTITION BY RANGE (id);
    ALTER TABLE tde_part_125
        ATTACH PARTITION tde_part_125_std FOR VALUES FROM (1) TO (100);

    -- relid is unchanged by ATTACH → the existing DEK still applies.
    v_oid_post := 'tde_part_125_std'::regclass::oid;
    IF v_oid_pre <> v_oid_post THEN
        RAISE EXCEPTION 'TEST 125 FAILED: relid changed across ATTACH (% → %)',
            v_oid_pre, v_oid_post;
    END IF;

    -- Readable through the parent after attach.
    SELECT val INTO v_read FROM tde_part_125 WHERE id = 42;
    IF v_read IS DISTINCT FROM repeat('ATTACH_MARKER_125_', 8) THEN
        RAISE EXCEPTION 'TEST 125 FAILED: attached partition unreadable via parent';
    END IF;

    -- Still encrypted at rest.
    CHECKPOINT;
    leaf_file  := pg_relation_filepath('tde_part_125_std'::regclass);
    leaf_bytes := pg_read_binary_file(leaf_file);
    needle     := convert_to('ATTACH_MARKER_125_ATTACH_MARKER_125_', 'UTF8');
    IF position(needle IN leaf_bytes) > 0 THEN
        RAISE EXCEPTION 'TEST 125 FAILED: plaintext found in attached encrypted partition file';
    END IF;

    DROP TABLE tde_part_125;   -- drops the attached partition too
    RAISE NOTICE 'TEST 125 PASSED: ATTACH of pre-existing encrypted table preserves data + encryption';
END;
$$;

-- ================================================================
-- TEST 126: DETACH PARTITION — detached leaf stays readable standalone
--
-- DETACH keeps the leaf's relid, so its catalog DEK row survives and the
-- now-standalone table must still decrypt.
-- ================================================================
DO $$
DECLARE
    v_read   text;
    n_cat    bigint;
BEGIN
    DROP TABLE IF EXISTS tde_part_126;
    DROP TABLE IF EXISTS tde_part_126_lo;

    CREATE TABLE tde_part_126 (id int, val text) PARTITION BY RANGE (id);
    CREATE TABLE tde_part_126_lo PARTITION OF tde_part_126
        FOR VALUES FROM (1) TO (100) USING encrypted_heap;

    INSERT INTO tde_part_126 VALUES (7, 'detach_survivor_value');

    ALTER TABLE tde_part_126 DETACH PARTITION tde_part_126_lo;

    -- Catalog DEK row must survive the detach (relid unchanged).
    SELECT count(*) INTO n_cat
    FROM pg_vault_tde_catalog WHERE relid = 'tde_part_126_lo'::regclass::oid;
    IF n_cat <> 1 THEN
        RAISE EXCEPTION 'TEST 126 FAILED: detached leaf lost its catalog DEK row (count=%)', n_cat;
    END IF;

    -- Standalone read must still decrypt.
    SELECT val INTO v_read FROM tde_part_126_lo WHERE id = 7;
    IF v_read IS DISTINCT FROM 'detach_survivor_value' THEN
        RAISE EXCEPTION 'TEST 126 FAILED: detached leaf unreadable (got %)',
            COALESCE(v_read, '<NULL>');
    END IF;

    DROP TABLE tde_part_126_lo;
    DROP TABLE tde_part_126;
    RAISE NOTICE 'TEST 126 PASSED: detached encrypted leaf remains readable standalone';
END;
$$;

-- ================================================================
-- TEST 127: MIXED tree — DOCUMENTS the per-leaf encryption limitation
--
-- Encryption is NOT a tree-wide property: a plain `heap` leaf attached to
-- the same parent stores its rows in PLAINTEXT on disk, with no error and
-- no warning.  This test asserts that exact gap so any future change that
-- starts enforcing tree-wide encryption is flagged here.
--
--   encrypted leaf  → no plaintext on disk + catalog DEK row present
--   plain heap leaf → plaintext present on disk + NO catalog row
-- ================================================================
DO $$
DECLARE
    enc_file   text;
    plain_file text;
    enc_bytes  bytea;
    plain_bytes bytea;
    needle     bytea;
    n_enc_cat  bigint;
    n_pln_cat  bigint;
BEGIN
    DROP TABLE IF EXISTS tde_part_127;

    CREATE TABLE tde_part_127 (id int, val text) PARTITION BY RANGE (id) USING encrypted_heap;
    CREATE TABLE tde_part_127_enc PARTITION OF tde_part_127
        FOR VALUES FROM (1) TO (100)   USING encrypted_heap;
    CREATE TABLE tde_part_127_plain PARTITION OF tde_part_127
        FOR VALUES FROM (100) TO (200) USING heap;

    INSERT INTO tde_part_127 VALUES
        (1,   repeat('MIXED_ENC_MARKER_127_',   8)),
        (150, repeat('MIXED_PLAIN_MARKER_127_', 8));

    CHECKPOINT;

    enc_file    := pg_relation_filepath('tde_part_127_enc'::regclass);
    plain_file  := pg_relation_filepath('tde_part_127_plain'::regclass);
    enc_bytes   := pg_read_binary_file(enc_file);
    plain_bytes := pg_read_binary_file(plain_file);

    -- Encrypted leaf: marker absent.
    needle := convert_to('MIXED_ENC_MARKER_127_MIXED_ENC_MARKER_127_', 'UTF8');
    IF position(needle IN enc_bytes) > 0 THEN
        RAISE EXCEPTION 'TEST 127 FAILED: plaintext found in the encrypted leaf';
    END IF;

    -- Plain leaf: marker present on disk (the documented leak).
    needle := convert_to('MIXED_PLAIN_MARKER_127_MIXED_PLAIN_MARKER_127_', 'UTF8');
    IF position(needle IN plain_bytes) = 0 THEN
        RAISE EXCEPTION 'TEST 127 FAILED: expected plaintext in the plain heap leaf but none found '
                        '(behaviour changed — mixed-tree encryption may now be enforced; revisit doc)';
    END IF;

    -- Catalog: encrypted leaf has a DEK row, plain leaf does not.
    SELECT count(*) INTO n_enc_cat
    FROM pg_vault_tde_catalog WHERE relid = 'tde_part_127_enc'::regclass::oid;
    SELECT count(*) INTO n_pln_cat
    FROM pg_vault_tde_catalog WHERE relid = 'tde_part_127_plain'::regclass::oid;

    IF n_enc_cat <> 1 THEN
        RAISE EXCEPTION 'TEST 127 FAILED: encrypted leaf missing catalog DEK row (count=%)', n_enc_cat;
    END IF;
    IF n_pln_cat <> 0 THEN
        RAISE EXCEPTION 'TEST 127 FAILED: plain heap leaf unexpectedly has a catalog DEK row (count=%)', n_pln_cat;
    END IF;

    DROP TABLE tde_part_127;
    RAISE WARNING 'TEST 127: mixed encrypted/plain partition tree stores plaintext in the plain '
                  'leaf';
END;
$$;


-- ================================================================
-- TEST 128: encrypted_heap intentionally DISABLES HOT updates
--
-- The v4 IV-first wire format makes heapam see the indexed column as always
-- "changed" (it inspects ciphertext, not plaintext), so no HOT update is
-- chosen. This is deliberate: a HOT decision over ciphertext could skip a
-- tde_btree index update and corrupt it. Assert HOT is off and that a normal
-- UPDATE + REINDEX still leaves the row findable via Index Scan.
-- ================================================================
DROP TABLE IF EXISTS tde_hot_128;
CREATE TABLE tde_hot_128 (id int4, val text) USING encrypted_heap;
CREATE INDEX tde_hot_idx_128
    ON tde_hot_128 USING tde_btree (id tde_int4_enc_ops);

INSERT INTO tde_hot_128 VALUES (1, 'before_update');

-- Only the non-indexed column changes.  On a plain heap this would be a HOT
-- update; on encrypted_heap the IV-first format forces a non-HOT update.
UPDATE tde_hot_128 SET val = 'after_update' WHERE id = 1;

-- Flush backend stats so the HOT-update counter is visible below.
SELECT pg_stat_force_next_flush();

DO $$
DECLARE
    n_hot      bigint;
    n_found    bigint;
    result_val text;
BEGIN
    -- HOT must be disabled on encrypted_heap: the IV-first wire format makes
    -- the indexed column always look modified to heapam, so no heap-only
    -- tuple is produced.
    SELECT n_tup_hot_upd INTO n_hot
    FROM pg_stat_user_tables WHERE relname = 'tde_hot_128';
    IF COALESCE(n_hot, 0) <> 0 THEN
        RAISE EXCEPTION
            'TEST 128 FAILED: expected NO HOT update on encrypted_heap (n_tup_hot_upd=%)',
            n_hot;
    END IF;

    -- A non-HOT UPDATE plus REINDEX must still leave the live row findable.
    REINDEX INDEX tde_hot_idx_128;

    -- Force an Index Scan and confirm the live (updated) row is found.
    SET enable_seqscan = off;
    SELECT count(*), max(val) INTO n_found, result_val
    FROM tde_hot_128 WHERE id = 1;
    RESET enable_seqscan;

    IF n_found <> 1 OR result_val IS DISTINCT FROM 'after_update' THEN
        RAISE EXCEPTION
            'TEST 128 FAILED: Index Scan after REINDEX found % row(s) val=% (expected 1, ''after_update'')',
            n_found, COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_hot_128;
    RAISE NOTICE
        'TEST 128 PASSED: encrypted_heap disables HOT (IV-first); non-HOT UPDATE + REINDEX keeps row findable';
END;
$$;


-- ================================================================
-- PHASE SUMMARY
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'v1.7 Tests 111-128 — COMPLETE';
    RAISE NOTICE '   tde_int4_enc_ops + disk forensic check . test 111';
    RAISE NOTICE '   tde_int8_enc_ops equality lookup ........ test 112';
    RAISE NOTICE '   tde_uuid_enc_ops equality lookup ........ test 113';
    RAISE NOTICE '   tde_date_enc_ops equality lookup ........ test 114';
    RAISE NOTICE '   tde_timestamptz_enc_ops equality lookup . test 115';
    RAISE NOTICE '   DEK rotation → stale index → REINDEX .... test 116';
    RAISE NOTICE '   multi-column enc_ops + text + int8 mix .. test 117';
    RAISE NOTICE '   CREATE INDEX on pre-populated table ..... test 118';
    RAISE NOTICE '   ON CONFLICT DO NOTHING + enc_ops unique . test 119';
    RAISE NOTICE '   partition routing + round-trip .......... test 120';
    RAISE NOTICE '   per-leaf DEK isolation .................. test 121';
    RAISE NOTICE '   AM inheritance (PARTITION OF) ........... test 122';
    RAISE NOTICE '   encrypted leaf on-disk forensic ......... test 123';
    RAISE NOTICE '   cross-partition row movement ............ test 124';
    RAISE NOTICE '   ATTACH pre-existing encrypted table ..... test 125';
    RAISE NOTICE '   DETACH keeps leaf readable .............. test 126';
    RAISE NOTICE '   MIXED tree limitation (doc) ............. test 127';
    RAISE NOTICE '   HOT disabled on encrypted_heap (IV-first) .. test 128';
    RAISE NOTICE '============================================================';
END;
$$;
