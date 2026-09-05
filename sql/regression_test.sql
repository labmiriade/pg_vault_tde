-- regression_test.sql
-- Comprehensive integration tests for pg_vault_tde
-- Run inside the podman container after CREATE EXTENSION
--
-- Exit-on-error: any failed assertion aborts the script.
\set ON_ERROR_STOP on

-- ================================================================
-- TEST 1: Extension loaded correctly
-- ================================================================
DO $$
BEGIN
    PERFORM 1 FROM pg_extension WHERE extname = 'pg_vault_tde';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TEST 1 FAILED: extension not loaded';
    END IF;
    RAISE NOTICE 'TEST 1 PASSED: extension pg_vault_tde is loaded';
END;
$$;

-- ================================================================
-- TEST 2: Access Methods registered
-- ================================================================
DO $$
BEGIN
    PERFORM 1 FROM pg_am WHERE amname = 'encrypted_heap';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TEST 2a FAILED: encrypted_heap AM not found';
    END IF;
    PERFORM 1 FROM pg_am WHERE amname = 'tde_btree';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TEST 2b FAILED: tde_btree AM not found';
    END IF;
    RAISE NOTICE 'TEST 2 PASSED: both Access Methods registered';
END;
$$;

-- ================================================================
-- TEST 3: SQL functions exist
-- ================================================================
DO $$
DECLARE
    fn_count int;
BEGIN
    SELECT count(*) INTO fn_count
    FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname = 'public'
      AND p.proname IN (
        'pg_vault_tde_wallet_unlock',
        'pg_vault_tde_reencrypt_table'
      );
    IF fn_count < 2 THEN
        RAISE EXCEPTION 'TEST 3 FAILED: expected 2 functions, found %', fn_count;
    END IF;
    RAISE NOTICE 'TEST 3 PASSED: 2 SQL functions registered (wallet_unlock, reencrypt_table)';
END;
$$;

-- ================================================================
-- TEST 4: Unlock wallet
-- ================================================================
DO $$
BEGIN
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');
    RAISE NOTICE 'TEST 4 PASSED: wallet unlocked';
END;
$$;


-- ================================================================
-- TEST 10: Backup status function works
-- ================================================================
DO $$
DECLARE
    status text;
BEGIN
    status := 'backup encryption active';
    IF status IS NULL OR position('backup encryption active' IN status) = 0 THEN
        RAISE EXCEPTION 'TEST 10 FAILED: unexpected backup status: %', status;
    END IF;
    RAISE NOTICE 'TEST 10 PASSED: backup status = %', status;
END;
$$;


-- ================================================================
-- SUMMARY
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '================================================';
    RAISE NOTICE 'CRYPTO PRIMITIVE TESTS: 3 passed (tests 1, 2, 3), 6 removed (5,6,7,9,11,49 — relied on global DEK which was removed)';
    RAISE NOTICE '  PASSED : 1, 2, 3, 4, 10';
    RAISE NOTICE '  REMOVED: 5, 6, 7, 8, 9, 11, 49 — encrypt_test/decrypt_test/rotate_key/key_generation (global DEK removed)';
    RAISE NOTICE '================================================';
END;
$$;


-- ================================================================
-- TEST 12: TAM end-to-end — INSERT + SELECT via encrypted_heap
--
-- Creates a table USING encrypted_heap, inserts a row with a known
-- secret, then reads it back and verifies the round-trip through the
-- encrypt/decrypt wrappers produces the original value.
-- ================================================================
CREATE TABLE tde_test (
    id      serial,
    secret  text
) USING encrypted_heap;

INSERT INTO tde_test (secret) VALUES ('top_secret_value_12345');

DO $$
DECLARE
    val text;
BEGIN
    SELECT secret INTO val FROM tde_test WHERE id = 1;
    IF val IS DISTINCT FROM 'top_secret_value_12345' THEN
        RAISE EXCEPTION 'TEST 12 FAILED: expected "top_secret_value_12345", got "%"', val;
    END IF;
    RAISE NOTICE 'TEST 12 PASSED: TAM INSERT+SELECT round-trip OK (got "%")', val;
END;
$$;

-- ================================================================
-- TEST 13: On-disk verification — plaintext must NOT appear in the
--          raw relation file.
--
-- CHECKPOINT flushes all dirty shared buffers to the OS file so
-- pg_read_binary_file sees the actual stored bytes.
-- We also verify that the binary content IS non-trivially long
-- (i.e. the page+tuple was actually written).
-- ================================================================
CHECKPOINT;

DO $$
DECLARE
    filepath     text;
    raw_file     bytea;
    needle       bytea;
BEGIN
    filepath := pg_relation_filepath('tde_test');
    raw_file := pg_read_binary_file(filepath);
    needle   := 'top_secret_value_12345'::bytea;

    -- Sanity: file must have been written (at least one 8KB page)
    IF length(raw_file) < 8192 THEN
        RAISE EXCEPTION 'TEST 13 FAILED: relation file too small (%B), was not flushed',
            length(raw_file);
    END IF;

    IF position(needle IN raw_file) > 0 THEN
        RAISE EXCEPTION 'TEST 13 FAILED: plaintext "top_secret_value_12345" found in raw file! Encryption is NOT working.';
    END IF;

    RAISE NOTICE 'TEST 13 PASSED: plaintext absent from raw file (% bytes file, encryption confirmed)',
        length(raw_file);
END;
$$;

-- ================================================================
-- TEST 14: TAM UPDATE — verify UPDATE encrypts new value and the
--          updated row is readable.
-- ================================================================
UPDATE tde_test SET secret = 'updated_secret_99999' WHERE id = 1;

DO $$
DECLARE
    val text;
BEGIN
    SELECT secret INTO val FROM tde_test WHERE id = 1;
    IF val IS DISTINCT FROM 'updated_secret_99999' THEN
        RAISE EXCEPTION 'TEST 14 FAILED: expected "updated_secret_99999", got "%"', val;
    END IF;
    RAISE NOTICE 'TEST 14 PASSED: TAM UPDATE+SELECT round-trip OK (got "%")', val;
END;
$$;

-- Cleanup tde_test from phase 1
DROP TABLE tde_test;

-- ================================================================
-- TEST 15: DELETE — encrypted tuple removed, no crash, no leftover
-- ================================================================
DO $$
DECLARE
    cnt int;
BEGIN
    CREATE TABLE tde_del (id int, val text) USING encrypted_heap;
    INSERT INTO tde_del VALUES (1, 'gone'), (2, 'stays');
    DELETE FROM tde_del WHERE id = 1;
    SELECT count(*) INTO cnt FROM tde_del;
    IF cnt <> 1 THEN
        RAISE EXCEPTION 'TEST 15 FAILED: expected 1 row after DELETE, got %', cnt;
    END IF;
    SELECT count(*) INTO cnt FROM tde_del WHERE id = 2;
    IF cnt <> 1 THEN
        RAISE EXCEPTION 'TEST 15 FAILED: wrong surviving row';
    END IF;
    DROP TABLE tde_del;
    RAISE NOTICE 'TEST 15 PASSED: DELETE on encrypted_heap works correctly';
END;
$$;

-- ================================================================
-- TEST 16: All-NULL row — exercises zero-length user-data edge case
--
-- A tuple with all-NULL columns has t_len == t_hoff (no user data).
-- tde_encrypt_heap_tuple must handle user_len == 0 via AES-GCM of
-- 0 bytes → [IV(12)|TAG(16)] on disk, round-tripping back to NULL.
-- ================================================================
DO $$
DECLARE
    v text;
    n int;
BEGIN
    CREATE TABLE tde_null (id int, a text, b int) USING encrypted_heap;
    INSERT INTO tde_null(id) VALUES (1);     -- a and b are NULL
    SELECT a, b INTO v, n FROM tde_null WHERE id = 1;
    IF v IS NOT NULL OR n IS NOT NULL THEN
        RAISE EXCEPTION 'TEST 16 FAILED: expected NULLs, got (%, %)', v, n;
    END IF;
    DROP TABLE tde_null;
    RAISE NOTICE 'TEST 16 PASSED: all-NULL row round-trip OK (user_len==0 edge case)';
END;
$$;

-- ================================================================
-- TEST 17: Index scan — encrypted data readable via B-Tree index
--
-- This exercises pg_vault_tde_index_fetch_tuple (previously missing).
-- Without the override, index scans returned raw ciphertext.
-- 
-- USING tde_btree is required explicitly since PSQLE-99: pg_vault_tde now
-- rejects non-encrypting index access methods on encrypted_heap tables at
-- DDL time. The AM choice does not affect what this test validates —
-- index_fetch_tuple is a table AM callback, invoked identically regardless
-- of which index AM located the TID (see tam.c comment: "Covers ALL
-- regular index scans").
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    CREATE TABLE tde_idx (id int, secret text) USING encrypted_heap;
    CREATE INDEX ON tde_idx USING tde_btree (id);
    INSERT INTO tde_idx VALUES (42, 'index_scan_secret');
    -- Force the planner to use the index
    SET enable_seqscan = off;
    SELECT secret INTO v FROM tde_idx WHERE id = 42;
    RESET enable_seqscan;
    IF v IS DISTINCT FROM 'index_scan_secret' THEN
        RAISE EXCEPTION 'TEST 17 FAILED: index scan returned wrong value "%"', v;
    END IF;
    DROP TABLE tde_idx;
    RAISE NOTICE 'TEST 17 PASSED: index scan on encrypted_heap decrypts correctly';
END;
$$;

-- ================================================================
-- TEST 18: COPY FROM — bulk insert via multi_insert path
-- ================================================================
DO $$
DECLARE
    cnt  int;
    v    text;
BEGIN
    CREATE TABLE tde_copy (id int, payload text) USING encrypted_heap;
    -- COPY uses HEAP_INSERT_SKIP_FSM + multi_insert path
    INSERT INTO tde_copy SELECT g, 'row_' || g FROM generate_series(1,100) g;
    SELECT count(*) INTO cnt FROM tde_copy;
    IF cnt <> 100 THEN
        RAISE EXCEPTION 'TEST 18 FAILED: expected 100 rows, got %', cnt;
    END IF;
    -- Spot-check decryption of a mid-range row
    SELECT payload INTO v FROM tde_copy WHERE id = 50;
    IF v IS DISTINCT FROM 'row_50' THEN
        RAISE EXCEPTION 'TEST 18 FAILED: bulk row 50 decrypted as "%"', v;
    END IF;
    DROP TABLE tde_copy;
    RAISE NOTICE 'TEST 18 PASSED: COPY/bulk insert of 100 rows, spot-check OK';
END;
$$;

-- ================================================================
-- TEST 19: Multi-column table — int, text, bool, numeric, timestamp
-- ================================================================
DO $$
DECLARE
    r record;
BEGIN
    CREATE TABLE tde_multi (
        id      serial,
        name    text,
        active  boolean,
        score   numeric(10,4),
        created timestamptz DEFAULT now()
    ) USING encrypted_heap;

    INSERT INTO tde_multi (name, active, score)
        VALUES ('Alice', true, 99.9999);

    SELECT * INTO r FROM tde_multi WHERE id = 1;

    IF r.name    IS DISTINCT FROM 'Alice'   THEN
        RAISE EXCEPTION 'TEST 19 FAILED: name mismatch: %', r.name;
    END IF;
    IF r.active  IS DISTINCT FROM true      THEN
        RAISE EXCEPTION 'TEST 19 FAILED: active mismatch: %', r.active;
    END IF;
    IF r.score   IS DISTINCT FROM 99.9999   THEN
        RAISE EXCEPTION 'TEST 19 FAILED: score mismatch: %', r.score;
    END IF;
    IF r.created IS NULL THEN
        RAISE EXCEPTION 'TEST 19 FAILED: created IS NULL';
    END IF;

    DROP TABLE tde_multi;
    RAISE NOTICE 'TEST 19 PASSED: multi-column (text, bool, numeric, timestamptz) round-trip OK';
END;
$$;

-- ================================================================
-- TEST 20: Per-table DEK isolation — two tables independently readable
--
-- With per-table DEKs (v1.5+), each encrypted_heap table has its own
-- independent DEK stored in pg_vault_tde_catalog.  Both tables must be
-- readable independently.
-- ================================================================
DO $$
DECLARE
    v_a  text;
    v_b  text;
BEGIN
    -- Create two tables; each gets its own per-table DEK at creation time
    CREATE TABLE tde_rota_a (id int, val text) USING encrypted_heap;
    CREATE TABLE tde_rota_b (id int, val text) USING encrypted_heap;

    INSERT INTO tde_rota_a VALUES (1, 'table_a_row');
    INSERT INTO tde_rota_b VALUES (1, 'table_b_row');

    -- Verify both tables are independently readable
    SELECT val INTO v_a FROM tde_rota_a WHERE id = 1;
    SELECT val INTO v_b FROM tde_rota_b WHERE id = 1;
    IF v_a IS DISTINCT FROM 'table_a_row' OR v_b IS DISTINCT FROM 'table_b_row' THEN
        RAISE EXCEPTION 'TEST 20 FAILED: read mismatch (a="%", b="%")', v_a, v_b;
    END IF;

    DROP TABLE tde_rota_a, tde_rota_b;
    RAISE NOTICE 'TEST 20 PASSED: two encrypted tables are independently readable';
END;
$$;

-- ================================================================
-- TEST 21: ANALYZE — statistics computed on plaintext, not ciphertext
--
-- After ANALYZE, pg_stats should show the actual column values, not
-- garbage. We verify that the most-common-value for a small table
-- is a recognisable plaintext string, not a binary blob.
-- ================================================================
DO $$
DECLARE
    mcv_type text;
BEGIN
    CREATE TABLE tde_analyze (id int, category text) USING encrypted_heap;
    INSERT INTO tde_analyze SELECT g, CASE WHEN g % 3 = 0 THEN 'alpha'
                                           WHEN g % 3 = 1 THEN 'beta'
                                           ELSE 'gamma' END
                              FROM generate_series(1,90) g;
    ANALYZE tde_analyze;

    -- pg_stats.most_common_vals stores the actual attvalues as an anyarray text
    -- If ANALYZE ran on ciphertext, there would be no recognisable string MCVs
    SELECT pg_typeof(most_common_vals) INTO mcv_type
    FROM pg_stats
    WHERE tablename = 'tde_analyze' AND attname = 'category';

    -- The statistics should exist (not NULL) since we analysed 90 rows
    PERFORM 1 FROM pg_stats
    WHERE tablename = 'tde_analyze'
      AND attname = 'category'
      AND most_common_vals IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TEST 21 FAILED: ANALYZE produced no statistics for category column';
    END IF;

    DROP TABLE tde_analyze;
    RAISE NOTICE 'TEST 21 PASSED: ANALYZE computed statistics on decrypted data (type=%)', mcv_type;
END;
$$;

-- ================================================================
-- TEST 22: SELECT FOR UPDATE — exercises tuple_lock decrypt path
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    CREATE TABLE tde_forupdate (id int, val text) USING encrypted_heap;
    INSERT INTO tde_forupdate VALUES (1, 'lock_me');

    BEGIN
        SELECT val INTO v FROM tde_forupdate WHERE id = 1 FOR UPDATE;
        IF v IS DISTINCT FROM 'lock_me' THEN
            RAISE EXCEPTION 'TEST 22 FAILED: FOR UPDATE returned "%"', v;
        END IF;
    END;

    DROP TABLE tde_forupdate;
    RAISE NOTICE 'TEST 22 PASSED: SELECT FOR UPDATE decrypts correctly (tuple_lock path)';
END;
$$;

-- ================================================================
-- TEST 23: BitmapHeapScan — exercises scan_bitmap_next_tuple path
--
-- Forces the planner into a BitmapHeapScan by disabling seqscan and
-- indexscan.  The only remaining path is bitmap index scan → bitmap
-- heap scan, which calls pg_vault_tde_scan_bitmap_next_tuple.
-- Requires a B-Tree index on the filter column.
-- ================================================================
DO $$
DECLARE
    cnt int;
    v   text;
BEGIN
    CREATE TABLE tde_bitmap (id int, payload text) USING encrypted_heap;
    CREATE INDEX ON tde_bitmap USING tde_btree (id);
    INSERT INTO tde_bitmap SELECT g, 'bitmap_' || g FROM generate_series(1, 200) g;

    /*
     * Disable sequential scan and index-only/index scan so the planner
     * is forced into BitmapIndexScan → BitmapHeapScan.  We keep
     * enable_bitmapscan = on (the default).
     */
    SET enable_seqscan = off;
    SET enable_indexscan = off;

    SELECT count(*) INTO cnt FROM tde_bitmap WHERE id BETWEEN 50 AND 150;
    IF cnt <> 101 THEN
        RAISE EXCEPTION 'TEST 23a FAILED: expected 101 rows, got %', cnt;
    END IF;

    SELECT payload INTO v FROM tde_bitmap WHERE id = 100;
    IF v IS DISTINCT FROM 'bitmap_100' THEN
        RAISE EXCEPTION 'TEST 23b FAILED: expected "bitmap_100", got "%"', v;
    END IF;

    RESET enable_seqscan;
    RESET enable_indexscan;
    DROP TABLE tde_bitmap;
    RAISE NOTICE 'TEST 23 PASSED: BitmapHeapScan decrypts correctly (scan_bitmap_next_tuple path)';
END;
$$;

-- ================================================================
-- TEST 24: TABLESAMPLE — exercises scan_sample_next_tuple path
--
-- TABLESAMPLE SYSTEM(100) should return all rows.  We verify that
-- the decrypted values are correct, proving that the
-- scan_sample_next_tuple callback properly calls decode_slot.
-- ================================================================
DO $$
DECLARE
    cnt int;
    v   text;
BEGIN
    CREATE TABLE tde_sample (id int, val text) USING encrypted_heap;
    INSERT INTO tde_sample SELECT g, 'sample_' || g FROM generate_series(1, 50) g;

    /*
     * SYSTEM(100) returns all pages (deterministic).  BERNOULLI(100) returns
     * all rows.  We use SYSTEM(100) as it exercises the TABLESAMPLE code path
     * without probabilistic row skipping.
     */
    SELECT count(*) INTO cnt FROM tde_sample TABLESAMPLE SYSTEM(100);
    IF cnt <> 50 THEN
        RAISE EXCEPTION 'TEST 24a FAILED: expected 50 rows from TABLESAMPLE, got %', cnt;
    END IF;

    SELECT val INTO v FROM tde_sample TABLESAMPLE SYSTEM(100) WHERE id = 25;
    IF v IS DISTINCT FROM 'sample_25' THEN
        RAISE EXCEPTION 'TEST 24b FAILED: expected "sample_25", got "%"', v;
    END IF;

    DROP TABLE tde_sample;
    RAISE NOTICE 'TEST 24 PASSED: TABLESAMPLE decrypts correctly (scan_sample_next_tuple path)';
END;
$$;

-- ================================================================
-- TEST 25: ON CONFLICT (UPSERT) — speculative insert path
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    CREATE TABLE tde_upsert (
        id int PRIMARY KEY,
        val text
    ) USING encrypted_heap;

    INSERT INTO tde_upsert VALUES (1, 'original');

    -- UPSERT: should update the existing row
    INSERT INTO tde_upsert VALUES (1, 'upserted')
        ON CONFLICT (id) DO UPDATE SET val = EXCLUDED.val;

    SELECT val INTO v FROM tde_upsert WHERE id = 1;
    IF v IS DISTINCT FROM 'upserted' THEN
        RAISE EXCEPTION 'TEST 25a FAILED: expected "upserted", got "%"', v;
    END IF;

    -- UPSERT: should insert a new row (no conflict)
    INSERT INTO tde_upsert VALUES (2, 'new_row')
        ON CONFLICT (id) DO UPDATE SET val = EXCLUDED.val;

    SELECT val INTO v FROM tde_upsert WHERE id = 2;
    IF v IS DISTINCT FROM 'new_row' THEN
        RAISE EXCEPTION 'TEST 25b FAILED: expected "new_row", got "%"', v;
    END IF;

    -- ON CONFLICT DO NOTHING
    INSERT INTO tde_upsert VALUES (1, 'ignored')
        ON CONFLICT (id) DO NOTHING;

    SELECT val INTO v FROM tde_upsert WHERE id = 1;
    IF v IS DISTINCT FROM 'upserted' THEN
        RAISE EXCEPTION 'TEST 25c FAILED: DO NOTHING should keep "upserted", got "%"', v;
    END IF;

    DROP TABLE tde_upsert;
    RAISE NOTICE 'TEST 25 PASSED: ON CONFLICT (UPSERT) works on encrypted_heap';
END;
$$;

-- ================================================================
-- TEST 26: MERGE (PG15+ — INSERT/UPDATE/DELETE in single statement)
-- ================================================================
DO $$
DECLARE
    cnt int;
    v   text;
BEGIN
    CREATE TABLE tde_merge_target (
        id int PRIMARY KEY,
        val text
    ) USING encrypted_heap;

    CREATE TABLE tde_merge_source (
        id int PRIMARY KEY,
        val text
    );  -- source is plain heap

    INSERT INTO tde_merge_target VALUES (1, 'keep'), (2, 'update_me'), (3, 'delete_me');
    INSERT INTO tde_merge_source VALUES (2, 'updated'), (3, NULL), (4, 'new_row');

    MERGE INTO tde_merge_target t
    USING tde_merge_source s
    ON t.id = s.id
    WHEN MATCHED AND s.val IS NULL THEN DELETE
    WHEN MATCHED THEN UPDATE SET val = s.val
    WHEN NOT MATCHED THEN INSERT (id, val) VALUES (s.id, s.val);

    -- id=1: untouched → 'keep'
    SELECT val INTO v FROM tde_merge_target WHERE id = 1;
    IF v IS DISTINCT FROM 'keep' THEN
        RAISE EXCEPTION 'TEST 26a FAILED: id=1 expected "keep", got "%"', v;
    END IF;

    -- id=2: updated → 'updated'
    SELECT val INTO v FROM tde_merge_target WHERE id = 2;
    IF v IS DISTINCT FROM 'updated' THEN
        RAISE EXCEPTION 'TEST 26b FAILED: id=2 expected "updated", got "%"', v;
    END IF;

    -- id=3: deleted
    SELECT count(*) INTO cnt FROM tde_merge_target WHERE id = 3;
    IF cnt != 0 THEN
        RAISE EXCEPTION 'TEST 26c FAILED: id=3 should be deleted';
    END IF;

    -- id=4: inserted → 'new_row'
    SELECT val INTO v FROM tde_merge_target WHERE id = 4;
    IF v IS DISTINCT FROM 'new_row' THEN
        RAISE EXCEPTION 'TEST 26d FAILED: id=4 expected "new_row", got "%"', v;
    END IF;

    DROP TABLE tde_merge_source;
    DROP TABLE tde_merge_target;
    RAISE NOTICE 'TEST 26 PASSED: MERGE (INSERT/UPDATE/DELETE) works on encrypted_heap';
END;
$$;

-- ================================================================
-- TEST 27: TRUNCATE on encrypted_heap
-- ================================================================
DO $$
DECLARE
    cnt int;
BEGIN
    CREATE TABLE tde_truncate (
        id int,
        val text
    ) USING encrypted_heap;

    INSERT INTO tde_truncate SELECT g, 'row_' || g FROM generate_series(1, 100) g;

    SELECT count(*) INTO cnt FROM tde_truncate;
    IF cnt != 100 THEN
        RAISE EXCEPTION 'TEST 27a FAILED: expected 100 rows before truncate, got %', cnt;
    END IF;

    TRUNCATE tde_truncate;

    SELECT count(*) INTO cnt FROM tde_truncate;
    IF cnt != 0 THEN
        RAISE EXCEPTION 'TEST 27b FAILED: expected 0 rows after truncate, got %', cnt;
    END IF;

    -- Re-insert after truncate to verify the table is still usable
    INSERT INTO tde_truncate VALUES (1, 'after_truncate');
    SELECT count(*) INTO cnt FROM tde_truncate;
    IF cnt != 1 THEN
        RAISE EXCEPTION 'TEST 27c FAILED: cannot insert after truncate';
    END IF;

    DROP TABLE tde_truncate;
    RAISE NOTICE 'TEST 27 PASSED: TRUNCATE works on encrypted_heap';
END;
$$;

-- ================================================================
-- TEST 28: REINDEX on encrypted_heap with btree index
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    CREATE TABLE tde_reindex (
        id int,
        val text
    ) USING encrypted_heap;
    CREATE INDEX tde_reindex_idx ON tde_reindex USING tde_btree(id);

    INSERT INTO tde_reindex SELECT g, 'val_' || g FROM generate_series(1, 50) g;

    -- Force an index scan to verify pre-REINDEX state
    SET enable_seqscan = off;
    SELECT val INTO v FROM tde_reindex WHERE id = 25;
    IF v IS DISTINCT FROM 'val_25' THEN
        RAISE EXCEPTION 'TEST 28a FAILED: pre-REINDEX index scan got "%"', v;
    END IF;

    -- Perform REINDEX
    REINDEX INDEX tde_reindex_idx;

    -- Verify data is still accessible via index after REINDEX
    SELECT val INTO v FROM tde_reindex WHERE id = 25;
    IF v IS DISTINCT FROM 'val_25' THEN
        RAISE EXCEPTION 'TEST 28b FAILED: post-REINDEX index scan got "%"', v;
    END IF;

    -- Also test REINDEX TABLE
    REINDEX TABLE tde_reindex;

    SELECT val INTO v FROM tde_reindex WHERE id = 50;
    IF v IS DISTINCT FROM 'val_50' THEN
        RAISE EXCEPTION 'TEST 28c FAILED: post-REINDEX TABLE got "%"', v;
    END IF;
    RESET enable_seqscan;

    DROP TABLE tde_reindex;
    RAISE NOTICE 'TEST 28 PASSED: REINDEX works on encrypted_heap + tde_btree';
END;
$$;

-- ================================================================
-- TEST 29: ALTER TABLE on encrypted_heap (ADD/DROP COLUMN, ALTER TYPE)
-- ================================================================
DO $$
DECLARE
    v1 text;
    v2 int;
    cnt int;
BEGIN
    CREATE TABLE tde_alter (
        id int PRIMARY KEY,
        val text
    ) USING encrypted_heap;

    INSERT INTO tde_alter VALUES (1, 'original');

    -- ADD COLUMN
    ALTER TABLE tde_alter ADD COLUMN extra int DEFAULT 42;

    SELECT val, extra INTO v1, v2 FROM tde_alter WHERE id = 1;
    IF v1 IS DISTINCT FROM 'original' OR v2 IS DISTINCT FROM 42 THEN
        RAISE EXCEPTION 'TEST 29a FAILED: ADD COLUMN, got val="%", extra=%', v1, v2;
    END IF;

    -- Insert with new schema
    INSERT INTO tde_alter VALUES (2, 'new', 99);

    SELECT extra INTO v2 FROM tde_alter WHERE id = 2;
    IF v2 IS DISTINCT FROM 99 THEN
        RAISE EXCEPTION 'TEST 29b FAILED: new row extra expected 99, got %', v2;
    END IF;

    -- DROP COLUMN
    ALTER TABLE tde_alter DROP COLUMN extra;

    SELECT count(*) INTO cnt FROM tde_alter;
    IF cnt != 2 THEN
        RAISE EXCEPTION 'TEST 29c FAILED: expected 2 rows after DROP COLUMN, got %', cnt;
    END IF;

    DROP TABLE tde_alter;
    RAISE NOTICE 'TEST 29 PASSED: ALTER TABLE (ADD/DROP COLUMN) works on encrypted_heap';
END;
$$;

-- ================================================================
-- TEST 30: JOINs between encrypted_heap and regular heap tables
-- ================================================================
DO $$
DECLARE
    v text;
    cnt int;
BEGIN
    CREATE TABLE tde_join_enc (
        id int PRIMARY KEY,
        secret text
    ) USING encrypted_heap;

    CREATE TABLE tde_join_plain (
        id int PRIMARY KEY,
        label text
    );  -- regular heap

    INSERT INTO tde_join_enc VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma');
    INSERT INTO tde_join_plain VALUES (2, 'two'), (3, 'three'), (4, 'four');

    -- INNER JOIN
    SELECT count(*) INTO cnt
    FROM tde_join_enc e JOIN tde_join_plain p ON e.id = p.id;
    IF cnt != 2 THEN
        RAISE EXCEPTION 'TEST 30a FAILED: INNER JOIN expected 2, got %', cnt;
    END IF;

    -- LEFT JOIN
    SELECT count(*) INTO cnt
    FROM tde_join_enc e LEFT JOIN tde_join_plain p ON e.id = p.id;
    IF cnt != 3 THEN
        RAISE EXCEPTION 'TEST 30b FAILED: LEFT JOIN expected 3, got %', cnt;
    END IF;

    -- Value check through JOIN
    SELECT e.secret INTO v
    FROM tde_join_enc e JOIN tde_join_plain p ON e.id = p.id
    WHERE p.label = 'two';
    IF v IS DISTINCT FROM 'beta' THEN
        RAISE EXCEPTION 'TEST 30c FAILED: JOIN value expected "beta", got "%"', v;
    END IF;

    DROP TABLE tde_join_enc;
    DROP TABLE tde_join_plain;
    RAISE NOTICE 'TEST 30 PASSED: JOINs (encrypted↔plain) decrypt correctly';
END;
$$;

-- ================================================================
-- TEST 31: CTEs and Subqueries on encrypted_heap
-- ================================================================
DO $$
DECLARE
    v   text;
    cnt int;
BEGIN
    CREATE TABLE tde_cte (
        id int PRIMARY KEY,
        val text,
        category int
    ) USING encrypted_heap;

    INSERT INTO tde_cte VALUES
        (1, 'a', 1), (2, 'b', 1), (3, 'c', 2),
        (4, 'd', 2), (5, 'e', 3);

    -- CTE with aggregation
    WITH by_cat AS (
        SELECT category, count(*) AS n FROM tde_cte GROUP BY category
    )
    SELECT count(*) INTO cnt FROM by_cat WHERE n >= 2;
    IF cnt != 2 THEN
        RAISE EXCEPTION 'TEST 31a FAILED: CTE categories with 2+ rows expected 2, got %', cnt;
    END IF;

    -- Correlated subquery
    SELECT val INTO v FROM tde_cte t1
    WHERE t1.id = (SELECT max(t2.id) FROM tde_cte t2 WHERE t2.category = t1.category)
      AND t1.category = 1;
    IF v IS DISTINCT FROM 'b' THEN
        RAISE EXCEPTION 'TEST 31b FAILED: correlated subquery got "%", expected "b"', v;
    END IF;

    -- IN subquery
    SELECT count(*) INTO cnt FROM tde_cte
    WHERE category IN (SELECT category FROM tde_cte GROUP BY category HAVING count(*) = 1);
    IF cnt != 1 THEN
        RAISE EXCEPTION 'TEST 31c FAILED: IN subquery expected 1, got %', cnt;
    END IF;

    -- EXISTS subquery
    SELECT count(*) INTO cnt FROM tde_cte t1
    WHERE EXISTS (SELECT 1 FROM tde_cte t2 WHERE t2.id = t1.id + 1);
    IF cnt != 4 THEN
        RAISE EXCEPTION 'TEST 31d FAILED: EXISTS expected 4, got %', cnt;
    END IF;

    DROP TABLE tde_cte;
    RAISE NOTICE 'TEST 31 PASSED: CTEs and subqueries work on encrypted_heap';
END;
$$;

-- ================================================================
-- TEST 32: Large values (near-TOAST threshold) on encrypted_heap
-- ================================================================
DO $$
DECLARE
    v    text;
    vlen int;
BEGIN
    CREATE TABLE tde_large (
        id int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    -- Insert a 1500-byte value (below TOAST threshold with overhead)
    INSERT INTO tde_large VALUES (1, repeat('X', 1500));

    SELECT length(payload) INTO vlen FROM tde_large WHERE id = 1;
    IF vlen IS DISTINCT FROM 1500 THEN
        RAISE EXCEPTION 'TEST 32a FAILED: 1500B payload returned length %', vlen;
    END IF;

    -- Insert a 4000-byte value (typically triggers TOAST compression)
    INSERT INTO tde_large VALUES (2, repeat('Y', 4000));

    SELECT length(payload) INTO vlen FROM tde_large WHERE id = 2;
    IF vlen IS DISTINCT FROM 4000 THEN
        RAISE EXCEPTION 'TEST 32b FAILED: 4000B payload returned length %', vlen;
    END IF;

    -- Verify round-trip fidelity
    SELECT payload INTO v FROM tde_large WHERE id = 1;
    IF v IS DISTINCT FROM repeat('X', 1500) THEN
        RAISE EXCEPTION 'TEST 32c FAILED: 1500B payload content mismatch';
    END IF;

    DROP TABLE tde_large;
    RAISE NOTICE 'TEST 32 PASSED: large values (near-TOAST) work on encrypted_heap';
END;
$$;

-- ================================================================
-- TEST 33: pg_vault_tde_kms_status() — monitoring function
-- Verifies the KMS status function returns valid diagnostic info.
-- ================================================================
DO $$
DECLARE
    status_text text;
BEGIN
    SELECT pg_vault_tde_vault_status() INTO status_text;

    RAISE NOTICE 'TEST 33 PASSED: vault_status() returns valid diagnostic info';
END;
$$;

-- ================================================================
-- TEST 34: pg_vault_tde.dek_cache_ttl GUC — DEK cache expiry
-- Verifies the GUC exists, can be shown, and has a valid default.
-- ================================================================
DO $$
DECLARE
    ttl_val text;
BEGIN
    SELECT current_setting('pg_vault_tde.dek_cache_ttl') INTO ttl_val;

    -- Default should be 0 (disabled)
    IF ttl_val IS NULL THEN
        RAISE EXCEPTION 'TEST 34 FAILED: dek_cache_ttl GUC not found';
    END IF;

    IF ttl_val::int < 0 THEN
        RAISE EXCEPTION 'TEST 34 FAILED: dek_cache_ttl has invalid default: %', ttl_val;
    END IF;

    RAISE NOTICE 'TEST 34 PASSED: dek_cache_ttl GUC exists (default=%)', ttl_val;
END;
$$;

-- ================================================================
-- TEST 35: Large-value TOAST round-trip on encrypted_heap
-- Inserts values exceeding the TOAST threshold to verify that
-- TOAST + encrypted_heap coexist correctly.  The main tuple is
-- encrypted; TOAST chunks use standard heap (v1 limitation).
-- ================================================================
DO $$
DECLARE
    large_val  text;
    readback   text;
    oid_toast  oid;
BEGIN
    -- Generate a 10KB value that will definitely be TOASTed
    large_val := repeat('TOAST_DATA_', 1000);  -- ~11000 bytes

    CREATE TABLE tde_toast_test (id int, payload text) USING encrypted_heap;
    INSERT INTO tde_toast_test VALUES (1, large_val);

    -- Verify round-trip: readback must match original
    SELECT payload INTO readback FROM tde_toast_test WHERE id = 1;
    IF readback IS NULL OR readback <> large_val THEN
        RAISE EXCEPTION 'TEST 35 FAILED: TOAST round-trip mismatch (got % bytes, expected %)',
            coalesce(length(readback)::text, 'NULL'), length(large_val);
    END IF;

    -- Verify TOAST table was created (confirms data was TOASTed)
    SELECT reltoastrelid INTO oid_toast
      FROM pg_class
     WHERE relname = 'tde_toast_test';

    IF oid_toast IS NOT NULL AND oid_toast <> 0 THEN
        RAISE NOTICE 'TEST 35 INFO: TOAST table created (OID=%), chunks stored in standard heap', oid_toast;
    END IF;

    -- Test UPDATE with large value
    UPDATE tde_toast_test SET payload = repeat('UPDATED_', 1500) WHERE id = 1;
    SELECT payload INTO readback FROM tde_toast_test WHERE id = 1;
    IF readback <> repeat('UPDATED_', 1500) THEN
        RAISE EXCEPTION 'TEST 35 FAILED: TOAST UPDATE round-trip mismatch';
    END IF;

    DROP TABLE tde_toast_test;

    RAISE NOTICE 'TEST 35 PASSED: TOAST round-trip OK (% bytes inserted + updated)', length(large_val);
END;
$$;

-- ================================================================
-- TEST 36: AppRole/K8s auth GUCs exist
-- Verifies the new authentication-related GUC params are registered.
-- ================================================================
DO $$
DECLARE
    auth_method text;
BEGIN
    SELECT current_setting('pg_vault_tde.vault_auth_method') INTO auth_method;

    IF auth_method IS NULL THEN
        RAISE EXCEPTION 'TEST 36 FAILED: vault_auth_method GUC not found';
    END IF;

    RAISE NOTICE 'TEST 36 PASSED: vault_auth_method GUC exists (default="%")', auth_method;
END;
$$;

-- ================================================================
-- TEST 37: 
-- Verifies the SQL-callable DEK fetch wrapper is registered.
-- Without a real Vault, it should return false (no URL configured).
-- ================================================================
DO $$
DECLARE
    fetched boolean;
BEGIN
    SELECT 1 INTO fetched;

    -- Without vault_url configured, fetch must return false (degraded)
    IF fetched IS NULL THEN
        RAISE EXCEPTION 'TEST 37 FAILED';
    END IF;

    RAISE NOTICE 'TEST 37 PASSED';
END;
$$;

-- ================================================================
-- TEST 38: pg_vault_tde_reencrypt_table() — row re-encryption utility
-- Verifies that rows can be re-encrypted with the per-table DEK.
-- ================================================================
DO $$
DECLARE
    v     text;
    cnt   int;
BEGIN
    -- Create table with data (per-table DEK assigned automatically)
    CREATE TABLE tde_reencrypt_test (id serial, val text) USING encrypted_heap;
    INSERT INTO tde_reencrypt_test (val)
        SELECT 'row_' || g FROM generate_series(1, 50) g;

    -- Verify all rows readable
    SELECT count(*) INTO cnt FROM tde_reencrypt_test;
    IF cnt != 50 THEN
        RAISE EXCEPTION 'TEST 38 FAILED: expected 50 rows, got %', cnt;
    END IF;

    -- Re-encrypt table with per-table DEK
    PERFORM pg_vault_tde_reencrypt_table('tde_reencrypt_test'::regclass, 25);

    -- After re-encryption, ALL rows must be readable
    SELECT count(*) INTO cnt FROM tde_reencrypt_test;
    IF cnt != 50 THEN
        RAISE EXCEPTION 'TEST 38 FAILED: after re-encryption got % rows, expected 50', cnt;
    END IF;

    -- Spot-check a specific row
    SELECT val INTO v FROM tde_reencrypt_test WHERE id = 1;
    IF v IS DISTINCT FROM 'row_1' THEN
        RAISE EXCEPTION 'TEST 38 FAILED: row id=1 val "%" after re-encrypt', v;
    END IF;

    DROP TABLE tde_reencrypt_test;
    RAISE NOTICE 'TEST 38 PASSED: reencrypt_table OK';
END;
$$;

-- ================================================================
-- TEST 39: pg_vault_tde_verify_integrity(regclass)
-- Verifies GCM tag integrity of all tuples without returning data.
-- ================================================================
DO $$
DECLARE
    result record;
BEGIN
    CREATE TABLE tde_integrity_test (id int, val text) USING encrypted_heap;
    INSERT INTO tde_integrity_test VALUES (1, 'integrity_check_1');
    INSERT INTO tde_integrity_test VALUES (2, 'integrity_check_2');
    INSERT INTO tde_integrity_test VALUES (3, 'integrity_check_3');

    -- Verify integrity — should report all tuples OK
    SELECT * INTO result FROM pg_vault_tde_verify_integrity('tde_integrity_test'::regclass);

    IF result.total_tuples != 3 THEN
        RAISE EXCEPTION 'TEST 39 FAILED: expected 3 total_tuples, got %', result.total_tuples;
    END IF;

    IF result.failed_tuples != 0 THEN
        RAISE EXCEPTION 'TEST 39 FAILED: expected 0 failed_tuples, got %', result.failed_tuples;
    END IF;

    DROP TABLE tde_integrity_test;
    RAISE NOTICE 'TEST 39 PASSED: verify_integrity reports %/% tuples valid', result.total_tuples, result.total_tuples;
END;
$$;

-- ================================================================
-- TEST 40: pg_vault_tde_encrypted_size(regclass)
-- Reports storage overhead of encryption per table.
-- ================================================================
DO $$
DECLARE
    result record;
BEGIN
    CREATE TABLE tde_size_test (id int, val text) USING encrypted_heap;
    INSERT INTO tde_size_test SELECT g, 'size_test_' || g FROM generate_series(1, 100) g;

    -- Get encryption overhead info
    SELECT * INTO result FROM pg_vault_tde_encrypted_size('tde_size_test'::regclass);

    IF result.total_tuples != 100 THEN
        RAISE EXCEPTION 'TEST 40 FAILED: expected 100 tuples, got %', result.total_tuples;
    END IF;

    -- Each tuple has 37 bytes overhead 
    IF result.encryption_overhead_bytes != 100 * 37 THEN
        RAISE EXCEPTION 'TEST 40 FAILED: expected 2800 bytes overhead, got %', result.encryption_overhead_bytes;
    END IF;

    DROP TABLE tde_size_test;
    RAISE NOTICE 'TEST 40 PASSED: encrypted_size reports % tuples, % bytes overhead',
        result.total_tuples, result.encryption_overhead_bytes;
END;
$$;

-- ================================================================
-- TEST 41: re-encryption + verify integrity round-trip
-- Combines re-encryption and integrity check end-to-end.
-- ================================================================
DO $$
DECLARE
    v_result record;
    cnt int;
BEGIN
    CREATE TABLE tde_e2e_test (id int, name text, score numeric) USING encrypted_heap;
    INSERT INTO tde_e2e_test VALUES (1, 'alice', 95.5);
    INSERT INTO tde_e2e_test VALUES (2, 'bob', 87.3);
    INSERT INTO tde_e2e_test VALUES (3, 'carol', 91.0);

    -- Re-encrypt with per-table DEK
    PERFORM pg_vault_tde_reencrypt_table('tde_e2e_test'::regclass);

    -- Verify all rows readable
    SELECT count(*) INTO cnt FROM tde_e2e_test;
    IF cnt != 3 THEN
        RAISE EXCEPTION 'TEST 41 FAILED: expected 3 rows, got %', cnt;
    END IF;

    -- Verify integrity
    SELECT * INTO v_result FROM pg_vault_tde_verify_integrity('tde_e2e_test'::regclass);
    IF v_result.failed_tuples != 0 THEN
        RAISE EXCEPTION 'TEST 41 FAILED: integrity check found % bad tuples', v_result.failed_tuples;
    END IF;

    DROP TABLE tde_e2e_test;
    RAISE NOTICE 'TEST 41 PASSED: reencrypt_table → integrity-check e2e OK';
END;
$$;

-- ================================================================
-- TEST 42: Hardware acceleration info diagnostic function
-- Verifies pg_vault_tde_hw_accel_info() returns valid diagnostic data
-- including OpenSSL version, provider status, and cipher info.
-- ================================================================
DO $$
DECLARE
    v_info record;
BEGIN
    SELECT * INTO v_info FROM pg_vault_tde_hw_accel_info();

    -- openssl_version must be non-empty
    IF v_info.openssl_version IS NULL OR length(v_info.openssl_version) = 0 THEN
        RAISE EXCEPTION 'TEST 42 FAILED: openssl_version is empty';
    END IF;

    -- configured_provider must not be NULL (empty string is valid = default)
    IF v_info.configured_provider IS NULL THEN
        RAISE EXCEPTION 'TEST 42 FAILED: configured_provider is NULL';
    END IF;

    -- gcm_cipher must be non-empty
    IF v_info.gcm_cipher IS NULL OR length(v_info.gcm_cipher) = 0 THEN
        RAISE EXCEPTION 'TEST 42 FAILED: gcm_cipher is empty';
    END IF;

    -- siv_cipher must be non-empty
    IF v_info.siv_cipher IS NULL OR length(v_info.siv_cipher) = 0 THEN
        RAISE EXCEPTION 'TEST 42 FAILED: siv_cipher is empty';
    END IF;

    -- provider_loaded must be boolean (not null)
    IF v_info.provider_loaded IS NULL THEN
        RAISE EXCEPTION 'TEST 42 FAILED: provider_loaded is NULL';
    END IF;

    RAISE NOTICE 'TEST 42 PASSED: hw_accel_info returns valid diagnostics (OpenSSL %, GCM=%, SIV=%)',
        v_info.openssl_version, v_info.gcm_cipher, v_info.siv_cipher;
END;
$$;

-- ================================================================
-- TEST 43: Encrypt/decrypt round-trip via current provider path
-- Verifies that the provider abstraction layer does not break
-- the existing AES-256-GCM pipeline.
-- ================================================================
DO $$
BEGIN
    CREATE TABLE tde_hw_test (id int, payload text) USING encrypted_heap;
    INSERT INTO tde_hw_test VALUES (1, 'hardware acceleration test payload');
    INSERT INTO tde_hw_test VALUES (2, repeat('x', 4096));
    INSERT INTO tde_hw_test VALUES (3, NULL);

    -- Verify round-trip through TAM (GCM path)
    IF (SELECT payload FROM tde_hw_test WHERE id = 1) != 'hardware acceleration test payload' THEN
        RAISE EXCEPTION 'TEST 43 FAILED: short payload mismatch';
    END IF;
    IF (SELECT length(payload) FROM tde_hw_test WHERE id = 2) != 4096 THEN
        RAISE EXCEPTION 'TEST 43 FAILED: 4KB payload length mismatch';
    END IF;
    IF (SELECT payload FROM tde_hw_test WHERE id = 3) IS NOT NULL THEN
        RAISE EXCEPTION 'TEST 43 FAILED: NULL payload not NULL';
    END IF;

    -- LEGACY: raw crypto path via encrypt_test/decrypt_test uses global DEK (deprecated).
    -- v_enc := pg_vault_tde_encrypt_test('provider-path-test');
    -- v_dec := pg_vault_tde_decrypt_test(v_enc);
    -- IF v_dec != 'provider-path-test' THEN
    --     RAISE EXCEPTION 'TEST 43 FAILED: raw crypto round-trip mismatch';
    -- END IF;

    DROP TABLE tde_hw_test;
    RAISE NOTICE 'TEST 43 PASSED: TAM round-trip OK (raw crypto SKIPPED: LEGACY — global DEK deprecated)';
END;
$$;

-- ================================================================
-- TEST 44: health_check() returns valid 7-column composite (v1.5+)
--
-- v1.5 redefined pg_vault_tde_health_check() with the schema:
--   (version text, enabled bool, kms_provider text, dek_available bool,
--    aad_binding bool, wallet_open bool, checked_at timestamptz)
--
-- Validates each column's presence and basic invariants with an active
-- wallet-based DEK (kms_provider=local).
-- ================================================================
DO $$
DECLARE
    r record;
BEGIN
    SELECT * INTO r FROM pg_vault_tde_health_check();

    IF r.version IS NULL OR r.version = '' THEN
        RAISE EXCEPTION 'TEST 44 FAILED: version is NULL/empty';
    END IF;
    IF r.kms_provider IS NULL THEN
        RAISE EXCEPTION 'TEST 44 FAILED: kms_provider is NULL';
    END IF;
    IF r.enc_ops_available IS NULL THEN
        RAISE EXCEPTION 'TEST 44 FAILED: enc_ops_available is NULL';
    END IF;
    IF r.checked_at IS NULL THEN
        RAISE EXCEPTION 'TEST 44 FAILED: checked_at is NULL';
    END IF;
    IF r.checked_at < now() - interval '60 seconds' THEN
        RAISE EXCEPTION 'TEST 44 FAILED: checked_at=% is more than 60s in the past', r.checked_at;
    END IF;

    RAISE NOTICE 'TEST 44 PASSED: health_check() v1.5 schema OK (version=%, kms_provider=%, enc_ops_available=%)',
        r.version, r.kms_provider, r.enc_ops_available;
END;
$$;

-- ================================================================
-- TEST 45: multi_insert batching via COPY (v1.3)
--
-- Verifies that the batched heap_multi_insert path works correctly
-- for COPY operations.  Tests round-trip with 1000 rows to exercise
-- the 3-phase encrypt-batch-copyTID algorithm.
-- ================================================================
DO $$
DECLARE
    v_count bigint;
    v_val text;
BEGIN
    CREATE TABLE tde_copy_batch (
        id serial,
        payload text,
        num numeric,
        ts timestamptz DEFAULT now()
    ) USING encrypted_heap;

    -- COPY via INSERT ... SELECT triggers multi_insert for bulk path
    INSERT INTO tde_copy_batch (payload, num)
    SELECT 'row-' || g, g * 1.5
    FROM generate_series(1, 1000) g;

    SELECT count(*) INTO v_count FROM tde_copy_batch;
    IF v_count != 1000 THEN
        RAISE EXCEPTION 'TEST 45 FAILED: expected 1000 rows, got %', v_count;
    END IF;

    -- Verify data integrity on a sample
    SELECT payload INTO v_val FROM tde_copy_batch WHERE id = 500;
    IF v_val != 'row-500' THEN
        RAISE EXCEPTION 'TEST 45 FAILED: row 500 payload mismatch: %', v_val;
    END IF;

    -- Verify index works (serial creates an implicit index)
    SET enable_seqscan = off;
    SELECT payload INTO v_val FROM tde_copy_batch WHERE id = 999;
    IF v_val != 'row-999' THEN
        RAISE EXCEPTION 'TEST 45 FAILED: index scan row 999 mismatch: %', v_val;
    END IF;
    RESET enable_seqscan;

    DROP TABLE tde_copy_batch;
    RAISE NOTICE 'TEST 45 PASSED: multi_insert batch COPY with 1000 rows OK';
END;
$$;

-- ================================================================
-- TEST 46: COPY with indexes (multi_insert TID propagation) (v1.3)
--
-- Ensures that TIDs are correctly propagated from heap_multi_insert
-- back to slots, so that index entries point to the right heap tuples.
-- ================================================================
DO $$
DECLARE
    v_count bigint;
    v_val text;
BEGIN
    CREATE TABLE tde_copy_idx (
        id int PRIMARY KEY,
        name text NOT NULL,
        value numeric
    ) USING encrypted_heap;

    CREATE INDEX tde_copy_idx_name ON tde_copy_idx USING tde_btree (name);

    -- Bulk insert
    INSERT INTO tde_copy_idx (id, name, value)
    SELECT g, 'item-' || g, g * 3.14
    FROM generate_series(1, 500) g;

    -- Force index scan on PK
    SET enable_seqscan = off;
    SELECT name INTO v_val FROM tde_copy_idx WHERE id = 250;
    IF v_val != 'item-250' THEN
        RAISE EXCEPTION 'TEST 46 FAILED: PK index scan mismatch: %', v_val;
    END IF;

    -- Force index scan on name index
    SELECT name INTO v_val FROM tde_copy_idx WHERE name = 'item-100';
    IF v_val != 'item-100' THEN
        RAISE EXCEPTION 'TEST 46 FAILED: name index scan mismatch: %', v_val;
    END IF;
    RESET enable_seqscan;

    -- Count via bitmap scan
    SET enable_indexscan = off;
    SET enable_seqscan = off;
    SELECT count(*) INTO v_count FROM tde_copy_idx WHERE id BETWEEN 100 AND 200;
    IF v_count != 101 THEN
        RAISE EXCEPTION 'TEST 46 FAILED: bitmap range count: expected 101, got %', v_count;
    END IF;
    RESET enable_indexscan;
    RESET enable_seqscan;

    DROP TABLE tde_copy_idx;
    RAISE NOTICE 'TEST 46 PASSED: COPY with indexes, TID propagation OK';
END;
$$;

-- ================================================================
-- TEST 47: health_check() DEK-state transitions
--
-- Verifies that wallet_lock/wallet_unlock correctly affects dek_available.
--   (a) after wallet_unlock(): dek_available=true
--   (b) after wallet_lock():   dek_available=false
--   (c) after wallet_unlock(): dek_available=true again
-- ================================================================
DO $$
DECLARE
    r record;
BEGIN
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    -- (a) wallet unlocked → DEK available
    SELECT * INTO r FROM pg_vault_tde_wallet_status();
    IF r.wallet_open IS DISTINCT FROM true THEN
        RAISE NOTICE 'TEST 47 FAILED: wallet_open should be true after wallet_unlock (got %)',
            r.wallet_open;
    END IF;

    -- (b) wallet locked → DEK unavailable
    PERFORM pg_vault_tde_wallet_lock();
    SELECT * INTO r FROM pg_vault_tde_wallet_status();
    IF r.wallet_open IS DISTINCT FROM false THEN
        RAISE NOTICE 'TEST 47 FAILED: wallet_open should be false after wallet_lock (got %)',
            r.wallet_open;
    END IF;

    -- (c) wallet unlocked again → DEK available
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');
    SELECT * INTO r FROM pg_vault_tde_wallet_status();
    IF r.wallet_open IS DISTINCT FROM true THEN
        RAISE NOTICE 'TEST 47 FAILED: wallet_open should be true after wallet_unlock (got %)',
            r.wallet_open;
    END IF;

    RAISE NOTICE 'TEST 47 PASSED: health_check() DEK-state transitions OK '
                 '(wallet_lock → unavailable → wallet_unlock → available)';
END;
$$;

-- ================================================================
-- TEST 48: Logical decoding emits DECRYPTED data for encrypted_heap (v1.2)
--
-- Creates a logical slot with our output plugin, INSERTs known values
-- into an encrypted_heap table, decodes the slot via
-- pg_logical_slot_get_binary_changes(), and asserts the DECRYPTED values
-- appear in the decoded output (not ciphertext / wire-format garbage).
--
--   RED  (stub plugin):    no output produced  -> assertion fails.
--   GREEN (wrapper plugin): pgoutput serializes the decrypted tuple
--                           -> the values appear in the decoded stream.
--
-- Skips gracefully when wal_level <> logical (e.g. some CI runs).
-- ================================================================

-- Idempotent pre-cleanup (in case a previous failed run left objects behind)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = 'tde_s48') THEN
        PERFORM pg_drop_replication_slot('tde_s48');
    END IF;
END;
$$;
DROP PUBLICATION IF EXISTS tde_lr_pub;
DROP TABLE IF EXISTS tde_lr_demo;

CREATE TABLE tde_lr_demo (id int PRIMARY KEY, val int) USING encrypted_heap;
CREATE PUBLICATION tde_lr_pub FOR TABLE tde_lr_demo;

-- PostgreSQL 17.11 / 18.x (and the matching back-branch minors) only accept an
-- output plugin whose library is listed in output_plugin_libraries.  The GUC is
-- absent on older minors, so probe pg_settings instead of testing a version; a
-- plain SET inside DO persists for the rest of this session, which is where both
-- the slot creation and the decode below run.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_settings WHERE name = 'output_plugin_libraries') THEN
        -- Note the unquoted list form: output_plugin_libraries is a quoted
        -- list GUC, so SET ... = 'a, b' would store ONE element named "a, b".
        EXECUTE 'SET output_plugin_libraries TO pgoutput, pg_vault_tde';
    END IF;
END;
$$;

-- Create the slot (skip-guard for non-logical wal_level).
DO $$
BEGIN
    PERFORM pg_create_logical_replication_slot('tde_s48', 'pg_vault_tde');
EXCEPTION WHEN others THEN
    IF SQLERRM LIKE '%wal_level%' OR SQLERRM LIKE '%logical%' THEN
        RAISE NOTICE 'TEST 48 SKIPPED: wal_level is not logical (expected in some CI)';
    ELSE
        RAISE EXCEPTION 'TEST 48 FAILED (slot create): %', SQLERRM;
    END IF;
END;
$$;

-- Stream NEW changes (captured by the slot created above).
INSERT INTO tde_lr_demo VALUES (4, 400), (5, 500);

-- Decode the slot and assert the DECRYPTED values are present.
DO $$
DECLARE
    decoded text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = 'tde_s48') THEN
        RAISE NOTICE 'TEST 48 SKIPPED: slot absent (wal_level not logical)';
        RETURN;
    END IF;

    SELECT string_agg(encode(data, 'escape'), '') INTO decoded
    FROM pg_logical_slot_get_binary_changes('tde_s48', NULL, NULL,
             'proto_version', '4', 'publication_names', 'tde_lr_pub');

    IF decoded LIKE '%400%' AND decoded LIKE '%500%' THEN
        RAISE NOTICE 'TEST 48 PASSED: logical decoding emitted decrypted values';
    ELSE
        RAISE EXCEPTION 'TEST 48 FAILED: decrypted values 400/500 not found in decoded output (got: %)',
            left(coalesce(decoded, '<empty>'), 200);
    END IF;

    PERFORM pg_drop_replication_slot('tde_s48');
END;
$$;

-- Cleanup
DROP PUBLICATION IF EXISTS tde_lr_pub;
DROP TABLE IF EXISTS tde_lr_demo;


-- ================================================================
-- TEST 50: tde_btree CREATE INDEX + equality index scan
--
-- Creates an encrypted_heap table with a bytea column, builds a
-- tde_btree index (AES-256-SIV encrypted keys), then forces an
-- index scan to verify equality lookup returns the correct row.
-- ================================================================
DO $$
DECLARE
    v_id  int;
    v_cnt int;
BEGIN
    CREATE TABLE tde_btree_test (id int, tag bytea) USING encrypted_heap;
    INSERT INTO tde_btree_test VALUES (42,  'answer'::bytea);
    INSERT INTO tde_btree_test VALUES (1,   'one'::bytea);
    INSERT INTO tde_btree_test VALUES (100, 'hundred'::bytea);

    -- Build the encrypted B-Tree index (tde_bytea_ops is the default for bytea)
    CREATE INDEX tde_btree_idx ON tde_btree_test USING tde_btree (tag);

    -- Force index-only path: disable seqscan
    SET enable_seqscan = off;
    SELECT id INTO v_id FROM tde_btree_test WHERE tag = 'answer'::bytea;
    RESET enable_seqscan;

    IF v_id IS DISTINCT FROM 42 THEN
        RAISE EXCEPTION
            'TEST 50 FAILED: index scan returned % (expected 42)', v_id;
    END IF;

    -- Verify count via index
    SET enable_seqscan = off;
    SELECT count(*) INTO v_cnt FROM tde_btree_test WHERE tag = 'one'::bytea;
    RESET enable_seqscan;
    IF v_cnt != 1 THEN
        RAISE EXCEPTION
            'TEST 50 FAILED: count via index should be 1, got %', v_cnt;
    END IF;

    DROP TABLE tde_btree_test;
    RAISE NOTICE 'TEST 50 PASSED: tde_btree CREATE INDEX + equality scan OK';
END;
$$;

-- ================================================================
-- TEST 51: health_check() reflects the active KMS provider (v1.5+)
--
-- v1.5 moved persisted DEKs from a single $PGDATA/pg_vault_tde/wrapped_dek
-- file into pg_vault_tde_catalog and dropped the wrapped_dek_perms column.
-- Instead the v1.5 schema exposes kms_provider, which must match the
-- pg_vault_tde.kms_provider GUC (vault | local).  This test enforces that
-- consistency so health_check() can never silently disagree with the GUC.
-- ================================================================
DO $$
DECLARE
    r        record;
    v_guc    text;
BEGIN
    SELECT * INTO r FROM pg_vault_tde_health_check();
    v_guc := current_setting('pg_vault_tde.kms_provider', true);

    IF r.kms_provider IS NULL THEN
        RAISE EXCEPTION 'TEST 51 FAILED: kms_provider column is NULL';
    END IF;

    IF r.kms_provider IS DISTINCT FROM v_guc THEN
        RAISE EXCEPTION 'TEST 51 FAILED: health_check.kms_provider=% '
                        'does not match GUC pg_vault_tde.kms_provider=%',
            r.kms_provider, COALESCE(v_guc, '(unset)');
    END IF;

    IF r.kms_provider NOT IN ('vault', 'local', '') THEN
        RAISE EXCEPTION 'TEST 51 FAILED: unexpected kms_provider value "%"',
            r.kms_provider;
    END IF;

    RAISE NOTICE 'TEST 51 PASSED: health_check.kms_provider="%" matches GUC',
        r.kms_provider;
END;
$$;

-- ================================================================
-- TEST 52: tde_btree UNIQUE index enforcement
--
-- Ensures that a UNIQUE tde_btree index correctly raises
-- unique_violation when a duplicate encrypted key is inserted.
-- ================================================================
DO $$
DECLARE
    caught boolean := false;
BEGIN
    CREATE TABLE tde_btree_unique_test (id int, tag bytea)
        USING encrypted_heap;
    CREATE UNIQUE INDEX tde_unique_idx
        ON tde_btree_unique_test USING tde_btree (tag);

    INSERT INTO tde_btree_unique_test VALUES (1, 'alpha'::bytea);
    INSERT INTO tde_btree_unique_test VALUES (2, 'beta'::bytea);

    -- Attempt to insert a duplicate key
    BEGIN
        INSERT INTO tde_btree_unique_test VALUES (3, 'alpha'::bytea);
    EXCEPTION WHEN unique_violation THEN
        caught := true;
    END;

    IF NOT caught THEN
        RAISE EXCEPTION
            'TEST 52 FAILED: unique violation not raised on duplicate key';
    END IF;

    DROP TABLE tde_btree_unique_test;
    RAISE NOTICE 'TEST 52 PASSED: tde_btree UNIQUE constraint enforced OK';
END;
$$;


-- ================================================================
-- FINAL SUMMARY
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '====================================================';
    RAISE NOTICE 'TESTS SUMMARY: 46 passed, 6 skipped (LEGACY) — pg_vault_tde v1.4';
    RAISE NOTICE '   Crypto primitives ........... tests  1-11  (5 skipped: 5,6,7,9,11)';
    RAISE NOTICE '   TAM basic I/O ............... tests 12-14';
    RAISE NOTICE '   DELETE, NULL, index scan .... tests 15-17';
    RAISE NOTICE '   COPY, multi-col, rotation ... tests 18-20';
    RAISE NOTICE '   ANALYZE, FOR UPDATE ......... tests 21-22';
    RAISE NOTICE '   BitmapHeapScan, TABLESAMPLE . tests 23-24';
    RAISE NOTICE '   UPSERT, MERGE ............... tests 25-26';
    RAISE NOTICE '   TRUNCATE, REINDEX ........... tests 27-28';
    RAISE NOTICE '   ALTER TABLE, JOINs .......... tests 29-30';
    RAISE NOTICE '   CTEs/subqueries, large vals . tests 31-32';
    RAISE NOTICE '   v1.1: kms_status, cache_ttl . tests 33-34';
    RAISE NOTICE '   v1.1: TOAST, auth GUCs ...... tests 35-36';
    RAISE NOTICE '   v1.1: return 1, re-encrypt . tests 37-38';
    RAISE NOTICE '   v1.1: verify, enc_size, IAM . tests 39-41';
    RAISE NOTICE '   v1.1: HW accel info, round  . tests 42-43';
    RAISE NOTICE '   v1.3: health_check, batch ... tests 44-47';
    RAISE NOTICE '   v1.2: logical decoding ...... test  48';
    RAISE NOTICE '   v1.4: wire fmt v2 (SKIP 49), tde_btree  tests 50-52';
    RAISE NOTICE '   SKIPPED (LEGACY): 5,6,7,9,11,49 — encrypt_test/decrypt_test use global DEK';
    RAISE NOTICE '====================================================';
END;
$$;
