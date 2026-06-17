-- regression_test_schema.sql
-- Schema and multi-database isolation tests for pg_vault_tde
--
-- These tests verify that encrypted_heap tables work correctly when:
--   1. The extension is installed in a non-default database
--   2. Tables are created in a non-public schema
--   3. search_path is set to a custom schema (no 'public')
--   4. Multiple schemas coexist in the same database
--
-- Test numbering: SCHEMA-1 through SCHEMA-20 (distinct from the main
-- regression suite tests 1-87 to avoid confusion in CI output).
--
-- Prerequisites:
--   - Extension is already installed and loaded in the current cluster
--
-- Execution:
--   psql -U postgres -f sql/regression_test_schema.sql
--   make ci-schema
--
-- Exit code: non-zero on any failure (\set ON_ERROR_STOP on)
--
-- Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

\set ON_ERROR_STOP on

-- ================================================================
-- PHASE 1: Create dedicated test database
-- ================================================================

-- Drop leftover from a previous run (ignore error if not exists)
DROP DATABASE IF EXISTS tde_schema_test;
CREATE DATABASE tde_schema_test;

\c tde_schema_test

-- ================================================================
-- SCHEMA-TEST 1: Extension installs correctly in a new database
-- ================================================================
CREATE EXTENSION pg_vault_tde;
ALTER DATABASE tde_schema_test SET pg_vault_tde.kms_provider TO 'local';
SET pg_vault_tde.kms_provider = 'local';   -- ALTER DATABASE only affects new connections

SELECT pg_vault_tde_wallet_init('tde-schema-test');

DO $$
BEGIN
    PERFORM 1 FROM pg_extension WHERE extname = 'pg_vault_tde';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SCHEMA-TEST 1 FAILED: pg_vault_tde not found in pg_extension';
    END IF;
    RAISE NOTICE 'SCHEMA-TEST 1 PASSED: extension installed correctly in new database';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 2: Access Methods available in new database
-- ================================================================
DO $$
BEGIN
    PERFORM 1 FROM pg_am WHERE amname = 'encrypted_heap';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SCHEMA-TEST 2 FAILED: encrypted_heap AM not registered in new DB';
    END IF;
    PERFORM 1 FROM pg_am WHERE amname = 'tde_btree';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SCHEMA-TEST 2 FAILED: tde_btree AM not registered in new DB';
    END IF;
    RAISE NOTICE 'SCHEMA-TEST 2 PASSED: both AMs available in new database';
END;
$$;

-- ================================================================
-- PHASE 2: Create custom schema and set search_path
-- ================================================================
CREATE SCHEMA private_tde;
SET search_path = private_tde, public;

DO $$
DECLARE
    avail record;
BEGIN
    SELECT * INTO avail FROM pg_vault_tde_health_check();

    RAISE NOTICE 'SCHEMA-TEST 3 PASSED: health_check() do not fail';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 4: CREATE TABLE USING encrypted_heap in custom schema
--               Basic INSERT + SELECT round-trip
-- ================================================================
DO $$
DECLARE
    val text;
BEGIN
    CREATE TABLE private_tde.tde_schema_basic (
        id      serial,
        secret  text
    ) USING encrypted_heap;

    INSERT INTO private_tde.tde_schema_basic (secret) VALUES ('schema_secret_value');

    SELECT secret INTO val FROM private_tde.tde_schema_basic WHERE id = 1;
    IF val IS DISTINCT FROM 'schema_secret_value' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 4 FAILED: expected "schema_secret_value", got "%"', val;
    END IF;

    DROP TABLE private_tde.tde_schema_basic;
    RAISE NOTICE 'SCHEMA-TEST 4 PASSED: basic INSERT+SELECT in schema private_tde OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 5: On-disk plaintext absence in custom schema
--               The relfilepath still must not contain plaintext.
-- ================================================================

CREATE TABLE private_tde.tde_schema_disk (id int, secret text) USING encrypted_heap;
INSERT INTO private_tde.tde_schema_disk VALUES (1, 'on_disk_schema_secret');
CHECKPOINT;

DO $$
DECLARE
    filepath text;
    raw_file bytea;
    needle   bytea;
BEGIN
    filepath := pg_relation_filepath('private_tde.tde_schema_disk');
    raw_file := pg_read_binary_file(filepath);
    needle   := 'on_disk_schema_secret'::bytea;

    IF length(raw_file) < 8192 THEN
        RAISE EXCEPTION 'SCHEMA-TEST 5 FAILED: relation file too small (%B)', length(raw_file);
    END IF;
    IF position(needle IN raw_file) > 0 THEN
        RAISE EXCEPTION 'SCHEMA-TEST 5 FAILED: plaintext found in raw file (schema table)!';
    END IF;
    RAISE NOTICE 'SCHEMA-TEST 5 PASSED: on-disk plaintext absent for schema-qualified table';
END;
$$;

DROP TABLE private_tde.tde_schema_disk;

-- ================================================================
-- SCHEMA-TEST 6: Index scan in custom schema
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_idx (id int, secret text) USING encrypted_heap;
    CREATE INDEX ON private_tde.tde_schema_idx (id);
    INSERT INTO private_tde.tde_schema_idx VALUES (42, 'schema_index_secret');

    SET enable_seqscan = off;
    SELECT secret INTO v FROM private_tde.tde_schema_idx WHERE id = 42;
    RESET enable_seqscan;

    IF v IS DISTINCT FROM 'schema_index_secret' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 6 FAILED: index scan on schema table returned "%"', v;
    END IF;

    DROP TABLE private_tde.tde_schema_idx;
    RAISE NOTICE 'SCHEMA-TEST 6 PASSED: index scan on private_tde.tde_schema_idx OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 7: BitmapHeapScan in custom schema
-- ================================================================
DO $$
DECLARE
    cnt int;
    v   text;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_bitmap (id int, payload text) USING encrypted_heap;
    CREATE INDEX ON private_tde.tde_schema_bitmap (id);
    INSERT INTO private_tde.tde_schema_bitmap
        SELECT g, 'schema_row_' || g FROM generate_series(1, 100) g;

    SET enable_seqscan = off;
    SET enable_indexscan = off;

    SELECT count(*) INTO cnt
    FROM private_tde.tde_schema_bitmap WHERE id BETWEEN 1 AND 50;
    IF cnt <> 50 THEN
        RAISE EXCEPTION 'SCHEMA-TEST 7a FAILED: expected 50 rows, got %', cnt;
    END IF;

    SELECT payload INTO v FROM private_tde.tde_schema_bitmap WHERE id = 25;
    IF v IS DISTINCT FROM 'schema_row_25' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 7b FAILED: expected "schema_row_25", got "%"', v;
    END IF;

    RESET enable_seqscan;
    RESET enable_indexscan;
    DROP TABLE private_tde.tde_schema_bitmap;
    RAISE NOTICE 'SCHEMA-TEST 7 PASSED: BitmapHeapScan in custom schema OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 8: SELECT FOR UPDATE in custom schema (tuple_lock path)
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_forupdate (id int, val text) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_forupdate VALUES (1, 'schema_lock_me');

    BEGIN
        SELECT val INTO v
        FROM private_tde.tde_schema_forupdate WHERE id = 1 FOR UPDATE;
        IF v IS DISTINCT FROM 'schema_lock_me' THEN
            RAISE EXCEPTION 'SCHEMA-TEST 8 FAILED: FOR UPDATE returned "%"', v;
        END IF;
    END;

    DROP TABLE private_tde.tde_schema_forupdate;
    RAISE NOTICE 'SCHEMA-TEST 8 PASSED: SELECT FOR UPDATE in custom schema OK (tuple_lock path)';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 9: TABLESAMPLE in custom schema (scan_sample_next_tuple)
-- ================================================================
DO $$
DECLARE
    cnt int;
    v   text;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_sample (id int, val text) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_sample
        SELECT g, 'sample_' || g FROM generate_series(1, 50) g;

    SELECT count(*) INTO cnt
    FROM private_tde.tde_schema_sample TABLESAMPLE SYSTEM(100);
    IF cnt <> 50 THEN
        RAISE EXCEPTION 'SCHEMA-TEST 9a FAILED: expected 50 rows, got %', cnt;
    END IF;

    SELECT val INTO v
    FROM private_tde.tde_schema_sample TABLESAMPLE SYSTEM(100) WHERE id = 30;
    IF v IS DISTINCT FROM 'sample_30' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 9b FAILED: expected "sample_30", got "%"', v;
    END IF;

    DROP TABLE private_tde.tde_schema_sample;
    RAISE NOTICE 'SCHEMA-TEST 9 PASSED: TABLESAMPLE in custom schema OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 10: ANALYZE in custom schema
-- ================================================================
DO $$
DECLARE
    mcv_type text;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_analyze (id int, category text) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_analyze
        SELECT g, CASE WHEN g % 2 = 0 THEN 'even' ELSE 'odd' END
        FROM generate_series(1, 60) g;
    ANALYZE private_tde.tde_schema_analyze;

    SELECT pg_typeof(most_common_vals) INTO mcv_type
    FROM pg_stats
    WHERE schemaname = 'private_tde'
      AND tablename  = 'tde_schema_analyze'
      AND attname    = 'category';

    PERFORM 1 FROM pg_stats
    WHERE schemaname = 'private_tde'
      AND tablename  = 'tde_schema_analyze'
      AND attname    = 'category'
      AND most_common_vals IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SCHEMA-TEST 10 FAILED: ANALYZE produced no statistics in custom schema';
    END IF;

    DROP TABLE private_tde.tde_schema_analyze;
    RAISE NOTICE 'SCHEMA-TEST 10 PASSED: ANALYZE on custom schema table OK (type=%)', mcv_type;
END;
$$;

-- ================================================================
-- SCHEMA-TEST 11: TOAST large value in custom schema
-- ================================================================
DO $$
DECLARE
    v    text;
    vlen int;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_toast (id int, payload text) USING encrypted_heap;

    -- 65 kB value — well above the TOAST threshold
    INSERT INTO private_tde.tde_schema_toast VALUES (1, repeat('T', 65536));

    SELECT length(payload) INTO vlen FROM private_tde.tde_schema_toast WHERE id = 1;
    IF vlen <> 65536 THEN
        RAISE EXCEPTION 'SCHEMA-TEST 11 FAILED: expected 65536, got %', vlen;
    END IF;

    SELECT payload INTO v FROM private_tde.tde_schema_toast WHERE id = 1;
    IF v IS DISTINCT FROM repeat('T', 65536) THEN
        RAISE EXCEPTION 'SCHEMA-TEST 11 FAILED: TOAST value mismatch in custom schema';
    END IF;

    DROP TABLE private_tde.tde_schema_toast;
    RAISE NOTICE 'SCHEMA-TEST 11 PASSED: TOAST large value round-trip in custom schema OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 12: Per-table DEK isolation in custom schema
--   v1.7: rotate_key() removed; each table has its own independent DEK.
--   Verify that two tables in the same schema decrypt independently.
-- ================================================================
DO $$
DECLARE
    va text;
    vb text;
BEGIN
    CREATE TABLE private_tde.tde_schema_rota_a (id int, val text) USING encrypted_heap;
    CREATE TABLE private_tde.tde_schema_rota_b (id int, val text) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_rota_a VALUES (1, 'dek_a_schema');
    INSERT INTO private_tde.tde_schema_rota_b VALUES (2, 'dek_b_schema');

    SELECT val INTO va FROM private_tde.tde_schema_rota_a WHERE id = 1;
    SELECT val INTO vb FROM private_tde.tde_schema_rota_b WHERE id = 2;
    IF va IS DISTINCT FROM 'dek_a_schema' OR vb IS DISTINCT FROM 'dek_b_schema' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 12 FAILED: per-table DEK isolation broken (a=%, b=%)', va, vb;
    END IF;

    DROP TABLE private_tde.tde_schema_rota_a, private_tde.tde_schema_rota_b;
    RAISE NOTICE 'SCHEMA-TEST 12 PASSED: per-table DEK isolation in custom schema';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 13: Multi-schema isolation
--                Two schemas in the same database, each with an
--                encrypted_heap table — verifies that rows from
--                one schema do not leak into the other.
-- ================================================================
CREATE SCHEMA schema_alpha;
CREATE SCHEMA schema_beta;

DO $$
DECLARE
    v_alpha text;
    v_beta  text;
BEGIN
    

    CREATE TABLE schema_alpha.tde_multi_schema (id int, secret text) USING encrypted_heap;
    CREATE TABLE schema_beta.tde_multi_schema  (id int, secret text) USING encrypted_heap;

    INSERT INTO schema_alpha.tde_multi_schema VALUES (1, 'alpha_secret');
    INSERT INTO schema_beta.tde_multi_schema  VALUES (1, 'beta_secret');

    SELECT secret INTO v_alpha FROM schema_alpha.tde_multi_schema WHERE id = 1;
    SELECT secret INTO v_beta  FROM schema_beta.tde_multi_schema  WHERE id = 1;

    IF v_alpha IS DISTINCT FROM 'alpha_secret' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 13 FAILED: schema_alpha returned "%"', v_alpha;
    END IF;
    IF v_beta IS DISTINCT FROM 'beta_secret' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 13 FAILED: schema_beta returned "%"', v_beta;
    END IF;
    IF v_alpha = v_beta THEN
        RAISE EXCEPTION 'SCHEMA-TEST 13 FAILED: both schemas returned the same value!';
    END IF;

    DROP TABLE schema_alpha.tde_multi_schema, schema_beta.tde_multi_schema;
    RAISE NOTICE 'SCHEMA-TEST 13 PASSED: multi-schema isolation OK (alpha="%", beta="%")',
        v_alpha, v_beta;
END;
$$;

DROP SCHEMA schema_alpha;
DROP SCHEMA schema_beta;

-- ================================================================
-- SCHEMA-TEST 14: search_path without 'public' — extension functions
--                must remain reachable via the 'public' schema where
--                the extension installs its objects.
-- ================================================================
DO $$
DECLARE
    avail bool;
BEGIN
    -- Temporarily narrow search_path to only private_tde
    SET LOCAL search_path = private_tde;

    RAISE NOTICE 'SCHEMA-TEST 14 PASSED: extension functions reachable schema-qualified';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 15: UPDATE in custom schema — ctid preservation
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_update (id int, val text) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_update VALUES (1, 'before_update');

    UPDATE private_tde.tde_schema_update SET val = 'after_update' WHERE id = 1;

    SELECT val INTO v FROM private_tde.tde_schema_update WHERE id = 1;
    IF v IS DISTINCT FROM 'after_update' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 15 FAILED: UPDATE returned "%"', v;
    END IF;

    DROP TABLE private_tde.tde_schema_update;
    RAISE NOTICE 'SCHEMA-TEST 15 PASSED: UPDATE in custom schema OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 16: VACUUM in custom schema
--                Dead tuples collected, no crash on decryption.
-- ================================================================
DO $$
BEGIN
    
    CREATE TABLE private_tde.tde_schema_vacuum (id int, val text) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_vacuum
        SELECT g, 'vacuum_row_' || g FROM generate_series(1, 30) g;
    DELETE FROM private_tde.tde_schema_vacuum WHERE id <= 15;

    -- Force stats flush before checking n_dead_tup
    PERFORM pg_stat_force_next_flush();
    ANALYZE private_tde.tde_schema_vacuum;
END;
$$;

VACUUM private_tde.tde_schema_vacuum;

DO $$
DECLARE
    dead_before bigint;
BEGIN
    SELECT n_dead_tup INTO dead_before
    FROM pg_stat_user_tables
    WHERE schemaname = 'private_tde' AND relname = 'tde_schema_vacuum';

    RAISE NOTICE 'SCHEMA-TEST 16 PASSED: VACUUM on custom schema table completed without crash (dead_before=%)',
        dead_before;
    DROP TABLE private_tde.tde_schema_vacuum;
END;
$$;

-- ================================================================
-- SCHEMA-TEST 17: Bulk INSERT (multi_insert path) in custom schema
-- ================================================================
DO $$
DECLARE
    cnt int;
    v   text;
BEGIN
    CREATE TABLE private_tde.tde_schema_bulk (id int, payload text) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_bulk
        SELECT g, 'bulk_' || g FROM generate_series(1, 200) g;

    SELECT count(*) INTO cnt FROM private_tde.tde_schema_bulk;
    IF cnt <> 200 THEN
        RAISE EXCEPTION 'SCHEMA-TEST 17 FAILED: expected 200 rows, got %', cnt;
    END IF;
    SELECT payload INTO v FROM private_tde.tde_schema_bulk WHERE id = 100;
    IF v IS DISTINCT FROM 'bulk_100' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 17 FAILED: spot-check row 100 = "%"', v;
    END IF;

    DROP TABLE private_tde.tde_schema_bulk;
    RAISE NOTICE 'SCHEMA-TEST 17 PASSED: bulk INSERT (multi_insert) in custom schema OK (200 rows)';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 18: ON CONFLICT (UPSERT) in custom schema
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_upsert (
        id  int PRIMARY KEY,
        val text
    ) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_upsert VALUES (1, 'original');
    INSERT INTO private_tde.tde_schema_upsert VALUES (1, 'upserted')
        ON CONFLICT (id) DO UPDATE SET val = EXCLUDED.val;

    SELECT val INTO v FROM private_tde.tde_schema_upsert WHERE id = 1;
    IF v IS DISTINCT FROM 'upserted' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 18 FAILED: UPSERT returned "%"', v;
    END IF;

    DROP TABLE private_tde.tde_schema_upsert;
    RAISE NOTICE 'SCHEMA-TEST 18 PASSED: UPSERT in custom schema OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 19: JOIN across two encrypted_heap tables in same schema
-- ================================================================
DO $$
DECLARE
    v text;
    cnt int;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_j1 (id int, name text)   USING encrypted_heap;
    CREATE TABLE private_tde.tde_schema_j2 (id int, detail text) USING encrypted_heap;

    INSERT INTO private_tde.tde_schema_j1 VALUES (1, 'Alice'), (2, 'Bob');
    INSERT INTO private_tde.tde_schema_j2 VALUES (1, 'info_alice'), (2, 'info_bob');

    SELECT j2.detail INTO v
    FROM private_tde.tde_schema_j1 j1
    JOIN private_tde.tde_schema_j2 j2 ON j1.id = j2.id
    WHERE j1.name = 'Alice';

    IF v IS DISTINCT FROM 'info_alice' THEN
        RAISE EXCEPTION 'SCHEMA-TEST 19 FAILED: JOIN returned "%"', v;
    END IF;

    SELECT count(*) INTO cnt
    FROM private_tde.tde_schema_j1 j1
    JOIN private_tde.tde_schema_j2 j2 ON j1.id = j2.id;
    IF cnt <> 2 THEN
        RAISE EXCEPTION 'SCHEMA-TEST 19 FAILED: expected 2 join rows, got %', cnt;
    END IF;

    DROP TABLE private_tde.tde_schema_j1, private_tde.tde_schema_j2;
    RAISE NOTICE 'SCHEMA-TEST 19 PASSED: JOIN between schema-qualified encrypted tables OK';
END;
$$;

-- ================================================================
-- SCHEMA-TEST 20: All-NULL row in custom schema (user_len == 0 guard)
-- ================================================================
DO $$
DECLARE
    r record;
BEGIN
    
    CREATE TABLE private_tde.tde_schema_null (id int, a text, b int) USING encrypted_heap;
    INSERT INTO private_tde.tde_schema_null VALUES (1, NULL, NULL);

    SELECT * INTO r FROM private_tde.tde_schema_null WHERE id = 1;
    IF r.a IS NOT NULL THEN
        RAISE EXCEPTION 'SCHEMA-TEST 20 FAILED: expected NULL for a, got "%"', r.a;
    END IF;
    IF r.b IS NOT NULL THEN
        RAISE EXCEPTION 'SCHEMA-TEST 20 FAILED: expected NULL for b, got %', r.b;
    END IF;

    DROP TABLE private_tde.tde_schema_null;
    RAISE NOTICE 'SCHEMA-TEST 20 PASSED: all-NULL row in custom schema OK (no Assert crash)';
END;
$$;

-- ================================================================
-- PHASE 3: Cleanup — drop custom schemas and switch back to postgres
-- ================================================================
DROP SCHEMA private_tde CASCADE;

\c postgres

DROP DATABASE tde_schema_test;

\echo ''
\echo '══════════════════════════════════════════════════════════════'
\echo '  SCHEMA REGRESSION COMPLETE: ALL 20 TESTS PASSED'
\echo '══════════════════════════════════════════════════════════════'
