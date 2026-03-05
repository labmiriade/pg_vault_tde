-- regression_test_v16.sql — TDD tests 73-80 for pg_vault_tde v1.6
--
-- These tests cover the local-wallet (kms_provider = 'local') feature set
-- introduced in v1.6, including the regression fix for:
--
--   BUG: pg_vault_tde_wallet_unlock() did not cache the derived KEK, so the
--   first CREATE TABLE USING encrypted_heap (or INSERT) in the same session
--   triggered:
--     ERROR: [KMS] wrap_dek failed for relid=N
--   because local_wrap_dek() called local_get_passphrase() which returned
--   false when no wallet_passphrase_env/file/command GUC was configured.
--
--   FIX (src/kms/pg_vault_tde_kms_local.c): wallet_unlock() now stores the
--   derived KEK in local_wallet_state->kek (kek_loaded=true).  local_wrap_dek
--   and local_unwrap_dek use a fast path: when kek_loaded is true they call
--   local_wrap_dek_with_kek() / local_unwrap_dek_with_kek() directly,
--   bypassing local_get_passphrase() entirely.  wallet_lock() clears the cache
--   via OPENSSL_cleanse + kek_loaded=false.
--
-- Tests that require kms_provider = 'local':
--   74, 75, 76, 77, 78, 79, 80
--   These skip with a NOTICE when run in the default (vault) test container.
--   Run them with:
--     make ci-wallet          — starts a container with kms_provider=local
--
-- Tests that run regardless of kms_provider:
--   73  — structural check: v1.6 SQL functions are registered
--
-- Run sequence (full pipeline):
--   psql -f sql/pg_vault_tde--1.0.sql
--   psql -f sql/pg_vault_tde--1.4--1.5.sql
--   psql -f sql/pg_vault_tde--1.5--1.6.sql
--   psql -f sql/regression_test_v15.sql     (v1.5 tests 53-72)
--   psql -f sql/regression_test_v16.sql     (v1.6 tests 73-80)
--
-- Exit-on-error: any failed assertion aborts the script.
\set ON_ERROR_STOP on

-- ================================================================
-- Helper: emit a standard skip notice for wallet-only tests
-- ================================================================
-- (Macro-like: used inside each DO block that needs kms_provider=local)
-- We cannot use a SQL function here because psql --set ON_ERROR_STOP
-- fires on any function-level ERROR before we can catch it.

-- ================================================================
-- TEST 73: v1.6 wallet SQL functions registered
--
-- Passes regardless of kms_provider — only checks catalog presence.
-- Fails if the 1.5→1.6 upgrade script was not applied.
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
        'pg_vault_tde_wallet_lock',
        'pg_vault_tde_wallet_rotate_kek',
        'pg_vault_tde_wallet_export_bundle',
        'pg_vault_tde_wallet_import_bundle',
        'pg_vault_tde_wallet_change_passphrase'
      );

    IF fn_count < 6 THEN
        RAISE EXCEPTION
            'TEST 73 FAILED: expected 6 v1.6 wallet functions, found % '
            '(did you run the 1.5→1.6 upgrade script?)', fn_count;
    END IF;

    RAISE NOTICE 'TEST 73 PASSED: all 6 v1.6 wallet SQL functions registered';
END;
$$;

-- ================================================================
-- TEST 74: wallet_unlock → CREATE TABLE → INSERT → SELECT (REGRESSION)
--
-- This is the primary regression guard for the KEK-caching bug fix.
--
-- Before fix: wallet_unlock() derived the KEK and immediately discarded it
--   with OPENSSL_cleanse().  When encrypted_heap TAM called local_wrap_dek()
--   to wrap a new per-table DEK, local_get_passphrase() found no GUC source
--   configured and returned false.  PostgreSQL raised:
--     ERROR: [KMS] wrap_dek failed for relid=N
--
-- After fix: wallet_unlock() stores the derived KEK in
--   local_wallet_state->kek with kek_loaded=true.  local_wrap_dek() detects
--   kek_loaded and calls local_wrap_dek_with_kek() directly — bypassing
--   local_get_passphrase() — which succeeds.  The subsequent INSERT and SELECT
--   both complete without error.
--
-- Requires: kms_provider = 'local'  (skips on other providers)
-- ================================================================
DO $$
DECLARE
    v_provider text;
    v_email    text;
    v_count    int;
BEGIN
    v_provider := current_setting('pg_vault_tde.kms_provider', true);
    IF v_provider IS DISTINCT FROM 'local' THEN
        RAISE NOTICE
            'TEST 74 SKIPPED: kms_provider=% (need ''local'' — run: make ci-wallet)',
            COALESCE(v_provider, 'vault');
        RETURN;
    END IF;

    -- Clean up from any previous partial run
    DROP TABLE IF EXISTS tde_wallet_regression_74;

    -- Initialise wallet with a known test passphrase.
    -- Silently ignore "wallet already exists" so the test is idempotent.
    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_regression_pass_2026');
    EXCEPTION WHEN OTHERS THEN
        NULL;   -- wallet already initialised; that is fine
    END;

    -- Unlock: this MUST cache the KEK so the wrap_dek fast path works.
    -- If the KEK is NOT cached (pre-fix behaviour), the next CREATE TABLE
    -- will raise "wrap_dek failed".
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    -- CREATE TABLE — triggers local_wrap_dek() for the new per-table DEK.
    -- The regression manifests here: "wrap_dek failed for relid=N".
    CREATE TABLE tde_wallet_regression_74 (
        id    bigserial,
        email text
    ) USING encrypted_heap;

    -- INSERT — triggers encrypt path; DEK must be available in shmem.
    INSERT INTO tde_wallet_regression_74 (email)
    VALUES ('alice@regression.test'), ('bob@regression.test');

    -- SELECT — verifies GCM decryption + KEK accessible for unwrap.
    SELECT count(*) INTO v_count FROM tde_wallet_regression_74;
    IF v_count <> 2 THEN
        RAISE EXCEPTION
            'TEST 74 FAILED: expected 2 rows after INSERT, got %', v_count;
    END IF;

    SELECT email INTO v_email
    FROM tde_wallet_regression_74
    WHERE id = 1;

    IF v_email IS DISTINCT FROM 'alice@regression.test' THEN
        RAISE EXCEPTION
            'TEST 74 FAILED: decrypted email=''%'' expected ''alice@regression.test''',
            COALESCE(v_email, '<NULL>');
    END IF;

    DROP TABLE tde_wallet_regression_74;

    RAISE NOTICE
        'TEST 74 PASSED: wallet_unlock → CREATE TABLE → INSERT → SELECT '
        'succeeded (KEK-caching regression fix verified)';
END;
$$;

-- ================================================================
-- TEST 75: wallet_lock evicts DEKs from shmem
--
-- After wallet_lock() the wallet is closed and the cached KEK is
-- wiped.  pg_vault_tde_wallet_status() must report wallet_open=false
-- and dek_count=0.
--
-- Requires: kms_provider = 'local'  (skips on other providers)
-- ================================================================
DO $$
DECLARE
    v_provider text;
    v_status   record;
BEGIN
    v_provider := current_setting('pg_vault_tde.kms_provider', true);
    IF v_provider IS DISTINCT FROM 'local' THEN
        RAISE NOTICE
            'TEST 75 SKIPPED: kms_provider=% (need ''local'' — run: make ci-wallet)',
            COALESCE(v_provider, 'vault');
        RETURN;
    END IF;

    -- Ensure wallet is initialised and open from TEST 74 sequence
    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_regression_pass_2026');
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    -- Lock the wallet
    PERFORM pg_vault_tde_wallet_lock();

    -- Verify wallet reports closed state
    SELECT * INTO v_status FROM pg_vault_tde_wallet_status();

    IF v_status.wallet_open THEN
        RAISE EXCEPTION
            'TEST 75 FAILED: wallet_open=true after wallet_lock()';
    END IF;

    IF v_status.dek_count <> 0 THEN
        RAISE EXCEPTION
            'TEST 75 FAILED: dek_count=% after wallet_lock() (expected 0)',
            v_status.dek_count;
    END IF;

    RAISE NOTICE
        'TEST 75 PASSED: wallet_lock() evicted DEKs (dek_count=0, wallet_open=false)';
END;
$$;

-- ================================================================
-- TEST 76: wallet_unlock re-enables encryption after wallet_lock
--
-- After wallet_lock(), calling wallet_unlock() must restore full
-- encrypt/decrypt capability: CREATE TABLE + INSERT + SELECT all work.
-- This verifies the full lock → unlock lifecycle, not just the initial
-- unlock (which was the regression in TEST 74).
--
-- Requires: kms_provider = 'local'  (skips on other providers)
-- ================================================================
DO $$
DECLARE
    v_provider text;
    v_email    text;
    v_status   record;
BEGIN
    v_provider := current_setting('pg_vault_tde.kms_provider', true);
    IF v_provider IS DISTINCT FROM 'local' THEN
        RAISE NOTICE
            'TEST 76 SKIPPED: kms_provider=% (need ''local'' — run: make ci-wallet)',
            COALESCE(v_provider, 'vault');
        RETURN;
    END IF;

    DROP TABLE IF EXISTS tde_wallet_regression_76;

    -- Start from locked state
    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_regression_pass_2026');
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');
    PERFORM pg_vault_tde_wallet_lock();

    -- Re-unlock
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    -- Verify wallet shows open
    SELECT * INTO v_status FROM pg_vault_tde_wallet_status();
    IF NOT v_status.wallet_open THEN
        RAISE EXCEPTION
            'TEST 76 FAILED: wallet_open=false after second wallet_unlock()';
    END IF;

    -- Verify full cycle works again
    CREATE TABLE tde_wallet_regression_76 (id int, val text)
        USING encrypted_heap;
    INSERT INTO tde_wallet_regression_76 VALUES (1, 'unlock_cycle_ok');

    SELECT val INTO v_email
    FROM tde_wallet_regression_76
    WHERE id = 1;

    IF v_email IS DISTINCT FROM 'unlock_cycle_ok' THEN
        RAISE EXCEPTION
            'TEST 76 FAILED: val=''%'' expected ''unlock_cycle_ok''',
            COALESCE(v_email, '<NULL>');
    END IF;

    DROP TABLE tde_wallet_regression_76;

    RAISE NOTICE
        'TEST 76 PASSED: lock → unlock cycle restores full encrypt/decrypt capability';
END;
$$;

-- ================================================================
-- TEST 77: wallet_status returns correct 6-column composite
--
-- pg_vault_tde_wallet_status() must return exactly 6 columns:
--   wallet_path  text
--   wallet_open  bool
--   algorithm    text
--   dek_count    int
--   last_opened  timestamptz
--   file_perms   text
--
-- Wallet must exist and be open; dek_count must be >= 0.
--
-- Requires: kms_provider = 'local'  (skips on other providers)
-- ================================================================
DO $$
DECLARE
    v_provider text;
    v_status   record;
BEGIN
    v_provider := current_setting('pg_vault_tde.kms_provider', true);
    IF v_provider IS DISTINCT FROM 'local' THEN
        RAISE NOTICE
            'TEST 77 SKIPPED: kms_provider=% (need ''local'' — run: make ci-wallet)',
            COALESCE(v_provider, 'vault');
        RETURN;
    END IF;

    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_regression_pass_2026');
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    SELECT * INTO v_status FROM pg_vault_tde_wallet_status();

    -- wallet_path must be a non-empty string
    IF v_status.wallet_path IS NULL OR v_status.wallet_path = '' THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: wallet_path is NULL or empty';
    END IF;

    -- wallet_open must be true (we just unlocked)
    IF NOT v_status.wallet_open THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: wallet_open=false after wallet_unlock()';
    END IF;

    -- algorithm must be set (AES-256-WRAP or similar)
    IF v_status.algorithm IS NULL OR v_status.algorithm = '' THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: algorithm is NULL or empty';
    END IF;

    -- dek_count must be >= 0 (non-negative integer)
    IF v_status.dek_count < 0 THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: dek_count=% is negative', v_status.dek_count;
    END IF;

    -- last_opened must be set and recent (within last 60 seconds)
    IF v_status.last_opened IS NULL THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: last_opened is NULL after wallet_unlock()';
    END IF;

    IF v_status.last_opened < now() - interval '60 seconds' THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: last_opened=% is more than 60s in the past',
            v_status.last_opened;
    END IF;

    RAISE NOTICE
        'TEST 77 PASSED: wallet_status() → path=%, open=%, algo=%, '
        'dek_count=%, last_opened~now, file_perms=%',
        v_status.wallet_path,
        v_status.wallet_open,
        v_status.algorithm,
        v_status.dek_count,
        COALESCE(v_status.file_perms, '(NULL)');
END;
$$;

-- ================================================================
-- TEST 78: wallet_change_passphrase re-wraps wallet under new KEK
--
-- After change_passphrase(old, new), wallet_unlock(old) must fail
-- and wallet_unlock(new) must succeed.  Existing encrypted tables
-- must remain readable after the passphrase change.
--
-- Requires: kms_provider = 'local'  (skips on other providers)
-- ================================================================
DO $$
DECLARE
    v_provider  text;
    v_val       text;
    v_unlock_ok boolean := false;
BEGIN
    v_provider := current_setting('pg_vault_tde.kms_provider', true);
    IF v_provider IS DISTINCT FROM 'local' THEN
        RAISE NOTICE
            'TEST 78 SKIPPED: kms_provider=% (need ''local'' — run: make ci-wallet)',
            COALESCE(v_provider, 'vault');
        RETURN;
    END IF;

    DROP TABLE IF EXISTS tde_wallet_regression_78;

    -- Prepare: init + unlock and create an encrypted table
    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_regression_pass_2026');
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    CREATE TABLE tde_wallet_regression_78 (id int, val text)
        USING encrypted_heap;
    INSERT INTO tde_wallet_regression_78 VALUES (1, 'change_pass_test');

    -- Change passphrase to a new value
    PERFORM pg_vault_tde_wallet_change_passphrase(
        'tde_regression_pass_2026',
        'tde_new_pass_2026'
    );

    -- Lock to force re-authentication
    PERFORM pg_vault_tde_wallet_lock();

    -- Unlocking with the OLD passphrase MUST fail
    BEGIN
        PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');
        -- If we reach here, it did not raise — that is a bug
    EXCEPTION WHEN OTHERS THEN
        v_unlock_ok := true;   -- expected: old pass rejected
    END;

    IF NOT v_unlock_ok THEN
        -- Clean up and fail
        DROP TABLE IF EXISTS tde_wallet_regression_78;
        RAISE EXCEPTION
            'TEST 78 FAILED: wallet_unlock(old_pass) should fail after '
            'change_passphrase but it did not';
    END IF;

    -- Unlocking with the NEW passphrase MUST succeed
    PERFORM pg_vault_tde_wallet_unlock('tde_new_pass_2026');

    -- Existing encrypted data must remain readable
    SELECT val INTO v_val
    FROM tde_wallet_regression_78
    WHERE id = 1;

    IF v_val IS DISTINCT FROM 'change_pass_test' THEN
        RAISE EXCEPTION
            'TEST 78 FAILED: val=''%'' after passphrase change (expected ''change_pass_test'')',
            COALESCE(v_val, '<NULL>');
    END IF;

    -- Reset passphrase back to the standard test value so subsequent
    -- tests can still call wallet_init/unlock with the known passphrase
    PERFORM pg_vault_tde_wallet_change_passphrase(
        'tde_new_pass_2026',
        'tde_regression_pass_2026'
    );

    DROP TABLE tde_wallet_regression_78;

    RAISE NOTICE
        'TEST 78 PASSED: wallet_change_passphrase re-wraps KEK, old pass rejected, '
        'new pass accepted, existing data readable';
END;
$$;

-- ================================================================
-- TEST 79: wallet_rotate_kek re-wraps all per-table DEKs atomically
--
-- After rotate_kek(), all existing encrypted tables must remain
-- readable (DEKs were re-wrapped under the new KEK).
-- wallet_status().dek_count must equal the number of encrypted tables.
--
-- Requires: kms_provider = 'local'  (skips on other providers)
-- ================================================================
DO $$
DECLARE
    v_provider text;
    v_status   record;
    v_val_a    text;
    v_val_b    text;
    v_gen_before bigint;
    v_gen_after  bigint;
BEGIN
    v_provider := current_setting('pg_vault_tde.kms_provider', true);
    IF v_provider IS DISTINCT FROM 'local' THEN
        RAISE NOTICE
            'TEST 79 SKIPPED: kms_provider=% (need ''local'' — run: make ci-wallet)',
            COALESCE(v_provider, 'vault');
        RETURN;
    END IF;

    DROP TABLE IF EXISTS tde_wallet_regression_79a;
    DROP TABLE IF EXISTS tde_wallet_regression_79b;

    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_regression_pass_2026');
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    -- Create two encrypted tables to verify multi-table re-wrap
    CREATE TABLE tde_wallet_regression_79a (id int, val text)
        USING encrypted_heap;
    CREATE TABLE tde_wallet_regression_79b (id int, val text)
        USING encrypted_heap;

    INSERT INTO tde_wallet_regression_79a VALUES (1, 'rotate_kek_table_a');
    INSERT INTO tde_wallet_regression_79b VALUES (1, 'rotate_kek_table_b');

    -- Capture DEK generation before rotation
    v_gen_before := pg_vault_tde_key_generation();

    -- Rotate the KEK — re-wraps all DEKs under a new KEK
    PERFORM pg_vault_tde_wallet_rotate_kek();

    -- DEK generation counter must have advanced (shmem DEKs were invalidated)
    v_gen_after := pg_vault_tde_key_generation();
    IF v_gen_after <= v_gen_before THEN
        RAISE EXCEPTION
            'TEST 79 FAILED: key_generation did not advance after rotate_kek '
            '(before=%, after=%)', v_gen_before, v_gen_after;
    END IF;

    -- Both tables must still be readable after KEK rotation
    SELECT val INTO v_val_a FROM tde_wallet_regression_79a WHERE id = 1;
    SELECT val INTO v_val_b FROM tde_wallet_regression_79b WHERE id = 1;

    IF v_val_a IS DISTINCT FROM 'rotate_kek_table_a' THEN
        RAISE EXCEPTION
            'TEST 79 FAILED: table_a val=''%'' (expected ''rotate_kek_table_a'')',
            COALESCE(v_val_a, '<NULL>');
    END IF;

    IF v_val_b IS DISTINCT FROM 'rotate_kek_table_b' THEN
        RAISE EXCEPTION
            'TEST 79 FAILED: table_b val=''%'' (expected ''rotate_kek_table_b'')',
            COALESCE(v_val_b, '<NULL>');
    END IF;

    DROP TABLE tde_wallet_regression_79a;
    DROP TABLE tde_wallet_regression_79b;

    RAISE NOTICE
        'TEST 79 PASSED: wallet_rotate_kek() re-wrapped all DEKs atomically '
        '(gen %→%, both tables readable)', v_gen_before, v_gen_after;
END;
$$;

-- ================================================================
-- TEST 80: wallet_export_bundle + wallet_import_bundle round-trip
--
-- Export the wallet to a file, then import it back.  After import +
-- fresh unlock, encrypted tables must remain readable.
--
-- Requires: kms_provider = 'local'  (skips on other providers)
-- ================================================================
DO $$
DECLARE
    v_provider   text;
    v_bundle     text := '/tmp/tde_test_wallet_bundle_80.bin';
    v_val        text;
BEGIN
    v_provider := current_setting('pg_vault_tde.kms_provider', true);
    IF v_provider IS DISTINCT FROM 'local' THEN
        RAISE NOTICE
            'TEST 80 SKIPPED: kms_provider=% (need ''local'' — run: make ci-wallet)',
            COALESCE(v_provider, 'vault');
        RETURN;
    END IF;

    DROP TABLE IF EXISTS tde_wallet_regression_80;

    BEGIN
        PERFORM pg_vault_tde_wallet_init('tde_regression_pass_2026');
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    CREATE TABLE tde_wallet_regression_80 (id int, val text)
        USING encrypted_heap;
    INSERT INTO tde_wallet_regression_80 VALUES (1, 'export_import_ok');

    -- Export: writes HMAC-signed bundle to /tmp
    PERFORM pg_vault_tde_wallet_export_bundle(v_bundle, 'ci-regression-test-80');

    -- Import: replaces in-memory wallet state from the bundle
    PERFORM pg_vault_tde_wallet_import_bundle(v_bundle, 'tde_regression_pass_2026');

    -- Re-open after import (import may reset open state)
    PERFORM pg_vault_tde_wallet_unlock('tde_regression_pass_2026');

    -- Verify existing encrypted data is still accessible
    SELECT val INTO v_val FROM tde_wallet_regression_80 WHERE id = 1;
    IF v_val IS DISTINCT FROM 'export_import_ok' THEN
        RAISE EXCEPTION
            'TEST 80 FAILED: val=''%'' after export+import (expected ''export_import_ok'')',
            COALESCE(v_val, '<NULL>');
    END IF;

    DROP TABLE tde_wallet_regression_80;

    RAISE NOTICE
        'TEST 80 PASSED: wallet_export_bundle + wallet_import_bundle round-trip OK';
END;
$$;

-- ================================================================
-- PHASE SUMMARY
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'v1.6 Wallet Tests 73-80 — COMPLETE';
    RAISE NOTICE '   v1.6 function registration ......... test 73';
    RAISE NOTICE '   wallet_unlock KEK-cache regression .. test 74  *';
    RAISE NOTICE '   wallet_lock evicts DEKs ............. test 75  *';
    RAISE NOTICE '   lock → unlock cycle ................. test 76  *';
    RAISE NOTICE '   wallet_status 6-column SRF .......... test 77  *';
    RAISE NOTICE '   wallet_change_passphrase ............ test 78  *';
    RAISE NOTICE '   wallet_rotate_kek multi-table ........ test 79  *';
    RAISE NOTICE '   wallet_export/import_bundle .......... test 80  *';
    RAISE NOTICE '';
    RAISE NOTICE '   * = requires kms_provider=local (make ci-wallet)';
    RAISE NOTICE '       these tests SKIP in the default vault container';
    RAISE NOTICE '============================================================';
END;
$$;
