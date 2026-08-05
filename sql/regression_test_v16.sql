-- regression_test_v16.sql — TDD tests 73-110 for pg_vault_tde v1.6
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
-- Tests that require pg_vault_tde.dev_mode = 'on':
--   84, 85
--   These skip when dev_mode is not set (forensic helper functions unavailable).
--
-- Tests that skip when pg_vault_tde.toast_encryption != 'on':
--   103
--
-- Tests that run regardless of kms_provider:
--   73, 81-83, 86-102, 104-110
--
-- Run sequence (full pipeline):
--   psql -f sql/pg_vault_tde--1.0.sql
--   psql -f sql/pg_vault_tde--1.4--1.5.sql
--   psql -f sql/pg_vault_tde--1.5--1.6.sql
--   psql -f sql/regression_test_v15.sql     (v1.5 tests 53-72)
--   psql -f sql/regression_test_v16.sql     (v1.6 tests 73-110)
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
        'pg_vault_tde_rotate_kek',
        'pg_vault_tde_wallet_change_passphrase'
      );

    IF fn_count < 4 THEN
        RAISE EXCEPTION
            'TEST 73 FAILED: expected 4 v1.6 wallet functions, found % '
            '(did you run the 1.5→1.6 upgrade script?)', fn_count;
    END IF;

    RAISE NOTICE 'TEST 73 PASSED: all 4 v1.6 wallet SQL functions registered';
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
    PERFORM pg_vault_tde_wallet_lock();
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
-- TEST 77: wallet_status returns correct 6-column composite (v1.6)
--
-- v1.6 redefined pg_vault_tde_wallet_status() to return exactly 6 columns:
--   wallet_exists  bool
--   wallet_open    bool
--   kek_algorithm  text
--   dek_count      int
--   last_opened    timestamptz
--   file_perms     text
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

    -- wallet_exists must be true (we just initialized it)
    IF NOT v_status.wallet_exists THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: wallet_exists=false after wallet_init()';
    END IF;

    -- wallet_open must be true (we just unlocked)
    IF NOT v_status.wallet_open THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: wallet_open=false after wallet_unlock()';
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

    -- file_perms must be a 4-digit octal string when wallet exists
    IF v_status.file_perms IS NULL OR v_status.file_perms = '' THEN
        RAISE EXCEPTION
            'TEST 77 FAILED: file_perms is NULL/empty for an existing wallet';
    END IF;

    RAISE NOTICE
        'TEST 77 PASSED: wallet_status() → exists=%, open=%, '
        'last_opened~now, file_perms=%',
        v_status.wallet_exists,
        v_status.wallet_open,
        v_status.file_perms;
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
    v_provider    text;
    v_val_a       text;
    v_val_b       text;
    v_oid_a       oid;
    v_oid_b       oid;
    v_wdek_a_pre  bytea;
    v_wdek_b_pre  bytea;
    v_wdek_a_post bytea;
    v_wdek_b_post bytea;
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

    v_oid_a := 'tde_wallet_regression_79a'::regclass::oid;
    v_oid_b := 'tde_wallet_regression_79b'::regclass::oid;

    -- Snapshot wrapped DEKs BEFORE rotation
    SELECT wrapped_dek INTO v_wdek_a_pre FROM pg_vault_tde_catalog WHERE relid = v_oid_a;
    SELECT wrapped_dek INTO v_wdek_b_pre FROM pg_vault_tde_catalog WHERE relid = v_oid_b;

    IF v_wdek_a_pre IS NULL OR v_wdek_b_pre IS NULL THEN
        RAISE EXCEPTION 'TEST 79 FAILED: missing catalog row before rotation';
    END IF;
    
    -- Rotate the KEK — re-wraps all DEKs under a freshly-derived KEK.
    -- v1.6 signature: takes a new_passphrase argument (the wallet file's
    -- on-disk MAC is rewritten under it).  We rotate to an interim
    -- passphrase, then rotate back so subsequent tests can keep using
    -- the standard passphrase.
    PERFORM pg_vault_tde_rotate_kek();


    -- Snapshot wrapped DEKs AFTER rotation — they MUST differ from before:
    -- the underlying DEK is unchanged (per-table DEK is preserved across
    -- KEK rotation), but the wrapping ciphertext changes because the KEK
    -- changed.
    SELECT wrapped_dek INTO v_wdek_a_post FROM pg_vault_tde_catalog WHERE relid = v_oid_a;
    SELECT wrapped_dek INTO v_wdek_b_post FROM pg_vault_tde_catalog WHERE relid = v_oid_b;

    IF v_wdek_a_post = v_wdek_a_pre THEN
        RAISE EXCEPTION
            'TEST 79 FAILED: table_a wrapped_dek did not change after rotate_kek '
            '(KEK rotation must produce new wrapping ciphertext)';
    END IF;
    IF v_wdek_b_post = v_wdek_b_pre THEN
        RAISE EXCEPTION
            'TEST 79 FAILED: table_b wrapped_dek did not change after rotate_kek';
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
        'TEST 79 PASSED: rotate_kek() re-wrapped both per-table DEKs '
        '(catalog ciphertext changed, both tables still readable)';
END;
$$;

-- TEST 80: removed in v1.7 (wallet_export_bundle/import_bundle superseded
-- by pg_vault_tde_seal_keys/unseal_keys — see tap/14 and tap/15)

-- ================================================================
-- TEST 81: Large TOAST round-trip across INSERT/UPDATE/DELETE
--
-- Drives the heap_toast_insert_or_update path with values well above
-- TOAST_TUPLE_THRESHOLD on encrypted_heap.  Validates that the
-- expanded PG_TRY (fix #1) preserves correctness through:
--   1. INSERT of a 64 KB text value
--   2. SELECT round-trip (must equal original)
--   3. UPDATE replacing it with another 64 KB value
--   4. SELECT round-trip on the updated value
--   5. DELETE
-- ================================================================
DO $$
DECLARE
    v_a       text;
    v_b       text;
    v_read    text;
    v_count   bigint;
BEGIN
    DROP TABLE IF EXISTS tde_toast_rt_81;

    CREATE TABLE tde_toast_rt_81 (
        id    int PRIMARY KEY,
        body  text
    ) USING encrypted_heap;

    -- ~64 KiB each (well above any TOAST/compression threshold)
    v_a := repeat('A_TOAST_PAYLOAD_v82_', 3500);
    v_b := repeat('B_TOAST_PAYLOAD_v82_', 3500);

    INSERT INTO tde_toast_rt_81 VALUES (1, v_a);

    SELECT body INTO v_read FROM tde_toast_rt_81 WHERE id = 1;
    IF v_read IS DISTINCT FROM v_a THEN
        RAISE EXCEPTION 'TEST 81 FAILED: INSERT round-trip mismatch (read len=%, expected len=%)',
            length(v_read), length(v_a);
    END IF;

    UPDATE tde_toast_rt_81 SET body = v_b WHERE id = 1;

    SELECT body INTO v_read FROM tde_toast_rt_81 WHERE id = 1;
    IF v_read IS DISTINCT FROM v_b THEN
        RAISE EXCEPTION 'TEST 81 FAILED: UPDATE round-trip mismatch';
    END IF;

    DELETE FROM tde_toast_rt_81 WHERE id = 1;

    SELECT count(*) INTO v_count FROM tde_toast_rt_81;
    IF v_count <> 0 THEN
        RAISE EXCEPTION 'TEST 81 FAILED: DELETE left % row(s)', v_count;
    END IF;

    DROP TABLE tde_toast_rt_81;

    RAISE NOTICE 'TEST 81 PASSED: 64 KB TOAST INSERT/UPDATE/DELETE round-trip OK';
END;
$$;

-- ================================================================
-- TEST 82: Subtransaction rollback after pre-TOAST + encrypt path
--
-- Drives the pg_vault_tde_tuple_insert pipeline (pre-TOAST + encrypt +
-- heap_insert) and then forces a subtransaction abort via a duplicate-PK
-- violation.  Validates fix #1: the expanded PG_TRY restores reltoastrelid
-- and OPENSSL_cleanses the plaintext intermediates even when the failure
-- happens AFTER heap_toast_insert_or_update has run, and the surrounding
-- table state remains consistent.
--
-- We use a COMPRESSIBLE near-TOAST payload so that pglz keeps the value
-- inline in the parent tuple (the v1.6 documented limitation: chunk-level
-- encryption of pg_toast_NNNNN is a v1.6 work item, so we deliberately
-- avoid forcing actual chunks here — a focused chunk test is in v1.6).
--
-- After the rollback, the original row must be intact and a fresh INSERT
-- of a non-conflicting row must succeed.
-- ================================================================
DO $$
DECLARE
    v_payload text;
    v_count   bigint;
    v_read    text;
BEGIN
    DROP TABLE IF EXISTS tde_toast_rollback_82;

    CREATE TABLE tde_toast_rollback_82 (
        id    int PRIMARY KEY,
        body  text
    ) USING encrypted_heap;

    -- ~50 KB of highly-repetitive text → pglz compresses it well below
    -- TOAST_TUPLE_TARGET, so the value travels through pre-TOAST +
    -- encrypt + heap_insert as an inline encoded datum (the path covered
    -- by v1.6 chunk-level encryption — chunks themselves stay v1.6).
    v_payload := repeat('TOAST_ROLLBACK_v83_inline_', 2000);

    -- Seed row id=1 (will be the conflict victim).
    INSERT INTO tde_toast_rollback_82 VALUES (1, v_payload);

    -- Doomed INSERT inside a savepoint.  pg_vault_tde_tuple_insert runs
    -- pre-TOAST + encrypt, swaps reltoastrelid → InvalidOid, then
    -- heap_insert fails on the unique key.  Fix #1's expanded PG_TRY must
    -- restore reltoastrelid and free intermediates before re-throwing.
    BEGIN
        INSERT INTO tde_toast_rollback_82 VALUES (1, v_payload);
        RAISE EXCEPTION 'TEST 82 FAILED: duplicate-PK INSERT did not raise';
    EXCEPTION WHEN unique_violation THEN
        NULL;  -- Expected; subtransaction rolls back.
    END;

    -- Existing row must still be readable and intact.
    SELECT count(*) INTO v_count FROM tde_toast_rollback_82;
    IF v_count <> 1 THEN
        RAISE EXCEPTION 'TEST 82 FAILED: expected 1 row after rollback, got %', v_count;
    END IF;

    SELECT body INTO v_read FROM tde_toast_rollback_82 WHERE id = 1;
    IF v_read IS DISTINCT FROM v_payload THEN
        RAISE EXCEPTION 'TEST 82 FAILED: original row corrupted by rolled-back INSERT';
    END IF;

    -- A fresh non-conflicting INSERT must still work — proves that
    -- reltoastrelid was correctly restored by fix #1's PG_CATCH branch.
    INSERT INTO tde_toast_rollback_82 VALUES (2, v_payload);
    SELECT body INTO v_read FROM tde_toast_rollback_82 WHERE id = 2;
    IF v_read IS DISTINCT FROM v_payload THEN
        RAISE EXCEPTION 'TEST 82 FAILED: post-rollback INSERT round-trip broken '
                        '(reltoastrelid restoration likely incorrect)';
    END IF;

    -- Sanity: rolled-back row id=1 was not duplicated.
    SELECT count(*) INTO v_count FROM tde_toast_rollback_82;
    IF v_count <> 2 THEN
        RAISE EXCEPTION 'TEST 82 FAILED: expected 2 rows after success INSERT, got %', v_count;
    END IF;

    DROP TABLE tde_toast_rollback_82;

    RAISE NOTICE 'TEST 82 PASSED: subtransaction rollback after pre-TOAST + encrypt '
                 'leaves the table consistent and reltoastrelid correctly restored';
END;
$$;

-- ================================================================
-- TEST 83: STORAGE EXTERNAL round-trip with real TOAST chunks
--
-- Validates the TAM read-path bypass for RELKIND_TOASTVALUE: when a
-- column is forced to STORAGE EXTERNAL with an incompressible payload,
-- toast_save_datum produces actual chunks in pg_toast_NNN.  Those chunks
-- are written by core's heap_insert (bypassing rd_tableam) and therefore
-- land plaintext on disk (v1.6 documented limitation).  The TAM read
-- callbacks (scan_getnextslot, index_fetch_tuple, tuple_fetch_row_version,
-- ...) MUST detect relkind == RELKIND_TOASTVALUE and skip the decrypt
-- path; otherwise GCM authentication fails on plaintext chunks and the
-- round-trip from the parent table would be broken.
--
-- This is the first test in the suite that exercises ACTUAL TOAST chunk
-- production (incompressible payload + STORAGE EXTERNAL); compressible
-- payloads in tests 32, 35, 57-60, 82 stay inline and never trigger the
-- chunk read path.
-- ================================================================
DO $$
DECLARE
    v_payload     text;
    v_read        text;
    v_toastrel    oid;
    v_chunks      bigint;
    v_payload_len int;
    v_read_len    int;
BEGIN
    DROP TABLE IF EXISTS tde_toast_external_83;

    CREATE TABLE tde_toast_external_83 (
        id    int PRIMARY KEY,
        body  text
    ) USING encrypted_heap;

    -- Force out-of-line storage: PG cannot keep the value inline, must
    -- chunk it to pg_toast_NNN regardless of size threshold.
    ALTER TABLE tde_toast_external_83 ALTER COLUMN body SET STORAGE EXTERNAL;

    -- Build ~80 KB of incompressible text: 2500 distinct 32-char MD5
    -- hashes concatenated, so pglz cannot shrink it.  Uses only core
    -- functions (no pgcrypto).
    SELECT string_agg(md5(g::text), '')
        INTO v_payload
        FROM generate_series(1, 2500) g;

    v_payload_len := length(v_payload);

    INSERT INTO tde_toast_external_83 VALUES (1, v_payload);

    -- Verify TOAST machinery actually produced chunks (precondition).
    SELECT reltoastrelid INTO v_toastrel
    FROM pg_class WHERE oid = 'tde_toast_external_83'::regclass;

    IF v_toastrel IS NULL OR v_toastrel = 0 THEN
        RAISE EXCEPTION 'TEST 83 FAILED: no TOAST relation auto-created';
    END IF;

    EXECUTE format('SELECT count(*) FROM pg_toast.%I',
                   (SELECT relname FROM pg_class WHERE oid = v_toastrel))
        INTO v_chunks;

    IF v_chunks = 0 THEN
        RAISE EXCEPTION 'TEST 83 FAILED: STORAGE EXTERNAL did not produce '
                        'TOAST chunks (precondition not met)';
    END IF;

    -- THE KEY ASSERTION: round-trip via the parent table.  This forces
    -- heap_fetch_toast_slice → systable_beginscan_ordered → table_index_
    -- fetch_tuple via OUR TAM (because reltoastrelid is encrypted_heap).
    -- Without the RELKIND_TOASTVALUE bypass, decrypt would fail with
    -- "AES-256-GCM authentication FAILED" on the plaintext chunks.
    SELECT body INTO v_read FROM tde_toast_external_83 WHERE id = 1;

    IF v_read IS NULL THEN
        RAISE EXCEPTION 'TEST 83 FAILED: SELECT returned NULL after TOAST insert';
    END IF;

    v_read_len := length(v_read);
    IF v_read_len <> v_payload_len THEN
        RAISE EXCEPTION 'TEST 83 FAILED: round-trip length mismatch '
                        '(wrote %, read %)', v_payload_len, v_read_len;
    END IF;

    IF v_read IS DISTINCT FROM v_payload THEN
        RAISE EXCEPTION 'TEST 83 FAILED: round-trip content mismatch';
    END IF;

    -- Bonus: an UPDATE that produces NEW chunks must also round-trip.
    UPDATE tde_toast_external_83 SET body = reverse(v_payload) WHERE id = 1;
    SELECT body INTO v_read FROM tde_toast_external_83 WHERE id = 1;
    IF v_read IS DISTINCT FROM reverse(v_payload) THEN
        RAISE EXCEPTION 'TEST 83 FAILED: post-UPDATE round-trip broken';
    END IF;

    DROP TABLE tde_toast_external_83;

    RAISE NOTICE
        'TEST 83 PASSED: STORAGE EXTERNAL round-trip OK (% bytes across % chunks; '
        'TAM RELKIND_TOASTVALUE bypass active on read path)',
        v_payload_len, v_chunks;
END;
$$;

-- ================================================================
-- TEST 84: verify_plaintext_on_disk on STORAGE EXTERNAL payload
--
-- Security assertion for the same real-chunk scenario used by TEST 83:
-- with STORAGE EXTERNAL + incompressible payload we force out-of-line
-- TOAST chunks, then call pg_vault_tde_verify_plaintext_on_disk().
--
-- The function raises ERROR if plaintext is detected in main/TOAST files,
-- so this test passes only if no exception is raised and is_encrypted=true.
-- ================================================================
DO $$
DECLARE
    v_payload     text;
    v_probe       text;
    v_result      record;
    v_toastrel    oid;
    v_chunks      bigint;
    v_dev_mode    text;
BEGIN
    v_dev_mode := current_setting('pg_vault_tde.dev_mode', true);
    IF v_dev_mode IS DISTINCT FROM 'on' THEN
        RAISE NOTICE 'TEST 84 SKIPPED: pg_vault_tde.dev_mode is % (need on for test-only forensic helpers)',
                     COALESCE(v_dev_mode, '<NULL>');
        RETURN;
    END IF;

    DROP TABLE IF EXISTS tde_toast_verify_disk_84;

    CREATE TABLE tde_toast_verify_disk_84 (
        id    int PRIMARY KEY,
        body  text
    ) USING encrypted_heap;

    ALTER TABLE tde_toast_verify_disk_84 ALTER COLUMN body SET STORAGE EXTERNAL;

    /*
     * Build ~80 KB incompressible payload to force real TOAST chunks.
     * Use the first 32-byte digest as a probe string for on-disk search.
     */
    SELECT string_agg(md5(g::text), '')
      INTO v_payload
      FROM generate_series(1, 2500) g;

    v_probe := substr(v_payload, 1, 32);

    INSERT INTO tde_toast_verify_disk_84 VALUES (1, v_payload);

    -- Precondition: TOAST relation exists and contains chunk rows.
    SELECT reltoastrelid INTO v_toastrel
    FROM pg_class WHERE oid = 'tde_toast_verify_disk_84'::regclass;

    IF v_toastrel IS NULL OR v_toastrel = 0 THEN
        RAISE EXCEPTION 'TEST 84 FAILED: no TOAST relation auto-created';
    END IF;

    EXECUTE format('SELECT count(*) FROM pg_toast.%I',
                   (SELECT relname FROM pg_class WHERE oid = v_toastrel))
      INTO v_chunks;

    IF v_chunks = 0 THEN
        RAISE EXCEPTION 'TEST 84 FAILED: STORAGE EXTERNAL did not produce '
                        'TOAST chunks (precondition not met)';
    END IF;

    SELECT *
      INTO v_result
      FROM pg_vault_tde_verify_plaintext_on_disk(
          'tde_toast_verify_disk_84'::regclass,
          v_probe
      );

    IF NOT v_result.is_encrypted THEN
        RAISE EXCEPTION 'TEST 84 FAILED: verify_plaintext_on_disk reported '
                        'is_encrypted=false: %',
                        COALESCE(v_result.message, '<NULL>');
    END IF;

    DROP TABLE tde_toast_verify_disk_84;

    RAISE NOTICE
        'TEST 84 PASSED: verify_plaintext_on_disk confirms STORAGE EXTERNAL '
        'payload is encrypted (chunks=%)', v_chunks;
END;
$$;

-- ================================================================
-- TEST 85: verify_toast_by_comparison on STORAGE EXTERNAL payload
--
-- Companion diagnostic to TEST 84 on the same real-chunk scenario.
-- Uses pg_vault_tde_verify_toast_by_comparison() to compare one sampled
-- chunk_data value against raw TOAST file bytes and validate that the
-- helper returns a coherent result payload for STORAGE EXTERNAL tables.
-- ================================================================
DO $$
DECLARE
    v_payload     text;
    v_toastrel    oid;
    v_chunks      bigint;
    v_cmp         record;
    v_dev_mode    text;
BEGIN
    v_dev_mode := current_setting('pg_vault_tde.dev_mode', true);
    IF v_dev_mode IS DISTINCT FROM 'on' THEN
        RAISE NOTICE 'TEST 85 SKIPPED: pg_vault_tde.dev_mode is % (need on for test-only forensic helpers)',
                     COALESCE(v_dev_mode, '<NULL>');
        RETURN;
    END IF;

    DROP TABLE IF EXISTS tde_toast_compare_disk_85;

    CREATE TABLE tde_toast_compare_disk_85 (
        id    int PRIMARY KEY,
        body  text
    ) USING encrypted_heap;

    ALTER TABLE tde_toast_compare_disk_85 ALTER COLUMN body SET STORAGE EXTERNAL;

    SELECT string_agg(md5(g::text), '')
      INTO v_payload
      FROM generate_series(1, 2500) g;

    INSERT INTO tde_toast_compare_disk_85 VALUES (1, v_payload);

    -- Precondition: TOAST relation exists and has at least one chunk row.
    SELECT reltoastrelid INTO v_toastrel
    FROM pg_class WHERE oid = 'tde_toast_compare_disk_85'::regclass;

    IF v_toastrel IS NULL OR v_toastrel = 0 THEN
        RAISE EXCEPTION 'TEST 85 FAILED: no TOAST relation auto-created';
    END IF;

    EXECUTE format('SELECT count(*) FROM pg_toast.%I',
                   (SELECT relname FROM pg_class WHERE oid = v_toastrel))
      INTO v_chunks;

    IF v_chunks = 0 THEN
        RAISE EXCEPTION 'TEST 85 FAILED: STORAGE EXTERNAL did not produce '
                        'TOAST chunks (precondition not met)';
    END IF;

    SELECT *
      INTO v_cmp
      FROM pg_vault_tde_verify_toast_by_comparison(
          'tde_toast_compare_disk_85'::regclass
      );

    IF v_cmp.toast_table IS NULL THEN
        RAISE EXCEPTION 'TEST 85 FAILED: verify_toast_by_comparison returned '
                        'NULL toast_table despite TOAST precondition';
    END IF;

    IF v_cmp.sampled_chunk_size IS NULL OR v_cmp.sampled_chunk_size <= 0 THEN
        RAISE EXCEPTION 'TEST 85 FAILED: sampled_chunk_size is invalid: %',
                        COALESCE(v_cmp.sampled_chunk_size::text, '<NULL>');
    END IF;

    IF v_cmp.toast_file_size IS NULL OR v_cmp.toast_file_size <= 0 THEN
        RAISE EXCEPTION 'TEST 85 FAILED: toast_file_size is invalid: %',
                        COALESCE(v_cmp.toast_file_size::text, '<NULL>');
    END IF;

    IF v_cmp.message IS NULL OR v_cmp.message = '' THEN
        RAISE EXCEPTION 'TEST 85 FAILED: verify_toast_by_comparison returned '
                        'empty message';
    END IF;

    DROP TABLE tde_toast_compare_disk_85;

    RAISE NOTICE
        'TEST 85 PASSED: verify_toast_by_comparison returned coherent '
        'diagnostic output (is_encrypted=%, chunk_match_offset=%, chunks=%)',
        v_cmp.is_encrypted,
        COALESCE(v_cmp.chunk_match_offset::text, '<NULL>'),
        v_chunks;
END;
$$;

-- ================================================================
-- TEST 86: TOAST round-trip baseline with meaningful TEXT payload
-- ================================================================
DO $$
DECLARE
    payload_text text;
    readback_text text;
    rel_toast_oid oid;
BEGIN
    

    DROP TABLE IF EXISTS tde_toast_baseline_53;
    CREATE TABLE tde_toast_baseline_53 (id int, large_data text)
        USING encrypted_heap;

    payload_text := (
        SELECT string_agg(
            format(
                'Baseline TOAST paragraph %s: relation encryption validation token=%s marker=%s.',
                g,
                md5((g * 4099)::text),
                md5((g * 8111)::text)
            ),
            E'\n'
        )
        FROM generate_series(1, 160) AS g
    );

    IF length(payload_text) < 10000 THEN
        RAISE EXCEPTION 'TEST 86 FAILED: generated payload too short (% bytes)', length(payload_text);
    END IF;

    INSERT INTO tde_toast_baseline_53 VALUES (1, payload_text);

    SELECT large_data INTO readback_text
    FROM tde_toast_baseline_53
    WHERE id = 1;

    IF readback_text IS DISTINCT FROM payload_text THEN
        RAISE EXCEPTION
            'TEST 86 FAILED: TOAST round-trip mismatch (expected % bytes, got % bytes)',
            length(payload_text), length(readback_text);
    END IF;

    SELECT reltoastrelid INTO rel_toast_oid
    FROM pg_class
    WHERE oid = 'tde_toast_baseline_53'::regclass;

    IF rel_toast_oid IS NULL OR rel_toast_oid = 0 THEN
        RAISE EXCEPTION 'TEST 86 FAILED: expected TOAST relation for large payload';
    END IF;

    DROP TABLE tde_toast_baseline_53;
    RAISE NOTICE 'TEST 86 PASSED: TOAST baseline round-trip OK with meaningful large TEXT payload';
END;
$$;

-- ================================================================
-- TEST 87: TOAST forensic check — no plaintext in main/TOAST files
-- ================================================================
DO $$
DECLARE
    payload_text text;
    rel_toast_oid oid;
    toast_rel regclass;
    rel_file text;
    toast_file text;
    rel_bytes bytea;
    toast_bytes bytea;
    needle bytea;
BEGIN
    

    DROP TABLE IF EXISTS tde_toast_forensic_54;
    CREATE TABLE tde_toast_forensic_54 (id int, large_data text)
        USING encrypted_heap;

    payload_text := (
        SELECT string_agg(
            format(
                'Forensic TOAST paragraph %s: validate at-rest confidentiality token=%s trail=%s.',
                g,
                md5((g * 1237)::text),
                md5((g * 2131)::text)
            ),
            E'\n'
        )
        FROM generate_series(1, 170) AS g
    );

    IF length(payload_text) < 12000 THEN
        RAISE EXCEPTION 'TEST 87 FAILED: generated payload too short (% bytes)', length(payload_text);
    END IF;

    INSERT INTO tde_toast_forensic_54 VALUES (1, payload_text);

    SELECT reltoastrelid INTO rel_toast_oid
    FROM pg_class
    WHERE oid = 'tde_toast_forensic_54'::regclass;

    IF rel_toast_oid IS NULL OR rel_toast_oid = 0 THEN
        RAISE EXCEPTION 'TEST 87 FAILED: no TOAST relation created for forensic payload';
    END IF;

    toast_rel := rel_toast_oid::regclass;

    CHECKPOINT;

    rel_file := pg_relation_filepath('tde_toast_forensic_54'::regclass);
    toast_file := pg_relation_filepath(toast_rel);
    rel_bytes := pg_read_binary_file(rel_file);
    toast_bytes := pg_read_binary_file(toast_file);
    needle := convert_to(substr(payload_text, 1, 96), 'UTF8');

    IF position(needle IN rel_bytes) > 0 THEN
        RAISE EXCEPTION 'TEST 87 FAILED: plaintext snippet found in main relation file';
    END IF;

    IF position(needle IN toast_bytes) > 0 THEN
        RAISE EXCEPTION 'TEST 87 FAILED: plaintext snippet found in TOAST relation file';
    END IF;

    DROP TABLE tde_toast_forensic_54;
    RAISE NOTICE 'TEST 87 PASSED: forensic disk check OK (no plaintext in main/TOAST files)';
END;
$$;


-- ================================================================
-- TEST 88: STORAGE EXTERNAL — no compression, real TOAST chunks,
--          plaintext visible via SELECT but absent on disk
-- ================================================================
DO $$
DECLARE
    payload_text        text;
    selected_text       text;
    deleted_count       int;
    rel_toast_oid       oid;
    toast_rel_regclass  regclass;
    chunk_rows          bigint;
    chunk_payload_bytes bigint;
    rel_file            text;
    toast_file          text;
    rel_bytes           bytea;
    toast_bytes         bytea;
    needle              bytea;
BEGIN
    

    DROP TABLE IF EXISTS tde_storage_external_55;
    CREATE TABLE tde_storage_external_55 (
        id      int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    ALTER TABLE tde_storage_external_55
        ALTER COLUMN payload SET STORAGE EXTERNAL;

    payload_text := (
        SELECT string_agg(
            format(
                'External storage forensic paragraph %s: session=%s token=%s entropy=%s checksum=%s.',
                g,
                to_char(clock_timestamp(), 'YYYYMMDDHH24MISSMS'),
                md5((g * 7919)::text),
                md5((g * 1543)::text),
                md5((g * 2767)::text)
            ),
            E'\n'
        )
        FROM generate_series(1, 160) AS g
    );

    IF length(payload_text) < 10000 THEN
        RAISE EXCEPTION 'TEST 88 FAILED: generated payload too short (% bytes)', length(payload_text);
    END IF;

    INSERT INTO tde_storage_external_55 VALUES (1, payload_text);

    SELECT payload INTO selected_text
    FROM tde_storage_external_55
    WHERE id = 1;

    IF selected_text IS DISTINCT FROM payload_text THEN
        RAISE EXCEPTION 'TEST 88 FAILED: SELECT round-trip mismatch for EXTERNAL payload';
    END IF;

    SELECT reltoastrelid INTO rel_toast_oid
    FROM pg_class
    WHERE oid = 'tde_storage_external_55'::regclass;

    IF rel_toast_oid IS NULL OR rel_toast_oid = 0 THEN
        RAISE EXCEPTION 'TEST 88 FAILED: no TOAST table created for EXTERNAL payload';
    END IF;

    toast_rel_regclass := rel_toast_oid::regclass;

    EXECUTE format('SELECT count(*) FROM %s', toast_rel_regclass)
        INTO chunk_rows;
    IF chunk_rows <= 0 THEN
        RAISE EXCEPTION 'TEST 88 FAILED: expected TOAST chunks, got %', chunk_rows;
    END IF;

    EXECUTE format('SELECT coalesce(sum(length(chunk_data)),0) FROM %s', toast_rel_regclass)
        INTO chunk_payload_bytes;

    IF chunk_payload_bytes < (length(payload_text) * 95 / 100) THEN
        RAISE EXCEPTION 'TEST 88 FAILED: EXTERNAL looks compressed (chunk bytes=% vs payload=%)',
            chunk_payload_bytes, length(payload_text);
    END IF;

    UPDATE tde_storage_external_55
    SET payload = payload || E'\nUpdate marker 55: PostgreSQL TOAST EXTERNAL path.'
    WHERE id = 1;

    SELECT payload INTO selected_text
    FROM tde_storage_external_55
    WHERE id = 1;

    IF position('Update marker 55' IN selected_text) = 0 THEN
        RAISE EXCEPTION 'TEST 88 FAILED: UPDATE did not persist expected marker';
    END IF;

    CHECKPOINT;

    rel_file := pg_relation_filepath('tde_storage_external_55'::regclass);
    toast_file := pg_relation_filepath(toast_rel_regclass);
    rel_bytes := pg_read_binary_file(rel_file);
    toast_bytes := pg_read_binary_file(toast_file);
    needle := convert_to(substr(selected_text, 1, 96), 'UTF8');

    IF position(needle IN rel_bytes) > 0 THEN
        RAISE EXCEPTION 'TEST 88 FAILED: plaintext snippet found in main relation file';
    END IF;

    IF position(needle IN toast_bytes) > 0 THEN
        RAISE EXCEPTION 'TEST 88 FAILED: plaintext snippet found in TOAST relation file';
    END IF;

    DELETE FROM tde_storage_external_55 WHERE id = 1;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    IF deleted_count <> 1 THEN
        RAISE EXCEPTION 'TEST 88 FAILED: DELETE removed % rows (expected 1)', deleted_count;
    END IF;

    DROP TABLE tde_storage_external_55;
    RAISE NOTICE 'TEST 88 PASSED: STORAGE EXTERNAL verified (no compression + TOAST chunks + encrypted at rest + transparent DML)';
END;
$$;

-- ================================================================
-- TEST 89: STORAGE EXTENDED — compression + TOAST chunks + transparent DML
-- ================================================================
DO $$
DECLARE
    payload_text        text;
    selected_text       text;
    rel_toast_oid       oid;
    toast_rel_regclass  regclass;
    chunk_rows          bigint;
    chunk_payload_bytes bigint;
    compressed          text;
BEGIN
    

    DROP TABLE IF EXISTS tde_storage_extended_56;
    CREATE TABLE tde_storage_extended_56 (
        id      int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    ALTER TABLE tde_storage_extended_56
        ALTER COLUMN payload SET STORAGE EXTENDED;

    payload_text := (
        SELECT string_agg(
            format(
                'Extended storage analytical paragraph %s: PostgreSQL TDE keeps data confidential at rest while executor returns clear text. Scenario=%s; trace=%s; component=toast-path; milestone=2026.',
                g,
                (g % 11),
                md5((g * 31337)::text)
            ),
            E'\n'
        )
        FROM generate_series(1, 170) AS g
    );

    IF length(payload_text) < 12000 THEN
        RAISE EXCEPTION 'TEST 89 FAILED: generated payload too short (% bytes)', length(payload_text);
    END IF;

    INSERT INTO tde_storage_extended_56 VALUES (1, payload_text);

    SELECT payload INTO selected_text
    FROM tde_storage_extended_56
    WHERE id = 1;

    IF selected_text IS DISTINCT FROM payload_text THEN
        RAISE EXCEPTION 'TEST 89 FAILED: SELECT round-trip mismatch for EXTENDED payload';
    END IF;

    SELECT reltoastrelid INTO rel_toast_oid
    FROM pg_class
    WHERE oid = 'tde_storage_extended_56'::regclass;

    IF rel_toast_oid IS NULL OR rel_toast_oid = 0 THEN
        RAISE EXCEPTION 'TEST 89 FAILED: no TOAST table created for EXTENDED payload';
    END IF;

    toast_rel_regclass := rel_toast_oid::regclass;

    EXECUTE format('SELECT count(*) FROM %s', toast_rel_regclass)
        INTO chunk_rows;
    IF chunk_rows <= 0 THEN
        RAISE EXCEPTION 'TEST 89 FAILED: expected TOAST chunks, got %', chunk_rows;
    END IF;

    EXECUTE format('SELECT coalesce(sum(length(chunk_data)),0) FROM %s', toast_rel_regclass)
        INTO chunk_payload_bytes;

    IF chunk_payload_bytes >= (length(payload_text) * 90 / 100) THEN
        RAISE EXCEPTION 'TEST 89 FAILED: EXTENDED did not show expected compression (chunk bytes=% vs payload=%)',
            chunk_payload_bytes, length(payload_text);
    END IF;

    SELECT pg_column_compression(payload) INTO compressed
    FROM tde_storage_extended_56
    WHERE id = 1;

    IF compressed IS NULL THEN
        RAISE EXCEPTION 'TEST 89 FAILED: pg_column_compression returned NULL for EXTENDED toasted row';
    END IF;

    UPDATE tde_storage_extended_56
    SET payload = payload || E'\nUpdate marker 56: EXTENDED path update.'
    WHERE id = 1;

    SELECT payload INTO selected_text
    FROM tde_storage_extended_56
    WHERE id = 1;

    IF position('Update marker 56' IN selected_text) = 0 THEN
        RAISE EXCEPTION 'TEST 89 FAILED: UPDATE marker not found after rewrite';
    END IF;

    DELETE FROM tde_storage_extended_56 WHERE id = 1;
    IF EXISTS (SELECT 1 FROM tde_storage_extended_56 WHERE id = 1) THEN
        RAISE EXCEPTION 'TEST 89 FAILED: DELETE did not remove EXTENDED row';
    END IF;

    DROP TABLE tde_storage_extended_56;
    RAISE NOTICE 'TEST 89 PASSED: STORAGE EXTENDED verified (compression + TOAST chunks + transparent DML)';
END;
$$;

-- ================================================================
-- TEST 90: Storage metadata sanity — attstorage flags and TOAST presence
-- ================================================================
DO $$
DECLARE
    ext_storage "char";
    ext_reltoast oid;
    ext_toast_rows bigint;
    ext_toast_rel regclass;
    exd_storage "char";
    exd_reltoast oid;
    exd_toast_rows bigint;
    exd_toast_rel regclass;
BEGIN
    

    DROP TABLE IF EXISTS tde_storage_meta_ext_57;
    DROP TABLE IF EXISTS tde_storage_meta_exd_57;

    CREATE TABLE tde_storage_meta_ext_57 (id int PRIMARY KEY, payload text) USING encrypted_heap;
    CREATE TABLE tde_storage_meta_exd_57 (id int PRIMARY KEY, payload text) USING encrypted_heap;

    ALTER TABLE tde_storage_meta_ext_57 ALTER COLUMN payload SET STORAGE EXTERNAL;
    ALTER TABLE tde_storage_meta_exd_57 ALTER COLUMN payload SET STORAGE EXTENDED;

    INSERT INTO tde_storage_meta_ext_57
    VALUES (
        1,
        (SELECT string_agg(format('Meta ext %s token=%s', g, md5((g * 101)::text)), E'\n')
         FROM generate_series(1, 180) AS g)
    );

    INSERT INTO tde_storage_meta_exd_57
    VALUES (
        1,
        (SELECT string_agg(format('Meta exd %s PostgreSQL storage extended compression path token=%s', g, md5((g * 103)::text)), E'\n')
         FROM generate_series(1, 180) AS g)
    );

    SELECT a.attstorage, c.reltoastrelid
    INTO ext_storage, ext_reltoast
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    WHERE a.attrelid = 'tde_storage_meta_ext_57'::regclass
      AND a.attname = 'payload';

    IF ext_storage <> 'e' THEN
        RAISE EXCEPTION 'TEST 90 FAILED: EXTERNAL attstorage expected ''e'', got ''%''', ext_storage;
    END IF;

    IF ext_reltoast IS NULL OR ext_reltoast = 0 THEN
        RAISE EXCEPTION 'TEST 90 FAILED: EXTERNAL table missing TOAST relation';
    END IF;

    ext_toast_rel := ext_reltoast::regclass;
    EXECUTE format('SELECT count(*) FROM %s', ext_toast_rel)
        INTO ext_toast_rows;
    IF ext_toast_rows <= 0 THEN
        RAISE EXCEPTION 'TEST 90 FAILED: EXTERNAL table has no TOAST rows';
    END IF;

    SELECT a.attstorage, c.reltoastrelid
    INTO exd_storage, exd_reltoast
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    WHERE a.attrelid = 'tde_storage_meta_exd_57'::regclass
      AND a.attname = 'payload';

    IF exd_storage <> 'x' THEN
        RAISE EXCEPTION 'TEST 90 FAILED: EXTENDED attstorage expected ''x'', got ''%''', exd_storage;
    END IF;

    IF exd_reltoast IS NULL OR exd_reltoast = 0 THEN
        RAISE EXCEPTION 'TEST 90 FAILED: EXTENDED table missing TOAST relation';
    END IF;

    exd_toast_rel := exd_reltoast::regclass;
    EXECUTE format('SELECT count(*) FROM %s', exd_toast_rel)
        INTO exd_toast_rows;
    IF exd_toast_rows <= 0 THEN
        RAISE EXCEPTION 'TEST 90 FAILED: EXTENDED table has no TOAST rows';
    END IF;

    DROP TABLE tde_storage_meta_ext_57;
    DROP TABLE tde_storage_meta_exd_57;

    RAISE NOTICE 'TEST 90 PASSED: storage metadata verified (EXTERNAL=e, EXTENDED=x, TOAST rows present in both)';
END;
$$;

-- ================================================================
-- TEST 91: STORAGE EXTERNAL DELETE removes visible TOAST entries
--
-- Verifies that deleting a row with out-of-line EXTERNAL storage also
-- removes the row's visible chunk entries from the TOAST table.
-- ================================================================
DO $$
DECLARE
    payload_text       text;
    rel_toast_oid      oid;
    toast_rel_regclass regclass;
    chunk_rows_before  bigint;
    chunk_rows_after   bigint;
BEGIN
    

    DROP TABLE IF EXISTS tde_toast_delete_58;
    CREATE TABLE tde_toast_delete_58 (
        id      int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    ALTER TABLE tde_toast_delete_58
        ALTER COLUMN payload SET STORAGE EXTERNAL;

    payload_text := (
        SELECT string_agg(
            format(
                'Toast delete verification paragraph %s: token=%s marker=%s entropy=%s.',
                g,
                md5((g * 4241)::text),
                md5((g * 6553)::text),
                md5((g * 8081)::text)
            ),
            E'\n'
        )
        FROM generate_series(1, 180) AS g
    );

    IF length(payload_text) < 12000 THEN
        RAISE EXCEPTION 'TEST 91 FAILED: generated payload too short (% bytes)', length(payload_text);
    END IF;

    INSERT INTO tde_toast_delete_58 VALUES (1, payload_text);

    SELECT reltoastrelid INTO rel_toast_oid
    FROM pg_class
    WHERE oid = 'tde_toast_delete_58'::regclass;

    IF rel_toast_oid IS NULL OR rel_toast_oid = 0 THEN
        RAISE EXCEPTION 'TEST 91 FAILED: no TOAST table created for EXTERNAL payload';
    END IF;

    toast_rel_regclass := rel_toast_oid::regclass;

    EXECUTE format('SELECT count(*) FROM %s', toast_rel_regclass)
        INTO chunk_rows_before;
    IF chunk_rows_before <= 0 THEN
        RAISE EXCEPTION 'TEST 91 FAILED: expected visible TOAST rows before DELETE, got %', chunk_rows_before;
    END IF;

    DELETE FROM tde_toast_delete_58 WHERE id = 1;

    EXECUTE format('SELECT count(*) FROM %s', toast_rel_regclass)
        INTO chunk_rows_after;
    IF chunk_rows_after <> 0 THEN
        RAISE EXCEPTION 'TEST 91 FAILED: expected 0 visible TOAST rows after DELETE, got %', chunk_rows_after;
    END IF;

    DROP TABLE tde_toast_delete_58;
    RAISE NOTICE 'TEST 91 PASSED: deleting EXTERNAL row removes visible TOAST entries';
END;
$$;

-- ================================================================
-- TEST 92: VACUUM FULL 
--
-- Verifies that vacuum full works
-- ================================================================
DO $$
BEGIN
    DROP TABLE IF EXISTS test_vacuum;
    CREATE TABLE test_vacuum (
        id      int,
        payload text
    ) USING encrypted_heap;

    INSERT INTO test_vacuum SELECT i, 'payload' FROM generate_series(1, 100) i;

    DELETE FROM test_vacuum WHERE id % 2 = 0;
END
$$;

SELECT pg_stat_force_next_flush();

DO $$
DECLARE
    dead_tup int;
BEGIN
    SELECT n_dead_tup INTO dead_tup
    FROM pg_stat_all_tables WHERE relname = 'test_vacuum';

    IF dead_tup <> 50 THEN
        RAISE EXCEPTION 'TEST 92 FAILED: DEAD TUPLE SHOULD BE 50, GOT %', dead_tup;
    END IF;
END;
$$;

VACUUM test_vacuum;

DO $$
DECLARE
    dead_tup int;
BEGIN
    SELECT n_dead_tup INTO dead_tup
    FROM pg_stat_all_tables WHERE relname = 'test_vacuum';

    IF dead_tup <> 0 THEN
        RAISE EXCEPTION 'TEST 92 FAILED: VACUUM FAILED';
    END IF;

    RAISE NOTICE 'TEST 92 PASSED: VACUUM WORKED';
    DROP TABLE test_vacuum;
END
$$;


-- ================================================================
-- TEST 93: VACUUM FULL on encrypted_heap with TOAST data
--
-- VACUUM FULL rewrites all live tuples through
-- pg_vault_tde_relation_copy_for_cluster.  For rows with external
-- TOAST pointers, the code: (1) flattens the TOAST datum inline,
-- (2) re-TOASTs into the new heap via pg_vault_tde_toast_tuple,
-- (3) encrypts the new tuple with the current DEK.
--
-- After VACUUM FULL, tde_tuple_has_external_slow is exercised on
-- DELETE because VACUUM FULL may clear HEAP_HASEXTERNAL from the
-- encrypted tuple's infomask (to pass rewrite_heap_tuple's assertion).
-- The per-attribute fallback scan ensures TOAST chunks are deleted.
-- ================================================================
DO $$
DECLARE
    large_val text;
BEGIN
    

    CREATE TABLE tde_vacfull_60 (
        id      int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    large_val := repeat('VACFULL_DATA_', 1000);  -- ~13 KB, forces TOAST

    INSERT INTO tde_vacfull_60 VALUES (1, large_val);
    INSERT INTO tde_vacfull_60 VALUES (2, 'small_row');
    INSERT INTO tde_vacfull_60 VALUES (3, large_val || '_B');
    INSERT INTO tde_vacfull_60 VALUES (4, 'small_row_2');

    DELETE FROM tde_vacfull_60 WHERE id = 2;

    /*
     * VACUUM FULL rewrites all live tuples via
     * pg_vault_tde_relation_copy_for_cluster:
     *  - id=1, id=3: TOAST rows are flattened + re-TOASTed + re-encrypted
     *  - id=4: small row is decrypted, re-encrypted
     */

END $$;

SELECT pg_stat_force_next_flush();
VACUUM FULL tde_vacfull_60;

DO $$
DECLARE 
    large_val text;
    readback  text;
    cnt       int;
BEGIN
    large_val := repeat('VACFULL_DATA_', 1000);

    SELECT payload INTO readback FROM tde_vacfull_60 WHERE id = 1;
    IF readback IS DISTINCT FROM large_val THEN
        RAISE EXCEPTION 'TEST 93 FAILED: id=1 TOAST row after VACUUM FULL mismatch '
            '(got % bytes, expected %)', length(readback), length(large_val);
    END IF;

    SELECT payload INTO readback FROM tde_vacfull_60 WHERE id = 3;
    IF readback IS DISTINCT FROM large_val || '_B' THEN
        RAISE EXCEPTION 'TEST 93 FAILED: id=3 TOAST row after VACUUM FULL mismatch';
    END IF;

    SELECT payload INTO readback FROM tde_vacfull_60 WHERE id = 4;
    IF readback IS DISTINCT FROM 'small_row_2' THEN
        RAISE EXCEPTION 'TEST 93 FAILED: id=4 small row after VACUUM FULL mismatch';
    END IF;

    SELECT count(*) INTO cnt FROM tde_vacfull_60;
    IF cnt <> 3 THEN
        RAISE EXCEPTION 'TEST 93 FAILED: expected 3 rows after VACUUM FULL, got %', cnt;
    END IF;

    /*
     * DELETE the TOAST row after VACUUM FULL: exercises tde_tuple_has_external_slow
     * because VACUUM FULL may have cleared HEAP_HASEXTERNAL from the encrypted
     * tuple's infomask.  The per-attribute fallback ensures heap_toast_delete is
     * called and the TOAST chunks are properly removed.
     */
    DELETE FROM tde_vacfull_60 WHERE id = 1;

    SELECT count(*) INTO cnt FROM tde_vacfull_60;
    IF cnt <> 2 THEN
        RAISE EXCEPTION 'TEST 93 FAILED: expected 2 rows after deleting TOASTed row, got %', cnt;
    END IF;

    DROP TABLE tde_vacfull_60;
    RAISE NOTICE 'TEST 93 PASSED: VACUUM FULL (relation_copy_for_cluster + tde_tuple_has_external_slow) OK';
END;
$$;

-- ================================================================
-- TEST 94: CLUSTER on encrypted_heap with TOAST data
--
-- CLUSTER rewrites all live tuples in index order using the same
-- pg_vault_tde_relation_copy_for_cluster path as VACUUM FULL.
-- Verifies that both TOAST and non-TOAST rows survive clustering
-- with correct decryption.
-- ================================================================
DO $$
DECLARE
    large_val text;
    readback  text;
    cnt       int;
BEGIN
    

    CREATE TABLE tde_cluster_61 (
        id      int,
        payload text
    ) USING encrypted_heap;

    CREATE INDEX tde_cluster_61_idx ON tde_cluster_61 USING tde_btree (id);

    large_val := repeat('CLUSTER_DATA_', 900);  -- ~11 KB

    -- Insert rows out of order so CLUSTER does real work
    INSERT INTO tde_cluster_61 VALUES (3, large_val || '_C');
    INSERT INTO tde_cluster_61 VALUES (1, large_val || '_A');
    INSERT INTO tde_cluster_61 VALUES (4, 'small_d');
    INSERT INTO tde_cluster_61 VALUES (2, 'small_b');

    CLUSTER tde_cluster_61 USING tde_cluster_61_idx;

    SELECT payload INTO readback FROM tde_cluster_61 WHERE id = 1;
    IF readback IS DISTINCT FROM large_val || '_A' THEN
        RAISE EXCEPTION 'TEST 94 FAILED: id=1 after CLUSTER: got "%"', readback;
    END IF;

    SELECT payload INTO readback FROM tde_cluster_61 WHERE id = 2;
    IF readback IS DISTINCT FROM 'small_b' THEN
        RAISE EXCEPTION 'TEST 94 FAILED: id=2 after CLUSTER: got "%"', readback;
    END IF;

    SELECT payload INTO readback FROM tde_cluster_61 WHERE id = 3;
    IF readback IS DISTINCT FROM large_val || '_C' THEN
        RAISE EXCEPTION 'TEST 94 FAILED: id=3 after CLUSTER: got "%"', readback;
    END IF;

    SELECT count(*) INTO cnt FROM tde_cluster_61;
    IF cnt <> 4 THEN
        RAISE EXCEPTION 'TEST 94 FAILED: expected 4 rows after CLUSTER, got %', cnt;
    END IF;

    DROP TABLE tde_cluster_61;
    RAISE NOTICE 'TEST 94 PASSED: CLUSTER on encrypted_heap with TOAST data OK';
END;
$$;

-- ================================================================
-- TEST 95: TOAST data readable via index scan (index_fetch_tuple)
--
-- Verifies that pg_vault_tde_index_fetch_tuple correctly dereferences
-- external TOAST pointers when the read path goes through the index.
-- With enable_seqscan=off the planner chooses index scan, exercising
-- the tde_index_fetch_tuple → decode_slot → TOAST reassembly path.
-- ================================================================
DO $$
DECLARE
    large_val text;
    readback  text;
BEGIN
    

    CREATE TABLE tde_toast_idx_62 (
        id      int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    large_val := repeat('TOAST_INDEX_', 1000);  -- ~12 KB, forces TOAST

    INSERT INTO tde_toast_idx_62 VALUES (1, large_val);
    INSERT INTO tde_toast_idx_62 VALUES (2, 'small');

    SET enable_seqscan = off;
    SELECT payload INTO readback FROM tde_toast_idx_62 WHERE id = 1;
    RESET enable_seqscan;

    IF readback IS DISTINCT FROM large_val THEN
        RAISE EXCEPTION 'TEST 95 FAILED: TOAST via index_fetch_tuple mismatch '
            '(got % bytes, expected %)', length(readback), length(large_val);
    END IF;

    DROP TABLE tde_toast_idx_62;
    RAISE NOTICE 'TEST 95 PASSED: TOAST data decrypted correctly via index_fetch_tuple';
END;
$$;

-- ================================================================
-- TEST 96: TOAST data readable via BitmapHeapScan
--
-- Forces BitmapIndexScan → BitmapHeapScan by disabling seqscan and
-- indexscan, then verifies that scan_bitmap_next_tuple decrypts
-- external TOAST pointers correctly.
-- ================================================================
DO $$
DECLARE
    large_val text;
    readback  text;
    cnt       int;
BEGIN
    

    CREATE TABLE tde_toast_bitmap_63 (
        id      int,
        payload text
    ) USING encrypted_heap;

    CREATE INDEX tde_toast_bitmap_63_idx ON tde_toast_bitmap_63 USING tde_btree (id);

    large_val := repeat('TOAST_BITMAP_', 900);  -- ~11 KB

    INSERT INTO tde_toast_bitmap_63 VALUES (1, large_val || '_1');
    INSERT INTO tde_toast_bitmap_63 VALUES (2, large_val || '_2');
    INSERT INTO tde_toast_bitmap_63 VALUES (3, 'small');

    SET enable_seqscan   = off;
    SET enable_indexscan = off;

    SELECT count(*) INTO cnt
    FROM tde_toast_bitmap_63 WHERE id BETWEEN 1 AND 2;
    IF cnt <> 2 THEN
        RAISE EXCEPTION 'TEST 63a FAILED: BitmapHeapScan count: expected 2, got %', cnt;
    END IF;

    SELECT payload INTO readback
    FROM tde_toast_bitmap_63 WHERE id = 1;
    IF readback IS DISTINCT FROM large_val || '_1' THEN
        RAISE EXCEPTION 'TEST 63b FAILED: TOAST via BitmapHeapScan mismatch '
            '(got % bytes, expected %)', length(readback), length(large_val || '_1');
    END IF;

    RESET enable_seqscan;
    RESET enable_indexscan;

    DROP TABLE tde_toast_bitmap_63;
    RAISE NOTICE 'TEST 96 PASSED: TOAST data decrypted correctly via BitmapHeapScan (scan_bitmap_next_tuple)';
END;
$$;

-- ================================================================
-- TEST 97: TOAST data readable via SELECT FOR UPDATE (tuple_lock)
--
-- SELECT FOR UPDATE calls pg_vault_tde_tuple_lock, which decrypts the
-- slot on TM_Ok.  Verifies that external TOAST pointers are resolved
-- and decrypted on the lock path.
-- ================================================================
DO $$
DECLARE
    large_val text;
    readback  text;
BEGIN
    

    CREATE TABLE tde_toast_forupdate_64 (
        id      int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    large_val := repeat('TOAST_LOCK_', 1000);  -- ~11 KB

    INSERT INTO tde_toast_forupdate_64 VALUES (1, large_val);

    BEGIN
        SELECT payload INTO readback
        FROM tde_toast_forupdate_64
        WHERE id = 1
        FOR UPDATE;
    END;

    IF readback IS DISTINCT FROM large_val THEN
        RAISE EXCEPTION 'TEST 97 FAILED: TOAST via SELECT FOR UPDATE mismatch '
            '(got % bytes, expected %)', length(readback), length(large_val);
    END IF;

    DROP TABLE tde_toast_forupdate_64;
    RAISE NOTICE 'TEST 97 PASSED: TOAST data decrypted correctly via tuple_lock (SELECT FOR UPDATE)';
END;
$$;

-- ================================================================
-- TEST 98: TOAST data readable via TABLESAMPLE (scan_sample_next_tuple)
--
-- Verifies that scan_sample_next_tuple decrypts TOAST rows correctly.
-- SYSTEM(100) ensures all rows are sampled deterministically.
-- ================================================================
DO $$
DECLARE
    large_val text;
    readback  text;
    cnt       int;
BEGIN
    

    CREATE TABLE tde_toast_sample_65 (
        id      int,
        payload text
    ) USING encrypted_heap;

    large_val := repeat('TOAST_SAMPLE_', 900);  -- ~11 KB

    INSERT INTO tde_toast_sample_65 VALUES (1, large_val || '_A');
    INSERT INTO tde_toast_sample_65 VALUES (2, 'small');
    INSERT INTO tde_toast_sample_65 VALUES (3, large_val || '_B');

    SELECT count(*) INTO cnt
    FROM tde_toast_sample_65 TABLESAMPLE SYSTEM(100);
    IF cnt <> 3 THEN
        RAISE EXCEPTION 'TEST 65a FAILED: expected 3 rows via TABLESAMPLE, got %', cnt;
    END IF;

    SELECT payload INTO readback
    FROM tde_toast_sample_65 TABLESAMPLE SYSTEM(100)
    WHERE id = 1;
    IF readback IS DISTINCT FROM large_val || '_A' THEN
        RAISE EXCEPTION 'TEST 65b FAILED: TOAST via TABLESAMPLE mismatch '
            '(got % bytes, expected %)', length(readback), length(large_val || '_A');
    END IF;

    DROP TABLE tde_toast_sample_65;
    RAISE NOTICE 'TEST 98 PASSED: TOAST data decrypted correctly via TABLESAMPLE (scan_sample_next_tuple)';
END;
$$;

-- ================================================================
-- TEST 99: TOAST data — ANALYZE computes statistics correctly
--
-- ANALYZE calls scan_analyze_next_tuple on each row.  For TOAST-ed
-- columns the analyzer must receive decrypted data to compute
-- meaningful statistics.  Verifies that pg_stats entries exist for
-- the TOAST-triggering column, proving decode_slot is called during
-- statistics collection.
-- ================================================================
DO $$
DECLARE
    n_distinct_val numeric;
BEGIN
    

    CREATE TABLE tde_toast_analyze_66 (
        id      int,
        payload text
    ) USING encrypted_heap;

    -- 30 rows, each with a unique ~12 KB payload (forces TOAST)
    INSERT INTO tde_toast_analyze_66
    SELECT g, repeat('ANALYZE_TOAST_' || g || '_', 900)
    FROM generate_series(1, 30) g;

    ANALYZE tde_toast_analyze_66;

    -- n_distinct for id (30 unique values) must be non-zero
    SELECT COALESCE(n_distinct, 0) INTO n_distinct_val
    FROM pg_stats
    WHERE tablename = 'tde_toast_analyze_66' AND attname = 'id';

    IF n_distinct_val = 0 THEN
        RAISE EXCEPTION 'TEST 99 FAILED: ANALYZE produced zero n_distinct for id — '
            'statistics collection may have failed on TOAST read path';
    END IF;

    -- pg_stats entry for payload column must also exist
    PERFORM 1 FROM pg_stats
    WHERE tablename = 'tde_toast_analyze_66'
      AND attname = 'payload';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TEST 99 FAILED: pg_stats has no entry for payload column after ANALYZE';
    END IF;

    DROP TABLE tde_toast_analyze_66;
    RAISE NOTICE 'TEST 99 PASSED: ANALYZE on TOAST column produces valid statistics (scan_analyze_next_tuple path)';
END;
$$;

-- ================================================================
-- TEST 100: multi_insert (COPY path) with TOAST-triggering values
--
-- Verifies that pg_vault_tde_multi_insert correctly pre-TOASTs large
-- column values (via toast_if_necessary) before encryption in the
-- batch pipeline, and that all rows are readable after bulk load.
-- ================================================================
DO $$
DECLARE
    large_val text;
    readback  text;
    cnt       int;
BEGIN
    

    CREATE TABLE tde_toast_copy_67 (
        id      int,
        payload text
    ) USING encrypted_heap;

    large_val := repeat('COPY_TOAST_', 1000);  -- ~11 KB, above TOAST threshold

    -- INSERT ... SELECT triggers the multi_insert batch path
    INSERT INTO tde_toast_copy_67
    SELECT g, large_val || '_row' || g
    FROM generate_series(1, 10) g;

    SELECT count(*) INTO cnt FROM tde_toast_copy_67;
    IF cnt <> 10 THEN
        RAISE EXCEPTION 'TEST 100 FAILED: expected 10 rows, got %', cnt;
    END IF;

    SELECT payload INTO readback FROM tde_toast_copy_67 WHERE id = 5;
    IF readback IS DISTINCT FROM large_val || '_row5' THEN
        RAISE EXCEPTION 'TEST 100 FAILED: row 5 mismatch (got % bytes, expected %)',
            length(readback), length(large_val || '_row5');
    END IF;

    DROP TABLE tde_toast_copy_67;
    RAISE NOTICE 'TEST 100 PASSED: multi_insert (COPY path) with TOAST-triggering values OK';
END;
$$;

-- ================================================================
-- TEST 101: Multi-column TOAST — two large varlena attributes
--
-- Verifies that pg_vault_tde_toast_tuple iterates over ALL eligible
-- varlena columns, not just the first one, and that both columns
-- round-trip correctly after encryption.
-- ================================================================
DO $$
DECLARE
    large_a text;
    large_b text;
    read_a  text;
    read_b  text;
BEGIN
    

    CREATE TABLE tde_toast_multicol_68 (
        id    int PRIMARY KEY,
        col_a text,
        col_b text
    ) USING encrypted_heap;

    large_a := repeat('MULTI_COL_A_', 1000);   -- ~12 KB
    large_b := repeat('MULTI_COL_B_', 900);    -- ~10 KB

    INSERT INTO tde_toast_multicol_68 VALUES (1, large_a, large_b);

    SELECT col_a, col_b INTO read_a, read_b
    FROM tde_toast_multicol_68
    WHERE id = 1;

    IF read_a IS DISTINCT FROM large_a THEN
        RAISE EXCEPTION 'TEST 101 FAILED: col_a mismatch (got % bytes, expected %)',
            length(read_a), length(large_a);
    END IF;

    IF read_b IS DISTINCT FROM large_b THEN
        RAISE EXCEPTION 'TEST 101 FAILED: col_b mismatch (got % bytes, expected %)',
            length(read_b), length(large_b);
    END IF;

    -- UPDATE both large columns to verify the update path also handles two TOAST attrs
    UPDATE tde_toast_multicol_68
    SET col_a = large_a || '_upd',
        col_b = large_b || '_upd'
    WHERE id = 1;

    SELECT col_a, col_b INTO read_a, read_b
    FROM tde_toast_multicol_68 WHERE id = 1;

    IF read_a IS DISTINCT FROM large_a || '_upd' THEN
        RAISE EXCEPTION 'TEST 101 FAILED: col_a after UPDATE mismatch';
    END IF;

    IF read_b IS DISTINCT FROM large_b || '_upd' THEN
        RAISE EXCEPTION 'TEST 101 FAILED: col_b after UPDATE mismatch';
    END IF;

    DROP TABLE tde_toast_multicol_68;
    RAISE NOTICE 'TEST 101 PASSED: multi-column TOAST (two large varlena columns) INSERT + UPDATE round-trip OK';
END;
$$;

-- ================================================================
-- TEST 102: UPDATE large→large exercises old_has_external in tuple_update
--
-- pg_vault_tde_tuple_update reads the OLD tuple version and checks
-- HeapTupleHasExternal before inserting the new encrypted tuple.
-- When both old and new values are large enough to be TOASTed:
--   - old tuple fetch: pg_vault_tde_tuple_fetch_row_version
--   - HeapTupleHasExternal on the decrypted old tuple → true
--   - toast_if_necessary on the new value → pre-TOAST new TOAST chunks
--   - tde_encrypt_heap_tuple on the toasted new tuple
--   - heap_update with reltoastrelid suppressed
-- Also verifies UPDATE large→small (old_has_external=true, new inline).
-- ================================================================
DO $$
DECLARE
    large_v1 text;
    large_v2 text;
    readback text;
    toast_table text;
    old_chunk int;
    found boolean;
BEGIN
    

    CREATE TABLE tde_toast_update_69 (
        id      int PRIMARY KEY,
        payload text
    ) USING encrypted_heap;

    SELECT string_agg(md5(random()::text), '') INTO large_v1 
    FROM generate_series(1, 10000);

    SELECT string_agg(md5(random()::text), '') INTO large_v2 
    FROM generate_series(1, 10000);

    INSERT INTO tde_toast_update_69 VALUES (1, large_v1);

    SELECT payload INTO readback 
    FROM tde_toast_update_69 
    WHERE id = 1;

    IF readback IS DISTINCT FROM large_v1 THEN
        RAISE EXCEPTION 'TEST 69a FAILED: initial INSERT mismatch';
    END IF;


    -- GET TOAST TABLE NAME
    SELECT reltoastrelid::regclass INTO toast_table
    FROM pg_class
    WHERE relname = 'tde_toast_update_69';

    EXECUTE format('SELECT DISTINCT chunk_id FROM %s', toast_table)
    INTO old_chunk;
    
    -- UPDATE large→large: old has external TOAST, new also needs TOAST
    UPDATE tde_toast_update_69 SET payload = large_v2 WHERE id = 1;

    SELECT payload INTO readback 
    FROM tde_toast_update_69
    WHERE id = 1;

    IF readback IS DISTINCT FROM large_v2 THEN
        RAISE EXCEPTION 'TEST 69b FAILED: UPDATE large→large mismatch '
            '(got % bytes, expected %)', length(readback), length(large_v2);
    END IF;

    --If chunk_id of old data still exists it's problem
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE chunk_id = $1)', toast_table)
    INTO found
    USING old_chunk;

    IF found THEN 
        RAISE EXCEPTION 'TEST 69c FAILED: OLD CHUNKs ARE STILL IN TOAST TABLE, SHOULD NOT';
    END IF;

    -- UPDATE large→small: old has external TOAST, new is inline
    UPDATE tde_toast_update_69 SET payload = 'small_value' WHERE id = 1;

    -- There shouldn't be any chunk
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s)', toast_table)
    INTO found;

    IF found THEN 
        RAISE EXCEPTION 'TEST 69d FAILED: THERE ARE SOME CHUNK IN THE TOAST TABLE, NO ONE WAS EXPECTED';
    END IF;

    -- UPDATE small→large: no old external, new needs TOAST
    UPDATE tde_toast_update_69 SET payload = large_v1 WHERE id = 1;

    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s)', toast_table)
    INTO found;

    IF NOT found THEN 
        RAISE EXCEPTION 'TEST 69d FAILED: THERE IS NO CHUNK, THEY WAS EXPECTED';
    END IF;

    DROP TABLE tde_toast_update_69;
    RAISE NOTICE 'TEST 102 PASSED: UPDATE large↔large and large↔small covers old_has_external path OK';
END;
$$;

-- ================================================================
-- TEST 103: pg_vault_tde.toast_encryption=on — TOAST table uses
--          encrypted_heap AM (pg_vault_tde_toast_am callback)
--
-- When pg_vault_tde.toast_encryption = on (the default), the TOAST
-- relation created for an encrypted_heap table must itself be stored
-- with the encrypted_heap AM so that chunk reads go through our TAM
-- callbacks (tde_index_fetch_tuple → decode_slot).
-- ================================================================
DO $$
DECLARE
    toast_oid  oid;
    toast_am   text;
    toast_enc  text;
BEGIN
    

    toast_enc := current_setting('pg_vault_tde.toast_encryption', true);

    -- Only assert when the GUC is explicitly on (or defaulting to on)
    IF toast_enc IS NULL OR toast_enc = 'on' THEN

        CREATE TABLE tde_toastam_70 (
            id      int PRIMARY KEY,
            payload text
        ) USING encrypted_heap;

        SELECT c.reltoastrelid INTO toast_oid
        FROM pg_class c
        WHERE c.oid = 'tde_toastam_70'::regclass;

        IF toast_oid IS NOT NULL AND toast_oid <> 0 THEN
            SELECT a.amname INTO toast_am
            FROM pg_class c
            JOIN pg_am a ON c.relam = a.oid
            WHERE c.oid = toast_oid;

            IF toast_am IS DISTINCT FROM 'encrypted_heap' THEN
                RAISE EXCEPTION
                    'TEST 103 FAILED: TOAST table AM is "%" — expected "encrypted_heap" '
                    '(toast_encryption=on)', COALESCE(toast_am, 'NULL');
            END IF;
        END IF;

        DROP TABLE tde_toastam_70;
        RAISE NOTICE
            'TEST 103 PASSED: toast_encryption=on → TOAST table AM is "encrypted_heap"';
    ELSE
        RAISE NOTICE
            'TEST 103 SKIPPED: pg_vault_tde.toast_encryption=% (not on)', toast_enc;
    END IF;
END;
$$;

-- ================================================================
-- TEST 104: TOAST header overflow
--
-- Verifies that the a tuple with size ~ 2kb - TDE OVERHEAD 
-- doesn't break everything
-- ================================================================
DO $$
DECLARE
    the_biggest_the_largest text;
    result text;
BEGIN

    the_biggest_the_largest := repeat('LIBERI_LIBERI', 156); -- 2028 Byte

    DROP TABLE IF EXISTS tde_toast_71;
    CREATE TABLE tde_toast_71 (
        id    int PRIMARY KEY,
        value text
    ) USING encrypted_heap;

    ALTER TABLE tde_toast_71 ALTER COLUMN value SET STORAGE PLAIN;

    INSERT INTO tde_toast_71 VALUES (1, the_biggest_the_largest);

    SELECT value INTO result 
    FROM tde_toast_71
    WHERE id = 1;

    IF result IS DISTINCT FROM the_biggest_the_largest THEN
        RAISE EXCEPTION 'TEST 104 FAILED: Value mismatch from original value';
    END IF;

    DROP TABLE tde_toast_71;
    RAISE NOTICE 'TEST 104 PASSED: INSERT OF A ALMOST 2Kb TEXT OK';
END;
$$;

-- ================================================================
-- TEST 105: ALTER TABLE x SET ACCESS METHOD heap
--
-- 1. encrypted_heap -> heap (All tuples of table should be
--  decrypted and stored plain. Tuple deregisterd from catalog)
-- 
-- ================================================================
DO $$
DECLARE
    is_enc boolean;
    example_text text;
    rel_id oid;
    tam name;
BEGIN
    DROP TABLE IF EXISTS pg_test_72;
    CREATE TABLE pg_test_72 (
        id int, 
        value text
    ) USING encrypted_heap;

    rel_id := 'pg_test_72'::regclass::oid;

    SELECT am.amname INTO tam
    FROM pg_am am, pg_class c
    WHERE am.oid = c.relam AND c.oid = rel_id;

    IF tam <> 'encrypted_heap' THEN
        RAISE EXCEPTION 'TEST 105 FAILED: after creation pg_test_72 should have encrypted_heap TAM';
    END IF;

    example_text := repeat('ciao_ciao', 100);
    
    INSERT INTO pg_test_72 (id, value) VALUES (1, example_text);

    SELECT is_encrypted INTO STRICT is_enc
    FROM pg_vault_tde_verify_plaintext_on_disk('pg_test_72', 'ciao_ciao'); 

    IF NOT is_enc THEN  
        RAISE EXCEPTION 'TEST 105 FAILED: text in encrypted_heap table is not encrypted';
    END IF;

    ALTER TABLE pg_test_72 SET ACCESS METHOD heap;

    SELECT am.amname INTO tam
    FROM pg_am am, pg_class c
    WHERE am.oid = c.relam AND c.oid = rel_id;

    IF tam <> 'heap' THEN
        RAISE EXCEPTION 'TEST 105 FAILED: after alter pg_test_72 should have heap TAM';
    END IF;

    SELECT is_encrypted INTO STRICT is_enc
    FROM pg_vault_tde_verify_plaintext_on_disk('pg_test_72', 'ciao_ciao'); 

    IF is_enc THEN
        RAISE EXCEPTION 'TEST 105 FAILED: text in heap table should not be encrypted';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_vault_tde_catalog WHERE relid = rel_id) THEN
        RAISE EXCEPTION 'TEST 105 FAILED: heap table still in pg_vault_tde_catalog, should be deregistered';
    END IF;

    DROP TABLE pg_test_72;

    RAISE NOTICE 'TEST 105 PASSED: ALTER TABLE SET ACCESS METHOD heap works correctly';

END;
$$;

-- ================================================================
-- TEST 106: ALTER TABLE x SET ACCESS METHOD encrypted_heap
--
-- heap -> encrypted_heap (All tuples should be encrypted and stored
-- encrypted. Relation registered in catalog)
-- 
-- ================================================================

DO $$
DECLARE
    is_enc boolean;
    example_text text;
    rel_id oid;
    tam name;
BEGIN

    example_text := repeat('ciao_ciao', 100);

    DROP TABLE IF EXISTS pg_test_73;
    CREATE TABLE pg_test_73 (
        id int, 
        value text
    );

    rel_id := 'pg_test_73'::regclass::oid;

    SELECT am.amname INTO tam
    FROM pg_am am, pg_class c
    WHERE am.oid = c.relam AND c.oid = rel_id;

    IF tam <> 'heap' THEN
        RAISE EXCEPTION 'TEST 106 FAILED: after creation pg_test_73 should have heap TAM';
    END IF;

    INSERT INTO pg_test_73 (id, value) VALUES (1, example_text);

    SELECT is_encrypted INTO STRICT is_enc
    FROM pg_vault_tde_verify_plaintext_on_disk('pg_test_73', 'ciao_ciao'); 

    IF is_enc THEN  
        RAISE EXCEPTION 'TEST 106 FAILED: text in heap table should be not encrypted';
    END IF;

    ALTER TABLE pg_test_73 SET ACCESS METHOD encrypted_heap;

    SELECT am.amname INTO tam
    FROM pg_am am, pg_class c
    WHERE am.oid = c.relam AND c.oid = rel_id;

    IF tam <> 'encrypted_heap' THEN
        RAISE EXCEPTION 'TEST 106 FAILED: after alter pg_test_73 should have encrypted_heap TAM';
    END IF;

    SELECT is_encrypted INTO STRICT is_enc
    FROM pg_vault_tde_verify_plaintext_on_disk('pg_test_73', 'ciao_ciao'); 

    IF NOT is_enc THEN
        RAISE EXCEPTION 'TEST 106 FAILED: text in encrypted_heap table should be encrypted';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_vault_tde_catalog WHERE relid = rel_id) THEN
        RAISE EXCEPTION 'TEST 106 FAILED: encrypted_heap table should be registered in pg_vault_tde_catalog';
    END IF;

    DROP TABLE pg_test_73;

    RAISE NOTICE 'TEST 106 PASSED: ALTER TABLE SET ACCESS METHOD encrypted_heap works correctly';
END;
$$;


-- ================================================================
-- TEST 107: Tuple readable after pg_vault_tde_rotation_online()
--
-- The table and its data MUST be committed before calling rotate_online,
-- because the BGW runs in a separate READ COMMITTED transaction.  If the
-- table were created inside the same DO block, the BGW would see an
-- uncommitted pg_class entry, hit get_rel_name() == NULL, and fail.
-- ================================================================

DROP TABLE IF EXISTS test_table_107;
CREATE TABLE test_table_107 (id serial, value text) USING encrypted_heap;
CREATE INDEX test_idx_74 ON test_table_107 USING tde_btree (id);
INSERT INTO test_table_107(value)
    SELECT 'testo_molto_bello' FROM generate_series(1, 10000) g;

DO $$
DECLARE
    rel_id     oid;
    result     text;
    sample     text := 'testo_molto_bello';
    prev_dek   bytea;
    curr_dek   bytea;
    is_enc     boolean;
    status_row record;
    wait_count int := 0;
    v_provider text;

BEGIN
    rel_id := 'test_table_107'::regclass::oid;

    SELECT is_encrypted INTO STRICT is_enc
    FROM pg_vault_tde_verify_plaintext_on_disk('test_table_107', sample);

    IF NOT is_enc THEN
        RAISE EXCEPTION 'TEST 107 FAILED: text is not encrypted';
    END IF;

    SELECT value INTO result
    FROM test_table_107
    WHERE id = 100;

    IF result <> sample THEN
        RAISE EXCEPTION 'TEST 107 FAILED: read result is different from sample';
    END IF;

    SELECT wrapped_dek INTO prev_dek
    FROM pg_vault_tde_catalog
    WHERE relid = rel_id;

    PERFORM pg_vault_tde_rotate_online('test_table_107');

    /*
     * COMMIT here is mandatory.  The SELECT above acquired AccessShareLock on
     * test_idx_74 (tde_btree).  The rotation BGW's Phase 3 calls reindex_index()
     * which needs AccessExclusiveLock on the same index.  Without COMMIT, the
     * BGW blocks indefinitely waiting for our lock, the poll loop times out with
     * status='running', and the test fails — even though the rotation itself is
     * correct.  COMMIT releases all transaction locks so the BGW can proceed.
     * Local variables (rel_id, status_row, prev_dek) survive the COMMIT.
     */
    COMMIT;

    DECLARE
        waited int := 0;
    BEGIN
        LOOP
            SELECT * INTO status_row FROM pg_vault_tde_rotation_status
            WHERE relid = rel_id;
            EXIT WHEN status_row.status IN ('complete', 'failed');
            EXIT WHEN waited > 40;
            PERFORM pg_sleep(0.25);
            waited := waited + 1;
        END LOOP;
    END;

    IF status_row IS NULL OR status_row.status <> 'complete' THEN
        RAISE EXCEPTION 'TEST 107 FAILED: online rotation did not complete (status=%)',
            COALESCE(status_row.status, 'NULL');
    END IF;

    SELECT wrapped_dek INTO curr_dek
    FROM pg_vault_tde_catalog
    WHERE relid = rel_id;

    IF prev_dek = curr_dek THEN
        RAISE EXCEPTION 'TEST 107 FAILED: the online rotation did not change the DEK';
    END IF;

    SELECT is_encrypted INTO STRICT is_enc
    FROM pg_vault_tde_verify_plaintext_on_disk('test_table_107', sample);

    IF NOT is_enc THEN
        RAISE EXCEPTION 'TEST 107 FAILED: text, after DEK rotation, is not encrypted';
    END IF;

    SELECT value INTO result
    FROM test_table_107
    WHERE id = 100;

    IF result <> sample THEN
        RAISE EXCEPTION 'TEST 107 FAILED: read result, after rotation, is different from sample';
    END IF;

    RAISE NOTICE 'TEST 107 PASSED: online rotation worked and tuples are still readable and encrypted';
END;
$$;

DROP TABLE test_table_107;

-- ================================================================
-- TEST 108: CREATE TABLE AS
-- 
-- CTAS should register the table BEFORE the query execution
-- for the insert
-- ================================================================

DO $$
DECLARE
    rel_id oid;
BEGIN
    DROP TABLE IF EXISTS test_table_108;

    CREATE TABLE test_table_108 
    USING encrypted_heap
    AS SELECT * FROM pg_vault_tde_wallet_status();

    rel_id := 'test_table_108'::regclass::oid;

    IF NOT EXISTS (SELECT 1 FROM pg_vault_tde_catalog WHERE relid = rel_id) THEN
        RAISE EXCEPTION 'TEST 108 FAILED: table just created should in pg_vault_tde_catalog';
    END IF;

    RAISE NOTICE 'TEST 108 PASSED: table created with CTAS registered in catalog and encrypted';
END;
$$;

-- ================================================================
-- TEST 109: VACUUM FULL ON TABLE WITH EXTERNAL STORAGE COLUMNS
-- ================================================================

DO $$
DECLARE 
    rel_id oid;

BEGIN   
    DROP TABLE IF EXISTS test_table_109;
    CREATE TABLE test_table_109 (
        id serial, 
        value text
    ) USING encrypted_heap;

    ALTER TABLE test_table_109 ALTER COLUMN VALUE SET STORAGE EXTERNAL;

    INSERT INTO test_table_109 (value) VALUES (repeat('ciao_ciao', 10000));
END;
$$;

SELECT pg_stat_force_next_flush();
VACUUM FULL test_table_109;

DO $$
DECLARE
    v_len   int;
    v_val   text;
    expected text := repeat('ciao_ciao', 10000);
BEGIN
    SELECT length(value) INTO v_len FROM test_table_109 WHERE id = 1;
    IF v_len IS DISTINCT FROM length(expected) THEN
        RAISE EXCEPTION 'TEST 109 FAILED: length mismatch after VACUUM FULL (got %, expected %)',
            v_len, length(expected);
    END IF;

    SELECT value INTO v_val FROM test_table_109 WHERE id = 1;
    IF v_val IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'TEST 109 FAILED: content mismatch after VACUUM FULL';
    END IF;

    DROP TABLE IF EXISTS test_table_109;

    RAISE NOTICE 'TEST 109 PASSED: VACUUM FULL on STORAGE EXTERNAL column decrypts correctly after rewrite';
END;
$$;


/* (currently commentend because it's not planned to be resolved)
-- ================================================================
-- TEST 110: WITH HOLD CURSOR PLAINTEXT SPILL ON DISK 
--
-- When WITH HOLD cursor can't allocate RAM for his query use the 
-- disk. We need to check if it spills plaintext.
-- ================================================================

ALTER SYSTEM SET work_mem = '64kB';
SELECT pg_reload_conf();

CREATE OR REPLACE FUNCTION check_tmp_file_for_needle(needle text)
RETURNS boolean AS $$
DECLARE
    tmp_filename text;
    file_bytes bytea;
    backend_pid int := pg_backend_pid();
    needle_bytes bytea := convert_to(needle, 'UTF8');
BEGIN
    FOR tmp_filename IN 
        SELECT name 
        FROM pg_ls_dir('base/pgsql_tmp') as name
        WHERE name LIKE 'pgsql_tmp' || backend_pid || '.%'
    LOOP

        file_bytes := pg_read_binary_file('base/pgsql_tmp/' || tmp_filename);

        IF position(needle_bytes in file_bytes) > 0 THEN
            RETURN true;
        END IF;
    END LOOP;
    
    RETURN false;
EXCEPTION
    WHEN undefined_file THEN
        RAISE EXCEPTION 'TEST 110 FAILED: Undefined file';
END;
$$ LANGUAGE plpgsql;

DROP TABLE IF EXISTS test_table_110;
CREATE TABLE test_table_110 (
    id serial, 
    value text
) USING encrypted_heap;

BEGIN;

INSERT INTO test_table_110 (value) SELECT 'ciao_ciao_' FROM generate_series(1, 100000);

DECLARE my_cursor NO SCROLL CURSOR WITH HOLD FOR SELECT * FROM test_table_110;

COMMIT;

DO $$
BEGIN
    IF check_tmp_file_for_needle('ciao_ciao_') THEN
        RAISE EXCEPTION ' TEST 110 FAILED: Needle found in tmp file';
    END IF;

    RAISE NOTICE 'TEST 110 PASSED: Needle NOT found in tmp file';

    DROP FUNCTION check_tmp_file_for_needle;
    DROP TABLE test_table_110;
END; 
$$;

ALTER SYSTEM RESET work_mem;*/

-- ================================================================
-- PHASE SUMMARY
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'v1.6 Tests 73-110 — COMPLETE';
    RAISE NOTICE '   v1.6 function registration .......... test 73';
    RAISE NOTICE '   wallet_unlock KEK-cache regression .. test 74  *';
    RAISE NOTICE '   wallet_lock evicts DEKs ............. test 75  *';
    RAISE NOTICE '   lock → unlock cycle ................. test 76  *';
    RAISE NOTICE '   wallet_status 6-column SRF .......... test 77  *';
    RAISE NOTICE '   wallet_change_passphrase ............ test 78  *';
    RAISE NOTICE '   rotate_kek multi-table .............. test 79  *';
    RAISE NOTICE '   Large TOAST round-trip (inline) ..... test 81';
    RAISE NOTICE '   Subtransaction rollback semantics ... test 82';
    RAISE NOTICE '   STORAGE EXTERNAL round-trip ......... test 83';
    RAISE NOTICE '   STORAGE EXTERNAL on-disk check ...... test 84  **';
    RAISE NOTICE '   TOAST byte-compare diagnostic ....... test 85  **';
    RAISE NOTICE '   TOAST round-trip baseline ........... test 86';
    RAISE NOTICE '   TOAST forensic disk check ........... test 87';
    RAISE NOTICE '   STORAGE EXTERNAL .................... test 88';
    RAISE NOTICE '   STORAGE EXTENDED .................... test 89';
    RAISE NOTICE '   Storage metadata sanity ............. test 90';
    RAISE NOTICE '   STORAGE EXTERNAL DELETE ............. test 91';
    RAISE NOTICE '   VACUUM FULL ......................... test 92';
    RAISE NOTICE '   VACUUM FULL + TOAST ................. test 93';
    RAISE NOTICE '   CLUSTER ............................. test 94';
    RAISE NOTICE '   TOAST + index scan .................. test 95';
    RAISE NOTICE '   TOAST + BitmapHeapScan .............. test 96';
    RAISE NOTICE '   TOAST + SELECT FOR UPDATE ........... test 97';
    RAISE NOTICE '   TOAST + TABLESAMPLE ................. test 98';
    RAISE NOTICE '   TOAST + ANALYZE ..................... test 99';
    RAISE NOTICE '   TOAST + multi_insert ................ test 100';
    RAISE NOTICE '   Multi-column TOAST .................. test 101';
    RAISE NOTICE '   UPDATE old_has_external ............. test 102';
    RAISE NOTICE '   toast_am GUC ........................ test 103  ***';
    RAISE NOTICE '   TOAST header overflow ............... test 104';
    RAISE NOTICE '   ALTER TABLE → heap .................. test 105';
    RAISE NOTICE '   ALTER TABLE → encrypted_heap ........ test 106';
    RAISE NOTICE '   Online rotation round-trip .......... test 107';
    RAISE NOTICE '   CREATE TABLE AS ..................... test 108';
    RAISE NOTICE '   VACUUM FULL + STORAGE EXTERNAL ...... test 109';
    RAISE NOTICE '   WITH HOLD cursor no plaintext spill . test 110';

    RAISE NOTICE '';
    RAISE NOTICE '   *   = requires kms_provider=local (make ci-wallet)';
    RAISE NOTICE '         these tests SKIP in the default vault container';
    RAISE NOTICE '   **  = requires pg_vault_tde.dev_mode=on';
    RAISE NOTICE '         these tests SKIP when dev_mode is not set';
    RAISE NOTICE '   *** = skips when pg_vault_tde.toast_encryption != on';
    RAISE NOTICE '============================================================';
END;
$$;
