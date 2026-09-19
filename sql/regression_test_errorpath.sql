-- regression_test_errorpath.sql — TDE tests 141-153 for pg_vault_tde
--
-- ERROR-PATH COVERAGE.
--
-- Every other regression file exercises the success path.  This one exercises
-- the PG_CATCH blocks: the code that only ever runs after a longjmp.  Those
-- handlers cleanse plaintext key material and free intermediates, so a bug
-- there leaks decrypted data or double-frees — and no success-path test can
-- ever reach it.
--
-- Mechanism: pg_vault_tde_wallet_lock() flushes the DEK from shmem, so the
-- next tde_gcm_encrypt() raises
--     ERROR: [CRYPTO] DEK unavailable for relid=N; cannot encrypt data
-- from inside tde_encrypt_heap_tuple() — which sits inside the PG_TRY of
-- every write path.  Each failing statement therefore unwinds through one
-- of the handlers under test.
--
-- Handlers covered (src/tam/pg_vault_tde_tam.c, src/tam/pg_vault_tde_toast.c):
--   pg_vault_tde_tuple_insert              → test 141
--   pg_vault_tde_multi_insert              → tests 142, 143
--   pg_vault_tde_tuple_update              → test 144
--   pg_vault_tde_tuple_insert_speculative  → test 145
--   pg_vault_tde_relation_copy_for_cluster → tests 146, 147
--   pg_vault_tde_toast_save_datum          → test 143
--
-- REQUIREMENTS (see ci/scripts/run-errorpath.sh):
--   - kms_provider=local, wallet_auto_open=off
--   - pg_vault_tde.wallet_dev_mode_passphrase MUST NOT be set.  With that GUC
--     the wallet silently re-opens itself on the next DEK request and every
--     statement below succeeds instead of failing — the tests then pass
--     vacuously.  Test 141 detects that and aborts.
--   - A SINGLE psql session: the unlocked-wallet state is per-backend, so
--     splitting the script across connections breaks the lock.
--   - superuser (pg_read_binary_file in tests 150-151)
--
-- Exit-on-error: any failed assertion aborts the script.
\set ON_ERROR_STOP on

\set PASSPHRASE 'tde_errorpath_pass_2026'
\set ITERATIONS 25

-- ================================================================
-- SETUP: initialise the wallet, build the fixture, take a baseline.
--
-- Two sentinels: one in a small (inline) column and one in a
-- TOAST-sized column, so tests 150-151 can look for plaintext in
-- both the main fork and the TOAST relation.
-- ================================================================
SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
SELECT pg_vault_tde_wallet_unlock(:'PASSPHRASE');

DROP TABLE IF EXISTS tde_errpath_141;
CREATE TABLE tde_errpath_141 (
    id    int primary key,
    small text,
    big   text
) USING encrypted_heap;

-- STORAGE EXTERNAL is load-bearing, not a detail.  The sentinel below is a
-- repeating 15-byte pattern, so with the default EXTENDED storage PostgreSQL
-- compresses 18 kB down to a few hundred bytes, keeps it inline, and the TOAST
-- relation stays empty — test 151 would then scan a 0-byte file and pass
-- without checking anything.  EXTERNAL forces out-of-line, uncompressed
-- storage, so the plaintext sentinel WOULD appear verbatim in the TOAST file
-- if the chunk writer ever stopped encrypting.
ALTER TABLE tde_errpath_141 ALTER COLUMN big SET STORAGE EXTERNAL;

INSERT INTO tde_errpath_141
SELECT g,
       'SENTINEL_SMALL_' || g,
       repeat('SENTINEL_TOAST_', 1200)
FROM generate_series(1, 50) g;

DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM tde_errpath_141;
    IF n <> 50 THEN
        RAISE EXCEPTION
            'ERROR-PATH SETUP FAILED: expected 50 baseline rows, got %', n;
    END IF;
END $$;

-- Flush the DEK.  Everything after this point must fail to encrypt.
SELECT pg_vault_tde_wallet_lock();

-- ================================================================
-- TEST 141: tuple_insert error path
--
-- Also the guard for the whole file: if the DEK is still reachable
-- (wallet_dev_mode_passphrase set, or lock() regressed) the INSERT
-- succeeds and every later test would pass vacuously.  Fail loudly.
-- ================================================================
DO $$
DECLARE
    caught int := 0;
    i      int;
BEGIN
    FOR i IN 1..25 LOOP
        BEGIN
            INSERT INTO tde_errpath_141 VALUES (1000 + i, 'x', 'y');
            RAISE EXCEPTION
                'TEST 141 FAILED: INSERT succeeded with the wallet locked — '
                'the DEK is still reachable, so the error paths are NOT being '
                'exercised.  Is pg_vault_tde.wallet_dev_mode_passphrase set?';
        EXCEPTION
            WHEN SQLSTATE 'P0001' THEN
                RAISE;                      -- our own assertion above
            WHEN OTHERS THEN
                caught := caught + 1;       -- expected: DEK unavailable
        END;
    END LOOP;

    IF caught <> 25 THEN
        RAISE EXCEPTION
            'TEST 141 FAILED: expected 25 caught errors, got %', caught;
    END IF;
    RAISE NOTICE
        'TEST 141 PASSED: tuple_insert PG_CATCH unwound % times, backend alive',
        caught;
END $$;

-- ================================================================
-- TEST 144: tuple_update error path
-- ================================================================
DO $$
DECLARE
    caught int := 0;
    i      int;
BEGIN
    FOR i IN 1..25 LOOP
        BEGIN
            UPDATE tde_errpath_141 SET small = 'changed' WHERE id = (i % 50) + 1;
            RAISE EXCEPTION 'TEST 144 FAILED: UPDATE succeeded with wallet locked';
        EXCEPTION
            WHEN SQLSTATE 'P0001' THEN RAISE;
            WHEN OTHERS THEN caught := caught + 1;
        END;
    END LOOP;

    IF caught <> 25 THEN
        RAISE EXCEPTION 'TEST 144 FAILED: expected 25 caught errors, got %', caught;
    END IF;
    RAISE NOTICE
        'TEST 144 PASSED: tuple_update PG_CATCH unwound % times, backend alive',
        caught;
END $$;

-- ================================================================
-- TEST 145: tuple_insert_speculative error path (ON CONFLICT / UPSERT)
-- ================================================================
DO $$
DECLARE
    caught int := 0;
    i      int;
BEGIN
    FOR i IN 1..25 LOOP
        BEGIN
            INSERT INTO tde_errpath_141 VALUES ((i % 50) + 1, 'u', 'v')
            ON CONFLICT (id) DO UPDATE SET small = 'u';
            RAISE EXCEPTION 'TEST 145 FAILED: UPSERT succeeded with wallet locked';
        EXCEPTION
            WHEN SQLSTATE 'P0001' THEN RAISE;
            WHEN OTHERS THEN caught := caught + 1;
        END;
    END LOOP;

    IF caught <> 25 THEN
        RAISE EXCEPTION 'TEST 145 FAILED: expected 25 caught errors, got %', caught;
    END IF;
    RAISE NOTICE
        'TEST 145 PASSED: tuple_insert_speculative PG_CATCH unwound % times',
        caught;
END $$;

-- ================================================================
-- Tests 142, 143, 146, 147 use statements that cannot run inside
-- plpgsql (COPY needs a client/program channel; VACUUM FULL and
-- CLUSTER need their own transaction).  They run at top level with
-- ON_ERROR_STOP disabled; test 148 then asserts the table is
-- byte-for-byte unchanged, which is what proves they all aborted.
-- ================================================================
\set ON_ERROR_STOP off

-- ---- TEST 142: multi_insert error path, SMALL rows --------------
-- 100 rows per COPY so heap_multi_insert really batches.  Small rows
-- skip TOASTing, so pg_vault_tde_toast_insert_or_update returns the
-- input tuple unchanged and toasted_inflight aliases plain_inflight —
-- the case where an unguarded pfree() in the handler double-frees.
\echo '-- TEST 142: multi_insert (small rows, aliased toasted/plain) x10'
COPY tde_errpath_141 FROM PROGRAM 'seq 100000 100099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 101000 101099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 102000 102099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 103000 103099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 104000 104099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 105000 105099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 106000 106099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 107000 107099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 108000 108099 | sed "s/$/\tsmallrow\tsmall/"';
COPY tde_errpath_141 FROM PROGRAM 'seq 109000 109099 | sed "s/$/\tsmallrow\tsmall/"';

-- ---- TEST 143: multi_insert + toast_save_datum error path --------
-- 12 kB payloads force the custom TOAST chunk writer, so the failure
-- unwinds through pg_vault_tde_toast_save_datum's inner PG_CATCH
-- (chunk_enc) as well as multi_insert's.
\echo '-- TEST 143: multi_insert + TOAST chunk writer x10'
COPY tde_errpath_141 FROM PROGRAM 'for n in $(seq 200000 200009); do printf "%s\tbigrow\t" $n; head -c 12000 /dev/zero | tr "\0" Z; echo; done';
COPY tde_errpath_141 FROM PROGRAM 'for n in $(seq 201000 201009); do printf "%s\tbigrow\t" $n; head -c 12000 /dev/zero | tr "\0" Z; echo; done';
COPY tde_errpath_141 FROM PROGRAM 'for n in $(seq 202000 202009); do printf "%s\tbigrow\t" $n; head -c 12000 /dev/zero | tr "\0" Z; echo; done';
COPY tde_errpath_141 FROM PROGRAM 'for n in $(seq 203000 203009); do printf "%s\tbigrow\t" $n; head -c 12000 /dev/zero | tr "\0" Z; echo; done';
COPY tde_errpath_141 FROM PROGRAM 'for n in $(seq 204000 204009); do printf "%s\tbigrow\t" $n; head -c 12000 /dev/zero | tr "\0" Z; echo; done';

-- ---- TEST 146: relation_copy_for_cluster error path (VACUUM FULL) -
-- This is the handler that had the real -Wclobbered bug: plain,
-- plain_for_write and enc_new are assigned inside PG_TRY(2) and read
-- by PG_CATCH(2), so without volatile the OPENSSL_cleanse is skipped.
\echo '-- TEST 146: relation_copy_for_cluster via VACUUM FULL x10'
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;
VACUUM FULL tde_errpath_141;

-- ---- TEST 147: relation_copy_for_cluster error path (CLUSTER) ----
\echo '-- TEST 147: relation_copy_for_cluster via CLUSTER x10'
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;

\set ON_ERROR_STOP on

-- Restore the DEK for the verification phase.
SELECT pg_vault_tde_wallet_unlock(:'PASSPHRASE');

-- ================================================================
-- Verdict for tests 142/143/146/147.
--
-- These ran at top level, so their failure cannot be caught in
-- plpgsql — but it is directly observable: each COPY would have
-- added 100 (or 10) rows and each rewrite would have replaced the
-- heap.  An unchanged 50-row fixture means all 40 statements aborted
-- inside the handler under test, and the backend stayed alive to run
-- this block.
-- ================================================================
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM tde_errpath_141;
    IF n <> 50 THEN
        RAISE EXCEPTION
            'TESTS 142/143/146/147 FAILED: fixture has % rows, expected 50 — '
            'a COPY/VACUUM FULL/CLUSTER committed instead of aborting', n;
    END IF;
    RAISE NOTICE 'TEST 142 PASSED: multi_insert PG_CATCH x10 batched COPY (small rows)';
    RAISE NOTICE 'TEST 143 PASSED: multi_insert + toast_save_datum PG_CATCH x5';
    RAISE NOTICE 'TEST 146 PASSED: relation_copy_for_cluster PG_CATCH x10 (VACUUM FULL)';
    RAISE NOTICE 'TEST 147 PASSED: relation_copy_for_cluster PG_CATCH x10 (CLUSTER)';
END $$;

-- ================================================================
-- TEST 148: the fixture survived the error storm unchanged.
--
-- This is what proves tests 142/143/146/147 actually aborted: had any
-- COPY committed, the count would have jumped by 100 (or 10); had any
-- VACUUM FULL / CLUSTER committed it would have rewritten the heap.
-- ================================================================
DO $$
DECLARE
    n       bigint;
    bad_sm  bigint;
BEGIN
    SELECT count(*) INTO n FROM tde_errpath_141;
    IF n <> 50 THEN
        RAISE EXCEPTION
            'TEST 148 FAILED: expected 50 rows after the error storm, got % — '
            'a statement that should have aborted committed instead', n;
    END IF;

    SELECT count(*) INTO bad_sm
    FROM tde_errpath_141
    WHERE small IS DISTINCT FROM 'SENTINEL_SMALL_' || id;
    IF bad_sm <> 0 THEN
        RAISE EXCEPTION
            'TEST 148 FAILED: % inline values corrupted by an aborted write',
            bad_sm;
    END IF;

    RAISE NOTICE
        'TEST 148 PASSED: 50/50 rows intact after 145 aborted writes';
END $$;

-- ================================================================
-- TEST 149: TOAST payloads still decrypt byte-for-byte.
--
-- The aborted TOAST writes went through the custom chunk writer and
-- its PG_CATCH.  If that handler freed or cleansed the wrong buffer,
-- the pre-existing chunks would come back damaged.
-- ================================================================
DO $$
DECLARE
    bad bigint;
BEGIN
    SELECT count(*) INTO bad
    FROM tde_errpath_141
    WHERE big IS DISTINCT FROM repeat('SENTINEL_TOAST_', 1200);
    IF bad <> 0 THEN
        RAISE EXCEPTION
            'TEST 149 FAILED: % TOAST payloads damaged by an aborted write', bad;
    END IF;
    RAISE NOTICE
        'TEST 149 PASSED: 50/50 TOAST payloads byte-identical after aborts';
END $$;

-- ================================================================
-- TEST 150: no plaintext in the main fork after the error storm.
--
-- A PG_CATCH that skips its OPENSSL_cleanse leaves decrypted bytes in
-- a palloc chunk, not on disk — but a handler that freed the WRONG
-- buffer could let an unencrypted tuple reach the heap.  Check both
-- sentinels against the physical file.
-- ================================================================
CHECKPOINT;

DO $$
DECLARE
    fp   text;
    raw  bytea;
    hit1 int;
    hit2 int;
BEGIN
    SELECT pg_relation_filepath('tde_errpath_141') INTO fp;
    raw  := pg_read_binary_file(fp);
    hit1 := position('SENTINEL_SMALL_'::bytea in raw);
    hit2 := position('SENTINEL_TOAST_'::bytea in raw);

    IF hit1 <> 0 OR hit2 <> 0 THEN
        RAISE EXCEPTION
            'TEST 150 FAILED: plaintext found in heap file % '
            '(SENTINEL_SMALL_ at %, SENTINEL_TOAST_ at %)', fp, hit1, hit2;
    END IF;
    RAISE NOTICE
        'TEST 150 PASSED: no plaintext in main fork (% bytes scanned)',
        length(raw);
END $$;

-- ================================================================
-- TEST 151: no plaintext in the TOAST relation after the error storm.
-- ================================================================
DO $$
DECLARE
    fp   text;
    raw  bytea;
    hit  int;
BEGIN
    SELECT pg_relation_filepath(reltoastrelid) INTO fp
    FROM pg_class WHERE oid = 'tde_errpath_141'::regclass;

    IF fp IS NULL THEN
        RAISE EXCEPTION 'TEST 151 FAILED: table has no TOAST relation';
    END IF;

    raw := pg_read_binary_file(fp);

    -- Guard against a vacuous pass: an empty TOAST file means the payload
    -- never went out of line (compression, or a too-small sentinel), so
    -- "no plaintext found" would prove nothing.
    IF length(raw) < 8192 THEN
        RAISE EXCEPTION
            'TEST 151 FAILED: TOAST file % is % bytes — the payload never went '
            'out of line, so this check is vacuous (is STORAGE EXTERNAL set?)',
            fp, length(raw);
    END IF;

    hit := position('SENTINEL_TOAST_'::bytea in raw);

    IF hit <> 0 THEN
        RAISE EXCEPTION
            'TEST 151 FAILED: plaintext found in TOAST file % at offset %',
            fp, hit;
    END IF;
    RAISE NOTICE
        'TEST 151 PASSED: no plaintext in TOAST relation (% bytes scanned)',
        length(raw);
END $$;

-- ================================================================
-- TEST 152: the relation is still fully writable and readable.
--
-- Proves the backend recovered: after 145 longjmps through the write
-- paths, every path still works and round-trips correctly.
-- ================================================================
DO $$
DECLARE
    got text;
    n   bigint;
BEGIN
    INSERT INTO tde_errpath_141 VALUES (9001, 'after_storm', repeat('R', 9000));
    UPDATE tde_errpath_141 SET small = 'after_storm_upd' WHERE id = 9001;

    SELECT small INTO got FROM tde_errpath_141 WHERE id = 9001;
    IF got IS DISTINCT FROM 'after_storm_upd' THEN
        RAISE EXCEPTION
            'TEST 152 FAILED: post-storm round-trip returned %',
            COALESCE(got, '<NULL>');
    END IF;

    SELECT count(*) INTO n FROM tde_errpath_141 WHERE big = repeat('R', 9000);
    IF n <> 1 THEN
        RAISE EXCEPTION
            'TEST 152 FAILED: post-storm TOAST round-trip returned % rows', n;
    END IF;

    DELETE FROM tde_errpath_141 WHERE id = 9001;
    RAISE NOTICE
        'TEST 152 PASSED: all write paths healthy after the error storm';
END $$;

-- VACUUM FULL and CLUSTER must work again too (relation_copy_for_cluster
-- on the success path, with the DEK back).
VACUUM FULL tde_errpath_141;
CLUSTER tde_errpath_141 USING tde_errpath_141_pkey;

DO $$
DECLARE
    bad bigint;
BEGIN
    SELECT count(*) INTO bad
    FROM tde_errpath_141
    WHERE small IS DISTINCT FROM 'SENTINEL_SMALL_' || id
       OR big   IS DISTINCT FROM repeat('SENTINEL_TOAST_', 1200);
    IF bad <> 0 THEN
        RAISE EXCEPTION
            'TEST 152 FAILED: % rows damaged by post-storm VACUUM FULL/CLUSTER',
            bad;
    END IF;
    RAISE NOTICE
        'TEST 152 PASSED: VACUUM FULL + CLUSTER rewrote 50/50 rows correctly';
END $$;

-- ================================================================
-- TEST 153: core must not re-TOAST the ciphertext (crash regression)
--
-- heap_toast_insert_or_update() fires on EITHER of two triggers: the tuple
-- carrying external attributes, or the tuple exceeding TOAST_TUPLE_THRESHOLD.
-- tde_encrypt_heap_tuple() clears HEAP_HASEXTERNAL, which covers the first.
-- The second is covered by clearing reltoastrelid around the core call.
--
-- Without that second half, a value whose PLAINTEXT tuple sits just under the
-- threshold -- so the pre-TOAST gate declines it -- lands just OVER once
-- TDE_V4_OVERHEAD bytes of AES-GCM overhead are added.  Core then deforms the
-- ciphertext as if it were varlena attributes and toast_save_datum()
-- segfaults, taking the backend with it.
--
-- The window is only as wide as that overhead, so this test sweeps the
-- boundary rather than picking one size: 2000 bytes crashed while 1995 and
-- 2005 were fine.  A single-size test would have missed it.
--
-- History: the suppression existed until commit ecea635, which replaced it
-- with the HEAP_HASEXTERNAL clearing alone.  Found by
-- test/isolation/specs/encrypted_rewrite_concurrency.spec.
-- ================================================================
DROP TABLE IF EXISTS tde_toast_boundary;
CREATE TABLE tde_toast_boundary (id int PRIMARY KEY, payload text)
    USING encrypted_heap;
ALTER TABLE tde_toast_boundary ALTER COLUMN payload SET STORAGE EXTERNAL;

DO $$
DECLARE
    len  int;
    got  int;
BEGIN
    -- Sweep TOAST_TUPLE_THRESHOLD (2032) from well below to well above, in
    -- steps finer than the encryption overhead so the window cannot be
    -- stepped over.
    FOR len IN 1960..2100 BY 5 LOOP
        INSERT INTO tde_toast_boundary VALUES (len, repeat('x', len));

        SELECT length(payload) INTO got
        FROM tde_toast_boundary WHERE id = len;

        IF got IS DISTINCT FROM len THEN
            RAISE EXCEPTION
                'TEST 153 FAILED: payload of % bytes read back as %',
                len, COALESCE(got::text, '<NULL>');
        END IF;
    END LOOP;

    -- UPDATE and the speculative path cross the same boundary.
    UPDATE tde_toast_boundary SET payload = repeat('y', 2000) WHERE id = 2000;
    INSERT INTO tde_toast_boundary VALUES (2000, repeat('z', 2000))
        ON CONFLICT (id) DO UPDATE SET payload = repeat('w', 2000);

    SELECT length(payload) INTO got
    FROM tde_toast_boundary WHERE id = 2000;
    IF got <> 2000 THEN
        RAISE EXCEPTION 'TEST 153 FAILED: boundary row damaged by UPDATE/UPSERT';
    END IF;

    RAISE NOTICE
        'TEST 153 PASSED: 29 sizes across TOAST_TUPLE_THRESHOLD, plus UPDATE '
        'and UPSERT at the boundary, all round-trip intact';
END $$;

-- COPY reaches heap_multi_insert, a different core entry point with the same
-- TOAST trigger.
COPY tde_toast_boundary FROM PROGRAM
    'for n in $(seq 3000 3040); do printf "%s\t" $n; head -c 2000 /dev/zero | tr "\0" q; echo; done';

DO $$
DECLARE
    bad int;
BEGIN
    SELECT count(*) INTO bad FROM tde_toast_boundary
    WHERE id BETWEEN 3000 AND 3040 AND length(payload) <> 2000;
    IF bad <> 0 THEN
        RAISE EXCEPTION 'TEST 153 FAILED: % boundary rows damaged by COPY', bad;
    END IF;
    RAISE NOTICE 'TEST 153 PASSED: multi_insert at the boundary, 41 rows intact';
END $$;

DROP TABLE tde_toast_boundary;

DROP TABLE tde_errpath_141;

\echo ''
\echo '=============================================================='
\echo '  ERROR-PATH REGRESSION COMPLETE: TESTS 141-153 PASSED'
\echo '=============================================================='
