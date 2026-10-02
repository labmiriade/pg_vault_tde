-- valgrind_workload.sql — memcheck exercise for pg_vault_tde
--
-- Driven by ci/scripts/run-valgrind.sh, which runs the postmaster under
-- Valgrind memcheck.  Memcheck costs 10-50x, so this deliberately trades
-- breadth for cost: small row counts, but every crypto-touching code path
-- at least once, success path AND error path.
--
-- What it is looking for, in order of how much it would hurt in production:
--   - invalid free / double free       (PG_CATCH cleanup handlers)
--   - invalid read/write               (buffer arithmetic in encrypt/decrypt)
--   - use of uninitialised values      (IV/tag/DEK buffers, wire-format headers)
--   - definite leaks of malloc'd state (libcurl handles; palloc is suppressed)
--
-- Requires: kms_provider=local, wallet_auto_open=off, and NO
-- wallet_dev_mode_passphrase (see run-errorpath.sh for why).
\set ON_ERROR_STOP on
\set PASSPHRASE 'tde_valgrind_pass_2026'

SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
SELECT pg_vault_tde_wallet_unlock(:'PASSPHRASE');

-- ---- Success paths ------------------------------------------------------
CREATE TABLE vg_t (id int primary key, small text, big text) USING encrypted_heap;
ALTER TABLE vg_t ALTER COLUMN big SET STORAGE EXTERNAL;

-- tuple_insert + toast_save_datum
INSERT INTO vg_t SELECT g, 'row_' || g, repeat('V', 9000) FROM generate_series(1, 20) g;

-- multi_insert (batched COPY, small rows: toasted aliases plain)
COPY vg_t FROM PROGRAM 'seq 1000 1049 | sed "s/$/\tcopied\tsmall/"';

-- multi_insert + custom TOAST chunk writer
COPY vg_t FROM PROGRAM 'for n in $(seq 2000 2004); do printf "%s\tbig\t" $n; head -c 9000 /dev/zero | tr "\0" W; echo; done';

-- decrypt paths: seqscan, index scan, bitmap
SELECT count(*) FROM vg_t;
SELECT count(*) FROM vg_t WHERE big = repeat('V', 9000);
SET enable_seqscan = off;
SELECT small FROM vg_t WHERE id = 7;
RESET enable_seqscan;

-- tuple_update (inline and TOAST-replacing), tuple_delete
UPDATE vg_t SET small = 'updated' WHERE id <= 5;
UPDATE vg_t SET big = repeat('X', 9500) WHERE id = 3;
DELETE FROM vg_t WHERE id BETWEEN 1000 AND 1009;

-- tuple_insert_speculative
INSERT INTO vg_t VALUES (7, 'spec', repeat('S', 9000))
ON CONFLICT (id) DO UPDATE SET small = 'spec_upd';

-- tde_btree encrypted index keys (AES-256-SIV path)
CREATE INDEX vg_idx ON vg_t USING tde_btree (id tde_int4_enc_ops);
SET enable_seqscan = off;
SELECT count(*) FROM vg_t WHERE id = 11;
RESET enable_seqscan;

-- relation_copy_for_cluster, success path, with external TOAST to migrate
VACUUM FULL vg_t;
CLUSTER vg_t USING vg_t_pkey;
SELECT count(*) FROM vg_t WHERE big = repeat('V', 9000);

-- ---- Error paths --------------------------------------------------------
-- The whole reason this workload is worth its runtime: the PG_CATCH handlers
-- cleanse key material and free intermediates, and memcheck is the only tool
-- here that can see a double free or a cleanse of the wrong buffer.
SELECT pg_vault_tde_wallet_lock();
\set ON_ERROR_STOP off

INSERT INTO vg_t VALUES (5000, 'x', 'y');
UPDATE vg_t SET small = 'nope' WHERE id = 11;
INSERT INTO vg_t VALUES (11, 'u', 'v') ON CONFLICT (id) DO UPDATE SET small = 'u';
COPY vg_t FROM PROGRAM 'seq 6000 6049 | sed "s/$/\tsmallrow\tsmall/"';
COPY vg_t FROM PROGRAM 'for n in $(seq 7000 7004); do printf "%s\tbig\t" $n; head -c 9000 /dev/zero | tr "\0" Z; echo; done';
VACUUM FULL vg_t;
CLUSTER vg_t USING vg_t_pkey;

\set ON_ERROR_STOP on
SELECT pg_vault_tde_wallet_unlock(:'PASSPHRASE');

-- Prove the backend recovered and the data is intact after the error storm.
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM vg_t WHERE big = repeat('V', 9000);
    IF n = 0 THEN
        RAISE EXCEPTION 'VALGRIND WORKLOAD FAILED: TOAST payloads lost';
    END IF;
    RAISE NOTICE 'valgrind workload: % TOAST rows intact after error storm', n;
END $$;

DROP TABLE vg_t;
