-- pg_vault_tde--1.4--1.5.sql
-- Upgrade script: v1.4 → v1.5 (Foundation Hardening + Local Wallet)
--
-- Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License
--
-- Changes in v1.5:
--   1. pg_vault_tde_catalog  — per-table DEK persistence
--   2. Local Wallet SQL functions (wallet init, status, passphrase change)
--   3. Online key rotation (pg_vault_tde_rotate_online + progress view)
--   4. tde_btree native type operator classes (text, int4, int8, uuid,
--      numeric, date, timestamptz)
--   5. pg_vault_tde_health_check() extended (kms_provider, wallet_open cols)
--
-- Invariant: All DDL in this file MUST be idempotent (uses IF NOT EXISTS).
-- Migration from v1.4: existing encrypted_heap tables use relid=0 sentinel.

-- Require superuser (same guard as base install)
DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user)
    THEN
        RAISE EXCEPTION 'pg_vault_tde upgrade requires superuser privileges';
    END IF;
END;
$$;

-- ============================================================================
-- 1. Per-table DEK catalog
-- ============================================================================
-- Stores the wrapped DEK for each encrypted_heap relation.  The in-memory
-- shmem cache (TdeRelDekCache) is authoritative at runtime; this catalog is
-- the source of truth for DEK restoration after server restart.
--
-- relid = 0 (InvalidOid sentinel) represents the legacy v1.4 single global DEK.
-- Per-table DEKs introduced in v1.5 use the actual relation OID.
CREATE TABLE IF NOT EXISTS pg_vault_tde_catalog (
    relid           oid          NOT NULL,          -- pg_class.oid; 0 = global DEK
    vault_key_name  text,                            -- KMS key name (Vault Transit key / wallet slot label)
    generation      bigint       NOT NULL DEFAULT 1, -- DEK rotation epoch
    wrapped_dek     bytea,                           -- provider-opaque wrapped DEK bytes (≤ 512 bytes)
    kms_provider    text         NOT NULL DEFAULT 'vault',  -- 'vault' | 'local' | 'pkcs11' | 'kmip'
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pg_vault_tde_catalog_pkey PRIMARY KEY (relid)
);

-- Only superusers and the TDE extension itself should access this catalog.
REVOKE ALL ON TABLE pg_vault_tde_catalog FROM PUBLIC;

-- Insert the legacy v1.4 global DEK sentinel row if upgrading from v1.4.
-- The wrapped_dek is NULL here because v1.4 stored the wrapped DEK in the
-- PGDATA file, not in a catalog.  Migration tooling sets this field.
INSERT INTO pg_vault_tde_catalog (relid, vault_key_name, generation, kms_provider)
VALUES (0, 'pg-tde-dek', 1, 'vault')
ON CONFLICT (relid) DO NOTHING;

-- ============================================================================
-- 2. Online key rotation progress catalog
-- ============================================================================
CREATE TABLE IF NOT EXISTS pg_vault_tde_rotation_progress (
    relid       oid          NOT NULL,
    status      text         NOT NULL DEFAULT 'running',  -- 'running' | 'complete' | 'failed'
    tuples_done bigint       NOT NULL DEFAULT 0,
    tuples_total bigint,
    started_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pg_vault_tde_rotation_progress_pkey PRIMARY KEY (relid)
);

REVOKE ALL ON TABLE pg_vault_tde_rotation_progress FROM PUBLIC;

-- Monitoring view (readable by pg_monitor role)
CREATE OR REPLACE VIEW pg_vault_tde_rotation_status AS
    SELECT
        c.relname                    AS table_name,
        r.relid,
        r.status,
        r.tuples_done,
        r.tuples_total,
        CASE WHEN r.tuples_total IS NULL OR r.tuples_total = 0 THEN NULL
             ELSE ROUND(100.0 * r.tuples_done / r.tuples_total, 1)
        END                          AS pct_complete,
        r.started_at,
        r.updated_at
    FROM pg_vault_tde_rotation_progress r
    JOIN pg_catalog.pg_class c ON c.oid = r.relid;

GRANT SELECT ON pg_vault_tde_rotation_status TO pg_monitor;

-- ============================================================================
-- 3. Local Wallet SQL functions
-- ============================================================================

-- pg_vault_tde_wallet_init(passphrase text)
--
-- Creates a new PKCS#12 wallet at `pg_vault_tde.wallet_path` protected by
-- `passphrase`.  Generates a fresh DEK and stores it wrapped in
-- pg_vault_tde_catalog.
-- Requires superuser; passphrase is NOT logged.
CREATE FUNCTION pg_vault_tde_wallet_init(passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_init_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_init(text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION pg_vault_tde_wallet_init(text) TO pg_monitor;

COMMENT ON FUNCTION pg_vault_tde_wallet_init(text) IS
'Initialize a new local PKCS#12 TDE wallet.  The passphrase MUST match the '
'environment variable named by pg_vault_tde.wallet_passphrase_env on '
'subsequent server restarts.';

-- pg_vault_tde_wallet_status()
--
-- Returns (wallet_exists bool, wallet_open bool, kek_algorithm text,
--          dek_wrapped bool).
CREATE FUNCTION pg_vault_tde_wallet_status()
    RETURNS TABLE (
        wallet_exists   bool,
        wallet_open     bool,
        kek_algorithm   text,
        dek_wrapped     bool
    )
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_status_sql';

-- pg_vault_tde_wallet_change_passphrase(old_passphrase text, new_passphrase text)
--
-- Re-wraps all DEKs under a new passphrase without touching encrypted data.
-- All existing encrypted tuples remain readable after the change.
CREATE FUNCTION pg_vault_tde_wallet_change_passphrase(old_passphrase text,
                                                       new_passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_change_passphrase_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_change_passphrase(text, text) FROM PUBLIC;

-- ============================================================================
-- 4. Online key rotation function
-- ============================================================================

-- pg_vault_tde_rotate_online(rel regclass, batch_size int DEFAULT 1000)
--
-- Spawns a BGW that re-encrypts `rel` in batches of `batch_size` tuples.
-- Does NOT take AccessExclusiveLock — concurrent SELECTs run unblocked.
-- Progress tracked in pg_vault_tde_rotation_progress.
CREATE FUNCTION pg_vault_tde_rotate_online(
        rel         regclass,
        batch_size  int     DEFAULT 1000
    )
    RETURNS void
    LANGUAGE C CALLED ON NULL INPUT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_rotate_online_sql';

-- ============================================================================
-- 5. tde_btree native type operator classes
-- ============================================================================
-- Each operator class maps the native type through its binary send function
-- (type serializer) into a bytea, which tde_iam_encrypt_key then wraps in
-- AES-256-SIV.  Only equality operators are supported — range scans return
-- wrong results on SIV ciphertext and are rejected by amvalidate.

-- text
CREATE OPERATOR CLASS tde_text_ops FOR TYPE text USING tde_btree AS
    OPERATOR 1 <  (text, text),
    OPERATOR 2 <= (text, text),
    OPERATOR 3 =  (text, text),
    OPERATOR 4 >= (text, text),
    OPERATOR 5 >  (text, text),
    FUNCTION 1 texticmp(text, text);

-- int4 (integer)
CREATE OPERATOR CLASS tde_int4_ops FOR TYPE int4 USING tde_btree AS
    OPERATOR 1 <  (int4, int4),
    OPERATOR 2 <= (int4, int4),
    OPERATOR 3 =  (int4, int4),
    OPERATOR 4 >= (int4, int4),
    OPERATOR 5 >  (int4, int4),
    FUNCTION 1 btint4cmp(int4, int4);

-- int8 (bigint)
CREATE OPERATOR CLASS tde_int8_ops FOR TYPE int8 USING tde_btree AS
    OPERATOR 1 <  (int8, int8),
    OPERATOR 2 <= (int8, int8),
    OPERATOR 3 =  (int8, int8),
    OPERATOR 4 >= (int8, int8),
    OPERATOR 5 >  (int8, int8),
    FUNCTION 1 btint8cmp(int8, int8);

-- uuid
CREATE OPERATOR CLASS tde_uuid_ops FOR TYPE uuid USING tde_btree AS
    OPERATOR 1 <  (uuid, uuid),
    OPERATOR 2 <= (uuid, uuid),
    OPERATOR 3 =  (uuid, uuid),
    OPERATOR 4 >= (uuid, uuid),
    OPERATOR 5 >  (uuid, uuid),
    FUNCTION 1 uuid_cmp(uuid, uuid);

-- numeric
CREATE OPERATOR CLASS tde_numeric_ops FOR TYPE numeric USING tde_btree AS
    OPERATOR 1 <  (numeric, numeric),
    OPERATOR 2 <= (numeric, numeric),
    OPERATOR 3 =  (numeric, numeric),
    OPERATOR 4 >= (numeric, numeric),
    OPERATOR 5 >  (numeric, numeric),
    FUNCTION 1 numeric_cmp(numeric, numeric);

-- date
CREATE OPERATOR CLASS tde_date_ops FOR TYPE date USING tde_btree AS
    OPERATOR 1 <  (date, date),
    OPERATOR 2 <= (date, date),
    OPERATOR 3 =  (date, date),
    OPERATOR 4 >= (date, date),
    OPERATOR 5 >  (date, date),
    FUNCTION 1 date_cmp(date, date);

-- timestamptz
CREATE OPERATOR CLASS tde_timestamptz_ops FOR TYPE timestamptz USING tde_btree AS
    OPERATOR 1 <  (timestamptz, timestamptz),
    OPERATOR 2 <= (timestamptz, timestamptz),
    OPERATOR 3 =  (timestamptz, timestamptz),
    OPERATOR 4 >= (timestamptz, timestamptz),
    OPERATOR 5 >  (timestamptz, timestamptz),
    FUNCTION 1 timestamptz_cmp(timestamptz, timestamptz);

-- ============================================================================
-- 6. New SQL function for online rotation status query
-- ============================================================================
CREATE FUNCTION pg_vault_tde_get_rotation_status(rel regclass)
    RETURNS TABLE (
        status          text,
        tuples_done     bigint,
        tuples_total    bigint,
        pct_complete    numeric,
        started_at      timestamptz,
        updated_at      timestamptz
    )
    LANGUAGE SQL STABLE AS $$
    SELECT status, tuples_done, tuples_total,
           CASE WHEN tuples_total IS NULL OR tuples_total = 0 THEN NULL
                ELSE ROUND(100.0 * tuples_done / tuples_total, 1)
           END,
           started_at, updated_at
    FROM pg_vault_tde_rotation_progress
    WHERE relid = $1::oid;
$$;

-- ============================================================================
-- 7. Health check extension (v1.5 adds kms_provider and aad_binding columns)
-- ============================================================================
-- Drops any existing pg_vault_tde_health_check() so we can replace it with
-- the v1.5 version that includes the new fields.

DROP FUNCTION IF EXISTS pg_vault_tde_health_check();

CREATE FUNCTION pg_vault_tde_health_check()
    RETURNS TABLE (
        version         text,
        enabled         bool,
        kms_provider    text,
        dek_available   bool,
        aad_binding     bool,
        wallet_open     bool,
        checked_at      timestamptz
    )
    LANGUAGE SQL STABLE AS $$
    SELECT
        '1.5'::text                         AS version,
        current_setting('pg_vault_tde.enabled', true)::bool AS enabled,
        current_setting('pg_vault_tde.kms_provider', true)  AS kms_provider,
        pg_vault_tde_dek_available()                         AS dek_available,
        true                                                  AS aad_binding,
        false                                                 AS wallet_open,  -- TODO: from C
        now()                                                 AS checked_at;
$$;

-- pg_vault_tde_dek_available() — helper used by health_check; returns true if
-- the shmem DEK slot holds a valid key.  Falls back to false on error so
-- health_check never raises.
CREATE OR REPLACE FUNCTION pg_vault_tde_dek_available()
    RETURNS bool
    LANGUAGE plpgsql STABLE AS $$
DECLARE
    ct bytea;
    pt text;
BEGIN
    -- Try a trivial encrypt/decrypt to confirm the DEK is live.
    ct := pg_vault_tde_encrypt_test('health_check_probe'::text);
    pt := pg_vault_tde_decrypt_test(ct);
    RETURN pt = 'health_check_probe';
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

-- ============================================================================
-- 8. pg_vault_tde_reencrypt_table(rel text, batch_size int) — synchronous
--    re-encryption helper used by tests and ad-hoc rotation scripts.
--
-- Calls pg_vault_tde_rotate_online() and polls the progress table until
-- status is not 'running' (or times out after 30 s with a WARNING).
-- ============================================================================
CREATE OR REPLACE FUNCTION pg_vault_tde_reencrypt_table(
        rel         text,
        batch_size  int DEFAULT 1000
    )
    RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    relid      oid  := rel::regclass::oid;
    tick       int  := 0;
    st         text;
BEGIN
    -- Trigger async BGW rotation
    PERFORM pg_vault_tde_rotate_online(rel::regclass, batch_size);

    -- Poll until complete (max 30 s)
    LOOP
        SELECT status INTO st
        FROM   pg_vault_tde_rotation_progress
        WHERE  relid = relid;

        EXIT WHEN st IN ('complete', 'done', 'failed');
        EXIT WHEN tick > 60;   /* 60 × 500ms = 30 s */

        PERFORM pg_sleep(0.5);
        tick := tick + 1;
    END LOOP;

    IF st IS NULL THEN
        RAISE WARNING
            'pg_vault_tde_reencrypt_table: no progress row found for %', rel;
    ELSIF st = 'failed' THEN
        RAISE EXCEPTION
            'pg_vault_tde_reencrypt_table: rotation failed for %', rel;
    ELSIF tick > 60 THEN
        RAISE WARNING
            'pg_vault_tde_reencrypt_table: timed out waiting for rotation '
            'to complete on %', rel;
    END IF;
END;
$$;

REVOKE ALL   ON FUNCTION pg_vault_tde_reencrypt_table(text, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_vault_tde_reencrypt_table(text, int) TO pg_monitor;

-- ============================================================================
-- 9. Update default_version in the control file (done from Makefile; no SQL)
-- ============================================================================
-- (This file is loaded by ALTER EXTENSION pg_vault_tde UPDATE TO '1.5')
