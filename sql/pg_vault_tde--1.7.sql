-- pg_vault_tde--1.7.sql
-- Extension install script for pg_vault_tde v1.7 (consolidated)
--
-- Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License
--
-- Fresh installation at v1.7.  For upgrades from older versions, use the
-- ALTER EXTENSION UPDATE path (scripts pg_vault_tde--1.0--1.4.sql, etc.).

-- ============================================================================
-- Superuser guard
-- ============================================================================
DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user)
    THEN
        RAISE EXCEPTION 'pg_vault_tde requires superuser privileges to install';
    END IF;
END;
$$;

-- ============================================================================
-- Access method handler functions (must precede CREATE ACCESS METHOD)
-- ============================================================================
CREATE FUNCTION pg_vault_tde_tableam_handler(internal)
    RETURNS table_am_handler
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_tableam_handler';

CREATE FUNCTION pg_vault_tde_iam_handler(internal)
    RETURNS index_am_handler
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_iam_handler';

-- ============================================================================
-- Access methods
-- ============================================================================
CREATE ACCESS METHOD encrypted_heap
    TYPE TABLE
    HANDLER pg_vault_tde_tableam_handler;

CREATE ACCESS METHOD tde_btree
    TYPE INDEX
    HANDLER pg_vault_tde_iam_handler;

COMMENT ON ACCESS METHOD encrypted_heap IS
    'pg_vault_tde Table Access Method: AES-256-GCM transparent encryption via Vault/OpenBao';
COMMENT ON ACCESS METHOD tde_btree IS
    'pg_vault_tde Index Access Method: AES-256-SIV deterministic encryption for B-Tree indexes';

-- ============================================================================
-- v1.5 plaintext operator classes for tde_btree
--
-- bytea, text, numeric remain DEFAULT.
-- int4, int8, uuid, date, timestamptz are kept for backwards compatibility
-- but are NOT DEFAULT — the v1.7 enc_ops classes are the defaults for those.
-- ============================================================================

CREATE OPERATOR CLASS tde_bytea_ops DEFAULT FOR TYPE bytea USING tde_btree AS
    OPERATOR 1 <  (bytea, bytea),
    OPERATOR 2 <= (bytea, bytea),
    OPERATOR 3 =  (bytea, bytea),
    OPERATOR 4 >= (bytea, bytea),
    OPERATOR 5 >  (bytea, bytea),
    FUNCTION 1 byteacmp(bytea, bytea);

CREATE OPERATOR CLASS tde_text_ops DEFAULT FOR TYPE text USING tde_btree AS
    OPERATOR 1 <  (text, text),
    OPERATOR 2 <= (text, text),
    OPERATOR 3 =  (text, text),
    OPERATOR 4 >= (text, text),
    OPERATOR 5 >  (text, text),
    FUNCTION 1 bttextcmp(text, text);

-- NOT DEFAULT: superseded by tde_int4_enc_ops in v1.7
CREATE OPERATOR CLASS tde_int4_ops FOR TYPE int4 USING tde_btree AS
    OPERATOR 1 <  (int4, int4),
    OPERATOR 2 <= (int4, int4),
    OPERATOR 3 =  (int4, int4),
    OPERATOR 4 >= (int4, int4),
    OPERATOR 5 >  (int4, int4),
    FUNCTION 1 btint4cmp(int4, int4);

-- NOT DEFAULT: superseded by tde_int8_enc_ops in v1.7
CREATE OPERATOR CLASS tde_int8_ops FOR TYPE int8 USING tde_btree AS
    OPERATOR 1 <  (int8, int8),
    OPERATOR 2 <= (int8, int8),
    OPERATOR 3 =  (int8, int8),
    OPERATOR 4 >= (int8, int8),
    OPERATOR 5 >  (int8, int8),
    FUNCTION 1 btint8cmp(int8, int8);

-- NOT DEFAULT: superseded by tde_uuid_enc_ops in v1.7
CREATE OPERATOR CLASS tde_uuid_ops FOR TYPE uuid USING tde_btree AS
    OPERATOR 1 <  (uuid, uuid),
    OPERATOR 2 <= (uuid, uuid),
    OPERATOR 3 =  (uuid, uuid),
    OPERATOR 4 >= (uuid, uuid),
    OPERATOR 5 >  (uuid, uuid),
    FUNCTION 1 uuid_cmp(uuid, uuid);

CREATE OPERATOR CLASS tde_numeric_ops DEFAULT FOR TYPE numeric USING tde_btree AS
    OPERATOR 1 <  (numeric, numeric),
    OPERATOR 2 <= (numeric, numeric),
    OPERATOR 3 =  (numeric, numeric),
    OPERATOR 4 >= (numeric, numeric),
    OPERATOR 5 >  (numeric, numeric),
    FUNCTION 1 numeric_cmp(numeric, numeric);

-- NOT DEFAULT: superseded by tde_date_enc_ops in v1.7
CREATE OPERATOR CLASS tde_date_ops FOR TYPE date USING tde_btree AS
    OPERATOR 1 <  (date, date),
    OPERATOR 2 <= (date, date),
    OPERATOR 3 =  (date, date),
    OPERATOR 4 >= (date, date),
    OPERATOR 5 >  (date, date),
    FUNCTION 1 date_cmp(date, date);

-- NOT DEFAULT: superseded by tde_timestamptz_enc_ops in v1.7
CREATE OPERATOR CLASS tde_timestamptz_ops FOR TYPE timestamptz USING tde_btree AS
    OPERATOR 1 <  (timestamptz, timestamptz),
    OPERATOR 2 <= (timestamptz, timestamptz),
    OPERATOR 3 =  (timestamptz, timestamptz),
    OPERATOR 4 >= (timestamptz, timestamptz),
    OPERATOR 5 >  (timestamptz, timestamptz),
    FUNCTION 1 timestamptz_cmp(timestamptz, timestamptz);

-- ============================================================================
-- v1.7 enc_ops: AES-256-SIV encrypted-key operator classes (STORAGE bytea)
-- ============================================================================
-- tde_enc_bytea_cmp: three-way memcmp comparator for SIV ciphertexts stored
-- as bytea.  Used as btree support function 1 for all enc_ops classes.
CREATE FUNCTION tde_enc_bytea_cmp(bytea, bytea)
    RETURNS integer
    LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_enc_bytea_cmp';

COMMENT ON FUNCTION tde_enc_bytea_cmp(bytea, bytea) IS
'Three-way comparator for AES-256-SIV encrypted index keys stored as bytea. '
'Used as btree support function 1 for tde_*_enc_ops operator classes. '
'Ordering is memcmp-based and has no semantic meaning; equality is preserved.';

-- Per-type SQL wrappers: index_getprocinfo looks up support function 1 using
-- opcintype (e.g. int4) as both lefttype/righttype — NOT the STORAGE type.
CREATE FUNCTION tde_int4_enc_cmp(int4, int4)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_enc_bytea_cmp';

CREATE FUNCTION tde_int8_enc_cmp(int8, int8)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_enc_bytea_cmp';

CREATE FUNCTION tde_uuid_enc_cmp(uuid, uuid)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_enc_bytea_cmp';

CREATE FUNCTION tde_date_enc_cmp(date, date)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_enc_bytea_cmp';

CREATE FUNCTION tde_timestamptz_enc_cmp(timestamptz, timestamptz)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_enc_bytea_cmp';

CREATE OPERATOR FAMILY tde_enc_ops_family USING tde_btree;

ALTER OPERATOR FAMILY tde_enc_ops_family USING tde_btree
    ADD FUNCTION 1 (int4,        int4)        tde_int4_enc_cmp(int4, int4);
ALTER OPERATOR FAMILY tde_enc_ops_family USING tde_btree
    ADD FUNCTION 1 (int8,        int8)        tde_int8_enc_cmp(int8, int8);
ALTER OPERATOR FAMILY tde_enc_ops_family USING tde_btree
    ADD FUNCTION 1 (uuid,        uuid)        tde_uuid_enc_cmp(uuid, uuid);
ALTER OPERATOR FAMILY tde_enc_ops_family USING tde_btree
    ADD FUNCTION 1 (date,        date)        tde_date_enc_cmp(date, date);
ALTER OPERATOR FAMILY tde_enc_ops_family USING tde_btree
    ADD FUNCTION 1 (timestamptz, timestamptz) tde_timestamptz_enc_cmp(timestamptz, timestamptz);

CREATE OPERATOR CLASS tde_int4_enc_ops
    DEFAULT FOR TYPE int4
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (int4, int4),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_int8_enc_ops
    DEFAULT FOR TYPE int8
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (int8, int8),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_uuid_enc_ops
    DEFAULT FOR TYPE uuid
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (uuid, uuid),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_date_enc_ops
    DEFAULT FOR TYPE date
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (date, date),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_timestamptz_enc_ops
    DEFAULT FOR TYPE timestamptz
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (timestamptz, timestamptz),
    STORAGE bytea;

-- ============================================================================
-- C functions: KMS status and token management
-- ============================================================================

-- KMS diagnostic status: returns a text summary of DEK cache state
CREATE FUNCTION pg_vault_tde_vault_status()
    RETURNS TABLE (
        configured          boolean, 
        auth_method         text,
        reachable           boolean   
    )
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_vault_status';

-- Manually renew the current Vault token lease
CREATE FUNCTION pg_vault_tde_refresh_token()
    RETURNS boolean
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_refresh_token';

-- ============================================================================
-- C functions: table re-encryption
-- ============================================================================

-- Re-encrypt all rows in an encrypted_heap table with the current DEK.
CREATE FUNCTION pg_vault_tde_reencrypt_table(
    rel regclass,
    batch_size integer DEFAULT 1000
)
    RETURNS void
    LANGUAGE C
    AS 'MODULE_PATHNAME', 'pg_vault_tde_reencrypt_table_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_reencrypt_table(regclass, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_vault_tde_reencrypt_table(regclass, int) TO pg_monitor;

-- Text-typed overload for callers that pass a table name as text
CREATE FUNCTION pg_vault_tde_reencrypt_table(
    rel text,
    batch_size int DEFAULT 1000
)
    RETURNS void
    LANGUAGE SQL SECURITY DEFINER AS $$
        SELECT pg_vault_tde_reencrypt_table(rel::regclass, batch_size);
$$;

REVOKE ALL ON FUNCTION pg_vault_tde_reencrypt_table(text, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_vault_tde_reencrypt_table(text, int) TO pg_monitor;

-- ============================================================================
-- C functions: verification and diagnostics
-- ============================================================================

-- Verify GCM authentication tags; returns (total_tuples, failed_tuples)
CREATE FUNCTION pg_vault_tde_verify_integrity(
    rel regclass,
    OUT total_tuples bigint,
    OUT failed_tuples bigint
)
    RETURNS record
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_verify_integrity';

-- Report encryption storage overhead; returns (total_tuples, overhead_bytes)
CREATE FUNCTION pg_vault_tde_encrypted_size(
    rel regclass,
    OUT total_tuples bigint,
    OUT encryption_overhead_bytes bigint
)
    RETURNS record
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_encrypted_size';

-- Hardware acceleration diagnostics
CREATE FUNCTION pg_vault_tde_hw_accel_info(
    OUT openssl_version text,
    OUT configured_provider text,
    OUT provider_loaded boolean,
    OUT gcm_cipher text,
    OUT siv_cipher text,
    OUT aes_ni_available boolean
)
    RETURNS record
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_hw_accel_info';

-- ============================================================================
-- Per-table DEK catalog
-- ============================================================================
-- Stores the wrapped DEK for each encrypted_heap relation.  The in-memory
-- shmem cache (TdeRelDekCache) is authoritative at runtime; this catalog is
-- the source of truth for DEK restoration after server restart.
CREATE TABLE IF NOT EXISTS pg_vault_tde_catalog (
    relid           oid          NOT NULL,          -- pg_class.oid
    generation      bigint       NOT NULL DEFAULT 1, -- DEK rotation epoch
    wrapped_dek     bytea,                           -- provider-opaque wrapped DEK bytes
    kms_provider    text         NOT NULL DEFAULT 'vault',
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pg_vault_tde_catalog_pkey PRIMARY KEY (relid)
);

REVOKE ALL ON TABLE pg_vault_tde_catalog FROM PUBLIC;

-- ============================================================================
-- Online key rotation progress catalog
-- ============================================================================
CREATE TABLE IF NOT EXISTS pg_vault_tde_rotation_progress (
    relid        oid          NOT NULL,
    status       text         NOT NULL DEFAULT 'running',
    tuples_done  bigint       NOT NULL DEFAULT 0,
    tuples_total bigint,
    started_at   timestamptz  NOT NULL DEFAULT now(),
    updated_at   timestamptz  NOT NULL DEFAULT now(),
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
-- Local Wallet SQL functions
-- ============================================================================

CREATE FUNCTION pg_vault_tde_wallet_init(passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_init_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_init(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_vault_tde_wallet_init(text) TO pg_monitor;

COMMENT ON FUNCTION pg_vault_tde_wallet_init(text) IS
'Initialize a new local PKCS#12 TDE wallet.  The passphrase MUST match the '
'environment variable named by pg_vault_tde.wallet_passphrase_env on '
'subsequent server restarts.';

-- v1.6 version: 6-column wallet status
CREATE FUNCTION pg_vault_tde_wallet_status()
    RETURNS TABLE (
        wallet_exists   bool,
        wallet_open     bool,
        kek_algorithm   text,
        last_opened     timestamptz,
        file_perms      text
    )
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_status_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_vault_tde_wallet_status() TO pg_monitor;

COMMENT ON FUNCTION pg_vault_tde_wallet_status() IS
'Return wallet diagnostics: existence, open/locked state, key algorithm, '
'number of cached per-table DEKs, last-unlock timestamp, and file permissions.';

-- Re-wraps all DEKs under a new passphrase without touching encrypted data
CREATE FUNCTION pg_vault_tde_wallet_change_passphrase(old_passphrase text,
                                                       new_passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_change_passphrase_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_change_passphrase(text, text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_change_passphrase(text, text) IS
'Re-protect the wallet and all per-table DEKs under a new passphrase. '
'Verifies the old passphrase first; then atomically re-wraps every catalog '
'entry and writes a new PKCS#12 wallet file.';

-- Verify passphrase and flush DEK cache
CREATE FUNCTION pg_vault_tde_wallet_unlock(passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_unlock_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_unlock(text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_unlock(text) IS
'Verify the supplied passphrase opens the PKCS#12 wallet, then flush the '
'per-table DEK cache in shared memory so every backend reloads keys through '
'the full unwrap path.  Marks the wallet as open.';

-- Flush DEK cache, mark wallet locked
CREATE FUNCTION pg_vault_tde_wallet_lock()
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_lock_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_lock() FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_lock() IS
'Flush all plaintext DEK material from shared memory without restarting the '
'server.  After this call, any access to an encrypted table will attempt an '
'unwrap — which will fail if no passphrase source is configured.';


-- Migrate all Vault-wrapped DEKs to a new local PKCS#12 wallet
CREATE FUNCTION pg_vault_tde_migrate_vault_to_wallet(new_passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_migrate_vault_to_wallet_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_migrate_vault_to_wallet(text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_migrate_vault_to_wallet(text) IS
'Re-wrap every per-table DEK that is currently protected by the Vault KMS '
'provider under a new local PKCS#12 wallet with new_passphrase.  Updates '
'kms_provider = ''local'' for each migrated row.  The local wallet must '
'already exist (call pg_vault_tde_wallet_init() first).';

-- ============================================================================
-- Physical backup key sealing
-- ============================================================================
-- Seal all wrapped DEKs (any provider) into an HMAC-signed bundle to accompany
-- a pg_basebackup.  The KEK is NOT included: it stays in the KMS/wallet and is
-- provisioned on the standby separately.

CREATE FUNCTION pg_vault_tde_seal_keys(dest_path       text,
                                       seal_passphrase text,
                                       label           text DEFAULT 'basebackup')
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_seal_keys_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_seal_keys(text, text, text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_seal_keys(text, text, text) IS
'Write an HMAC-SHA256-signed bundle of all wrapped DEKs (every kms_provider) '
'to dest_path, to accompany a physical backup (pg_basebackup).  The HMAC key '
'is derived from seal_passphrase via PBKDF2-SHA256.  The KEK is never included. '
'dest_path is written with 0600 permissions.';

-- Same bundle as pg_vault_tde_seal_keys, returned as bytea instead of being
-- written server-side.  Lets a remote client (pg_basebackup_tde) store the
-- bundle next to the backup on the client host.
CREATE FUNCTION pg_vault_tde_seal_keys_bytea(seal_passphrase text,
                                             label           text DEFAULT 'basebackup')
    RETURNS bytea
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_seal_keys_bytea_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_seal_keys_bytea(text, text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_seal_keys_bytea(text, text) IS
'Return an HMAC-SHA256-signed bundle of all wrapped DEKs (every kms_provider) '
'as bytea, to accompany a physical backup (pg_basebackup).  Same format as '
'pg_vault_tde_seal_keys(); the client is responsible for storing the bytes. '
'The KEK is never included.';

-- unseal the wrapped dek bundle
CREATE FUNCTION pg_vault_tde_unseal_keys(src_path        text,
                                         seal_passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_unseal_keys_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_unseal_keys(text, text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_unseal_keys(text, text) IS
'Verify and re-import a wrapped-DEK bundle created by pg_vault_tde_seal_keys(). '
'Checks the HMAC trailer with seal_passphrase before writing anything; on '
'success UPSERTs the catalog rows and evicts the shmem cache.';

-- ============================================================================
-- Online key rotation
-- ============================================================================

-- Spawn a BGW that re-encrypts rel in batches without AccessExclusiveLock
CREATE FUNCTION pg_vault_tde_rotate_online(
    rel        regclass,
    batch_size int DEFAULT 1000
)
    RETURNS void
    LANGUAGE C CALLED ON NULL INPUT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_rotate_online_sql';

-- Query rotation progress for a given relation
CREATE FUNCTION pg_vault_tde_get_rotation_status(rel regclass)
    RETURNS TABLE (
        status       text,
        tuples_done  bigint,
        tuples_total bigint,
        pct_complete numeric,
        started_at   timestamptz,
        updated_at   timestamptz
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
-- Health check (v1.7)
-- ============================================================================

CREATE FUNCTION pg_vault_tde_health_check()
    RETURNS TABLE (
        version           text,
        enabled           bool,
        kms_provider      text,
        enc_ops_available bool,
        checked_at        timestamptz
    )
    LANGUAGE SQL STABLE AS $$
    SELECT
        (SELECT extversion FROM pg_extension WHERE extname='pg_vault_tde') AS version,
        current_setting('pg_vault_tde.enabled', true)::bool     AS enabled,
        current_setting('pg_vault_tde.kms_provider', true)      AS kms_provider,
        EXISTS (
            SELECT 1 FROM pg_opclass
             WHERE opcname   = 'tde_int4_enc_ops'
               AND opcmethod = (SELECT oid FROM pg_am
                                 WHERE amname = 'tde_btree')
        )                                                         AS enc_ops_available,
        now()                                                     AS checked_at;
$$;

COMMENT ON FUNCTION pg_vault_tde_health_check() IS
'Return a single-row diagnostic snapshot of the pg_vault_tde extension. '
'Columns: version, enabled, kms_provider, enc_ops_available '
'(true when tde_*_enc_ops operator classes are installed), checked_at.';

-- ============================================================================
-- KEK rotation
-- ============================================================================

-- Re-wrap all per-table DEKs under a new KEK without touching encrypted data
CREATE FUNCTION pg_vault_tde_rotate_kek()
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_rotate_kek_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_rotate_kek() FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_rotate_kek() IS
'Re-wrap all per-table DEKs under a new KEK without touching encrypted tuple data. '
'For the local wallet provider: generates a fresh random KEK and rewrites the wallet file. '
'For the Vault provider: rotates the Transit key and re-wraps all DEKs. '
'Requires superuser. Flushes the shared-memory DEK cache after completion.';

-- ============================================================================
-- Diagnostic: detect tde_btree indexes still using plaintext (v1.5) ops
-- ============================================================================

CREATE OR REPLACE FUNCTION pg_vault_tde_check_plaintext_index_keys()
RETURNS TABLE (
    table_name   text,
    index_name   text,
    column_name  text,
    opclass_name text,
    suggestion   text
)
LANGUAGE SQL STABLE SECURITY DEFINER AS $$
    SELECT
        c.relname::text                     AS table_name,
        i.relname::text                     AS index_name,
        a.attname::text                     AS column_name,
        opc.opcname::text                   AS opclass_name,
        'REINDEX INDEX CONCURRENTLY '
            || quote_ident(i.relname)
            || ' -- then ALTER to use '
            || replace(opc.opcname, '_ops', '_enc_ops')::text AS suggestion
    FROM pg_index ix
    JOIN pg_class c  ON c.oid  = ix.indrelid
    JOIN pg_class i  ON i.oid  = ix.indexrelid
    JOIN pg_am    am ON am.oid = i.relam
    JOIN pg_attribute a ON a.attrelid = c.oid
    JOIN pg_opclass opc
         ON opc.oid = ix.indclass[array_position(
                            ix.indkey::int[], a.attnum::int) - 1]
    WHERE am.amname = 'tde_btree'
      AND c.relam   = (SELECT oid FROM pg_am WHERE amname = 'encrypted_heap')
      AND opc.opckeytype = 0
    ORDER BY c.relname, i.relname, a.attnum;
$$;

REVOKE ALL ON FUNCTION pg_vault_tde_check_plaintext_index_keys() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_vault_tde_check_plaintext_index_keys()
    TO pg_monitor;

COMMENT ON FUNCTION pg_vault_tde_check_plaintext_index_keys() IS
'Return one row for every tde_btree index on an encrypted_heap table that '
'uses a v1.5 plaintext operator class (opckeytype=0, no STORAGE bytea). '
'The suggestion column provides a REINDEX CONCURRENTLY command to use as a '
'starting point for migrating the index to the corresponding enc_ops class. '
'Restricted to pg_monitor and superuser.';

-- ============================================================================
-- Encryption verification utilities (test/forensics only)
-- ============================================================================

CREATE OR REPLACE FUNCTION pg_vault_tde_verify_plaintext_on_disk(
    table_name regclass,
    plaintext_needle text,
    OUT is_encrypted boolean,
    OUT main_file_size bigint,
    OUT toast_file_size bigint,
    OUT plaintext_in_main integer,
    OUT plaintext_in_toast integer,
    OUT message text
)
    RETURNS record
    LANGUAGE plpgsql STRICT
AS $$
DECLARE
    filepath_main   text;
    filepath_toast  text;
    raw_file_main   bytea;
    raw_file_toast  bytea;
    needle_bytes    bytea;
    needle_pos_main integer;
    needle_pos_toast integer;
    toast_oid       oid;
    min_file_size   integer := 8192;
    msg_parts       text[] := ARRAY[]::text[];
BEGIN

    CHECKPOINT;

    filepath_main := pg_relation_filepath(table_name);
    raw_file_main := pg_read_binary_file(filepath_main);
    needle_bytes  := plaintext_needle::bytea;

    IF length(raw_file_main) < min_file_size THEN
        RAISE EXCEPTION
            'pg_vault_tde_verify_plaintext_on_disk: main relation file too small (% bytes), '
            'was not flushed to disk', length(raw_file_main);
    END IF;

    needle_pos_main := position(needle_bytes IN raw_file_main);
    main_file_size  := length(raw_file_main);
    plaintext_in_main := needle_pos_main;

    SELECT reltoastrelid INTO toast_oid
      FROM pg_class
     WHERE oid = table_name::oid;

    toast_file_size  := NULL;
    plaintext_in_toast := NULL;
    needle_pos_toast := 0;

    IF toast_oid IS NOT NULL AND toast_oid <> 0 THEN
        filepath_toast := pg_relation_filepath(toast_oid);

        BEGIN
            raw_file_toast   := pg_read_binary_file(filepath_toast);
            toast_file_size  := length(raw_file_toast);
            needle_pos_toast := position(needle_bytes IN raw_file_toast);
            plaintext_in_toast := needle_pos_toast;

            msg_parts := array_append(msg_parts,
                format('TOAST file: %s bytes', toast_file_size));

            IF needle_pos_toast > 0 THEN
                msg_parts := array_append(msg_parts,
                    format('Plaintext "%s" detected at byte offset %s in the TOAST relation file.',
                        plaintext_needle, needle_pos_toast));
            ELSE
                msg_parts := array_append(msg_parts,
                    'TOAST relation file: plaintext not detected.');
            END IF;
        EXCEPTION WHEN others THEN
            msg_parts := array_append(msg_parts,
                'TOAST relation file not found (no TOAST chunks persisted yet).');
        END;
    ELSE
        msg_parts := array_append(msg_parts,
            'No TOAST relation is associated with the target table.');
    END IF;

    msg_parts := array_append(msg_parts,
        format('Main file: %s bytes', main_file_size));

    IF needle_pos_main > 0 THEN
        msg_parts := array_append(msg_parts,
            format('Plaintext "%s" detected at byte offset %s in the main relation file.',
                plaintext_needle, needle_pos_main));
    ELSE
        msg_parts := array_append(msg_parts,
            'Main relation file: plaintext not detected.');
    END IF;

    is_encrypted := (needle_pos_main = 0 AND needle_pos_toast = 0);

    IF needle_pos_main > 0 OR needle_pos_toast > 0 THEN
        message := 'Encryption verification failed. ' || array_to_string(msg_parts, ' | ');
    ELSE
        message := 'Encryption verification succeeded. ' || array_to_string(msg_parts, ' | ');
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION pg_vault_tde_verify_toast_by_comparison(
    table_name regclass,
    OUT is_encrypted boolean,
    OUT toast_table regclass,
    OUT toast_file_size bigint,
    OUT sampled_chunk_size integer,
    OUT chunk_match_offset integer,
    OUT header_looks_pg boolean,
    OUT message text
)
    RETURNS record
    LANGUAGE plpgsql STRICT
AS $$
DECLARE
    toast_oid      oid;
    filepath_toast text;
    raw_file_toast bytea;
    sampled_chunk  bytea;
    pd_lower       integer;
    pd_upper       integer;
BEGIN
    IF current_setting('pg_vault_tde.dev_mode', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION
            'pg_vault_tde_verify_toast_by_comparison is test-only; start postgres with pg_vault_tde.dev_mode=on';
    END IF;

    CHECKPOINT;

    SELECT c.reltoastrelid
      INTO toast_oid
      FROM pg_class c
     WHERE c.oid = table_name::oid;

    IF toast_oid IS NULL OR toast_oid = 0 THEN
        is_encrypted       := false;
        toast_table        := NULL;
        toast_file_size    := NULL;
        sampled_chunk_size := NULL;
        chunk_match_offset := NULL;
        header_looks_pg    := NULL;
        message := 'No TOAST relation exists for the specified table.';
        RETURN;
    END IF;

    toast_table := toast_oid::regclass;

    EXECUTE format(
        'SELECT chunk_data::bytea FROM %s ORDER BY chunk_id, chunk_seq LIMIT 1',
        toast_table
    )
    INTO sampled_chunk;

    IF sampled_chunk IS NULL OR length(sampled_chunk) = 0 THEN
        is_encrypted       := false;
        toast_file_size    := NULL;
        sampled_chunk_size := 0;
        chunk_match_offset := NULL;
        header_looks_pg    := NULL;
        message := 'The TOAST relation exists but is empty; no chunk_data is available for comparison.';
        RETURN;
    END IF;

    filepath_toast := pg_relation_filepath(toast_oid);
    raw_file_toast := pg_read_binary_file(filepath_toast);

    toast_file_size    := length(raw_file_toast);
    sampled_chunk_size := length(sampled_chunk);
    chunk_match_offset := position(sampled_chunk::bytea IN raw_file_toast::bytea);

    IF chunk_match_offset > 0 THEN
        is_encrypted    := false;
        header_looks_pg := NULL;
        message := 'ERROR: The compressed bytes retrieved from the database were found identically on disk. TDE is not active or is not encrypting TOAST data.';
        RETURN;
    END IF;

    IF toast_file_size >= 24 THEN
        pd_lower := get_byte(raw_file_toast, 12) + (get_byte(raw_file_toast, 13) * 256);
        pd_upper := get_byte(raw_file_toast, 14) + (get_byte(raw_file_toast, 15) * 256);

        header_looks_pg := (
            pd_lower >= 24 AND
            pd_lower <= 8192 AND
            pd_upper >= pd_lower AND
            pd_upper <= 8192
        );
    ELSE
        header_looks_pg := false;
    END IF;

    IF header_looks_pg THEN
        is_encrypted := false;
        message := 'Comparison completed: chunk_data was not found on disk, but the TOAST file presents recognizable PostgreSQL page headers; TOAST encryption cannot be demonstrated by this check.';
    ELSE
        is_encrypted := true;
        message := 'SUCCESS: The compressed data is present in the PostgreSQL engine but was not found on disk. TDE appears to be correctly encrypting the TOAST relation.';
    END IF;

END;
$$;
