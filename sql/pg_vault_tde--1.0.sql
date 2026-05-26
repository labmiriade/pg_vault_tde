-- pg_vault_tde--1.0.sql
-- Extension install script for pg_vault_tde
-- Copyright (c) 2026 Miriade Srl   - PostgreSQL License

-- Require superuser for installation
DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user)
    THEN
        RAISE EXCEPTION 'pg_vault_tde requires superuser privileges to install';
    END IF;
END;
$$;



-- Register handler functions first (required before CREATE ACCESS METHOD)
CREATE FUNCTION pg_vault_tde_tableam_handler(internal)
    RETURNS table_am_handler
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_tableam_handler';

CREATE FUNCTION pg_vault_tde_iam_handler(internal)
    RETURNS index_am_handler
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_iam_handler';

-- Register the Table Access Method (encrypted_heap)
CREATE ACCESS METHOD encrypted_heap
    TYPE TABLE
    HANDLER pg_vault_tde_tableam_handler;

-- Register the Index Access Method (tde_btree)
CREATE ACCESS METHOD tde_btree
    TYPE INDEX
    HANDLER pg_vault_tde_iam_handler;

-- Default operator class for bytea using tde_btree (v1.4)
-- Required for `CREATE INDEX ... USING tde_btree` on bytea columns.
-- Index lookups support equality only (AES-256-SIV is deterministic
-- but does not preserve ordering, so range operators return wrong results).
CREATE OPERATOR CLASS tde_bytea_ops DEFAULT FOR TYPE bytea USING tde_btree AS
    OPERATOR 1 <  (bytea, bytea),
    OPERATOR 2 <= (bytea, bytea),
    OPERATOR 3 =  (bytea, bytea),
    OPERATOR 4 >= (bytea, bytea),
    OPERATOR 5 >  (bytea, bytea),
    FUNCTION 1 byteacmp(bytea, bytea);

-- Expose backup status to monitoring tools
CREATE FUNCTION pg_vault_tde_backup_status()
    RETURNS text
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_backup_status';

-- Expose DEK rotation trigger (called by DBA or automation)
CREATE FUNCTION pg_vault_tde_rotate_key()
    RETURNS void
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_rotate_key';

-- Expose current key generation for monitoring
CREATE FUNCTION pg_vault_tde_key_generation()
    RETURNS bigint
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_key_generation';

-- KMS diagnostic status (v1.1): returns a text summary of DEK cache state
CREATE FUNCTION pg_vault_tde_kms_status()
    RETURNS text
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_kms_status';

-- Token refresh (v1.1): manually renew the current Vault token lease
CREATE FUNCTION pg_vault_tde_refresh_token()
    RETURNS boolean
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_refresh_token';

COMMENT ON ACCESS METHOD encrypted_heap IS
    'pg_vault_tde Table Access Method: AES-256-GCM transparent encryption via Vault/OpenBao';
COMMENT ON ACCESS METHOD tde_btree IS
    'pg_vault_tde Index Access Method: AES-256-SIV deterministic encryption for B-Tree indexes';

-- ================================================================
-- Test / diagnostic functions (safe for development and CI use)
-- ================================================================

-- Inject a random test DEK into shared memory (NO Vault needed)
CREATE FUNCTION pg_vault_tde_set_test_dek()
    RETURNS void
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_set_test_dek';

-- Encrypt text → bytea via AES-256-GCM (requires DEK set)
CREATE FUNCTION pg_vault_tde_encrypt_test(text)
    RETURNS bytea
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_encrypt_test';

-- Decrypt bytea → text via AES-256-GCM (verifies auth tag)
CREATE FUNCTION pg_vault_tde_decrypt_test(bytea)
    RETURNS text
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_decrypt_test';

-- ================================================================
-- v1.1: Vault DEK fetch, key rotation utilities, integrity checks
-- ================================================================

-- Fetch DEK from Vault Transit API (returns true on success)
CREATE FUNCTION pg_vault_tde_vault_fetch_dek()
    RETURNS boolean
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_vault_fetch_dek_sql';

-- Re-encrypt all rows in an encrypted_heap table with the current DEK.
-- After key rotation, uses prev_dek fallback to read old-DEK rows.
-- batch_size is accepted for API compat but currently unused.
CREATE FUNCTION pg_vault_tde_reencrypt_table(
    rel regclass,
    batch_size integer DEFAULT 1000
)
    RETURNS void
    LANGUAGE C
    AS 'MODULE_PATHNAME', 'pg_vault_tde_reencrypt_table_sql';

-- Verify GCM authentication tags on all tuples without returning data.
-- Returns (total_tuples, failed_tuples).
CREATE FUNCTION pg_vault_tde_verify_integrity(
    rel regclass,
    OUT total_tuples bigint,
    OUT failed_tuples bigint
)
    RETURNS record
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_verify_integrity';

-- Report encryption storage overhead: 28 bytes per tuple (IV + tag).
-- Returns (total_tuples, encryption_overhead_bytes).
CREATE FUNCTION pg_vault_tde_encrypted_size(
    rel regclass,
    OUT total_tuples bigint,
    OUT encryption_overhead_bytes bigint
)
    RETURNS record
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_encrypted_size';

-- Clear the previous DEK from shared memory (call after re-encryption).
-- Removes the rotation fallback — old-DEK rows become permanently unreadable.
CREATE FUNCTION pg_vault_tde_clear_prev_dek()
    RETURNS void
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_clear_prev_dek';

-- Hardware acceleration diagnostics: OpenSSL provider, cipher info, AES-NI.
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

-- ================================================================
-- v1.3: Health check, KEK rewrap
-- ================================================================

-- Unified health check: aggregates DEK, Vault, token, OpenSSL, HW accel state.
-- Returns a 15-column composite with overall_status (healthy/degraded/error).
CREATE FUNCTION pg_vault_tde_health_check(
    OUT overall_status text,
    OUT dek_valid boolean,
    OUT generation bigint,
    OUT prev_dek_available boolean,
    OUT vault_configured boolean,
    OUT vault_url text,
    OUT vault_reachable boolean,
    OUT auth_method text,
    OUT token_available boolean,
    OUT openssl_version text,
    OUT aes_ni_available boolean,
    OUT crypto_provider text,
    OUT encryption_enabled boolean,
    OUT dek_cache_ttl integer,
    OUT wrapped_dek_perms text
)
    RETURNS record
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_health_check';

-- Re-wrap the persisted wrapped DEK with the latest Vault Transit KEK version.
-- Call after rotating the KEK in Vault (vault write -f transit/keys/<key>/rotate).
-- The plaintext DEK does not change — only the wrapping key version.
CREATE FUNCTION pg_vault_tde_vault_rewrap_dek()
    RETURNS boolean
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_vault_rewrap_dek';

-- ================================================================
-- Encryption verification utility for testing / forensics
-- ================================================================

-- Verify that plaintext does NOT appear on disk (data is encrypted).
-- Checks BOTH the main table file AND TOAST chunks (if present).
-- Useful for unit tests, CI pipelines, and security audits.
--
-- USAGE:
--   SELECT * FROM pg_vault_tde_verify_plaintext_on_disk('my_table', 'secret_password');
--
-- RETURNS: record with columns:
--   - is_encrypted: boolean — TRUE if plaintext is NOT found anywhere 
--   - main_file_size: bigint — main table file size
--   - toast_file_size: bigint — TOAST file size (NULL if no TOAST)
--   - plaintext_in_main: integer — byte offset in main file (0 = not found)
--   - plaintext_in_toast: integer — byte offset in TOAST file (0 or NULL)
--   - message: text — human-readable result with all details
--
-- RAISES ERROR if plaintext is found in EITHER main table or TOAST chunks.
-- Warns if TOAST exists (v1 limitation: TOAST chunks are NOT encrypted).
-- TEST-ONLY GUARD: callable only when pg_vault_tde.dev_mode = on.
--
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
    min_file_size   integer := 8192;  -- one 8KB page
    msg_parts       text[] := ARRAY[]::text[];
BEGIN

    -- Force a checkpoint to ensure all dirty buffers are flushed to disk
    CHECKPOINT;

    -- Get the physical file path of the main table
    filepath_main := pg_relation_filepath(table_name);

    -- Read the main table file from disk
    raw_file_main := pg_read_binary_file(filepath_main);

    -- Convert plaintext search string to bytea (needle)
    needle_bytes := plaintext_needle::bytea;

    -- Sanity check: main file must have been flushed (at least one page)
    IF length(raw_file_main) < min_file_size THEN
        RAISE EXCEPTION
            'pg_vault_tde_verify_plaintext_on_disk: main relation file too small (% bytes), '
            'was not flushed to disk', length(raw_file_main);
    END IF;

    -- Search for plaintext in main file
    needle_pos_main := position(needle_bytes IN raw_file_main);
    main_file_size := length(raw_file_main);
    plaintext_in_main := needle_pos_main;

    -- Check if this table has a TOAST table
    SELECT reltoastrelid INTO toast_oid
      FROM pg_class
     WHERE oid = table_name::oid;

    -- Initialize TOAST columns to NULL
    toast_file_size := NULL;
    plaintext_in_toast := NULL;
    needle_pos_toast := 0;

    -- If TOAST exists, verify its contents too
    IF toast_oid IS NOT NULL AND toast_oid <> 0 THEN
        filepath_toast := pg_relation_filepath(toast_oid);
        
        BEGIN
            raw_file_toast := pg_read_binary_file(filepath_toast);
            toast_file_size := length(raw_file_toast);
            
            -- Search for plaintext in TOAST file
            needle_pos_toast := position(needle_bytes IN raw_file_toast);
            plaintext_in_toast := needle_pos_toast;
            
            -- Add TOAST info to message
            msg_parts := array_append(msg_parts, 
                format('TOAST file: %s bytes', toast_file_size));
            
            IF needle_pos_toast > 0 THEN
                msg_parts := array_append(msg_parts,
                    format('Plaintext "%s" detected at byte offset %s in the TOAST relation file.', 
                        plaintext_needle, needle_pos_toast));
            ELSE
                msg_parts := array_append(msg_parts,
                    format('TOAST relation file: plaintext not detected.'));
            END IF;
        EXCEPTION WHEN others THEN
            -- TOAST file may not exist if no TOAST chunks yet
            msg_parts := array_append(msg_parts, 'TOAST relation file not found (no TOAST chunks persisted yet).');
        END;
    ELSE
        msg_parts := array_append(msg_parts, 'No TOAST relation is associated with the target table.');
    END IF;

    -- Add main table info to message
    msg_parts := array_append(msg_parts, 
        format('Main file: %s bytes', main_file_size));

    IF needle_pos_main > 0 THEN
        msg_parts := array_append(msg_parts,
            format('Plaintext "%s" detected at byte offset %s in the main relation file.', 
                plaintext_needle, needle_pos_main));
    ELSE
        msg_parts := array_append(msg_parts,
            format('Main relation file: plaintext not detected.'));
    END IF;

    -- Overall result: encrypted only if NOT found in EITHER file
    is_encrypted := (needle_pos_main = 0 AND needle_pos_toast = 0);

    -- Build final message
    IF needle_pos_main > 0 OR needle_pos_toast > 0 THEN
        message := 'Encryption verification failed. ' || array_to_string(msg_parts, ' | ');
    ELSE
        message := 'Encryption verification succeeded. ' || array_to_string(msg_parts, ' | ');
    END IF;
END;
$$;

-- ================================================================
-- Advanced TOAST verification by byte-for-byte comparison
-- ================================================================

/*
 * Compare a sampled TOAST chunk_data (retrieved through SQL) against
 * the physical TOAST relation file bytes.
 *
 * Intended outcome:
 * - Match found  -> not encrypted on disk
 * - No match and page header does not look like a standard PG page
 *                -> likely encrypted/randomized on disk
 *
 * TEST-ONLY GUARD: callable only when pg_vault_tde.dev_mode = on.
 */
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
        is_encrypted := false;
        toast_table := NULL;
        toast_file_size := NULL;
        sampled_chunk_size := NULL;
        chunk_match_offset := NULL;
        header_looks_pg := NULL;
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
        is_encrypted := false;
        toast_file_size := NULL;
        sampled_chunk_size := 0;
        chunk_match_offset := NULL;
        header_looks_pg := NULL;
        message := 'The TOAST relation exists but is empty; no chunk_data is available for comparison.';
        RETURN;
    END IF;

    filepath_toast := pg_relation_filepath(toast_oid);
    raw_file_toast := pg_read_binary_file(filepath_toast);

    toast_file_size := length(raw_file_toast);
    sampled_chunk_size := length(sampled_chunk);

    chunk_match_offset := position(sampled_chunk::bytea IN raw_file_toast::bytea);

    IF chunk_match_offset > 0 THEN
        is_encrypted := false;
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

