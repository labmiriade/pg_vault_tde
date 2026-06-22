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

-- Re-encrypt all rows in an encrypted_heap table with the current DEK.
-- After key rotation, uses prev_dek fallback to read old-DEK rows.
-- batch_size is accepted for API compat but currently unused.
CREATE FUNCTION pg_vault_tde_reencrypt_table(
    rel regclass,
    batch_size integer DEFAULT 1000
)
    RETURNS void
    LANGUAGE C
    AS 'MODULE_PATHNAME', 'pg_vault_tde_reencrypt_table';

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
