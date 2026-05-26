-- pg_vault_tde--1.5--1.6.sql
--
-- Migration from pg_vault_tde 1.5 to 1.6.
--
-- v1.6 — Local Wallet KMS: Production-Ready Offline Encryption
--
-- Changes:
--   1. Replace wallet_status() with a 6-column version.
--   2. Promote wallet_change_passphrase() from stub to full implementation.
--   3. Add wallet_unlock(passphrase text)
--   4. Add wallet_lock()
--   5. Add wallet_rotate_kek(new_passphrase text)
--   6. Add wallet_export_bundle(dest_path text, label text)
--   7. Add wallet_import_bundle(src_path text, passphrase text)
--   8. Add migrate_vault_to_wallet(new_passphrase text)
--
-- Copyright (c) 2026 Miriade S.r.l., Licensed under the PostgreSQL License.

-- Guard: this script is idempotent for the DROP below, but must only run once.
--
-- NOTE: do NOT set search_path to pg_catalog here.  The functions created by
-- this script live in the extension schema (public).  Narrowing search_path
-- to pg_catalog causes COMMENT ON FUNCTION / REVOKE / GRANT to fail to
-- resolve unqualified names, and CREATE FUNCTION would land in the wrong
-- schema.  Let the extension mechanism control the search_path.

-- ============================================================================
-- 1. Replace wallet_status() with extended 6-column version
-- ============================================================================
-- The v1.5 version returned (wallet_exists, wallet_open, kek_algorithm,
-- dek_wrapped bool).  v1.6 enriches it with dek_count, last_opened, and
-- file_perms.  Because RETURNS TABLE changes shape, we must DROP and recreate.

DROP FUNCTION IF EXISTS pg_vault_tde_wallet_status();

CREATE FUNCTION pg_vault_tde_wallet_status()
    RETURNS TABLE (
        wallet_exists   bool,
        wallet_open     bool,
        kek_algorithm   text,
        dek_count       int,
        last_opened     timestamptz,
        file_perms      text
    )
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_status_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_status() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION pg_vault_tde_wallet_status() TO pg_monitor;

COMMENT ON FUNCTION pg_vault_tde_wallet_status() IS
'Return wallet diagnostics: existence, open/locked state, key algorithm, '
'number of cached per-table DEKs, last-unlock timestamp, and file permissions.';

-- ============================================================================
-- 2. wallet_change_passphrase() — create-or-replace in case 1.4→1.5 ran as a
--    stub, or the upgrade chain starts here on a fresh install.
-- ============================================================================
CREATE OR REPLACE FUNCTION pg_vault_tde_wallet_change_passphrase(
        old_passphrase text,
        new_passphrase text
    )
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_change_passphrase_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_change_passphrase(text, text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_change_passphrase(text, text) IS
'Re-protect the wallet and all per-table DEKs under a new passphrase. '
'Verifies the old passphrase first; then atomically re-wraps every catalog '
'entry and writes a new PKCS#12 wallet file.';

-- ============================================================================
-- 3. wallet_unlock(passphrase text) — verify passphrase and flush DEK cache
-- ============================================================================
CREATE FUNCTION pg_vault_tde_wallet_unlock(passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_unlock_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_unlock(text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_unlock(text) IS
'Verify the supplied passphrase opens the PKCS#12 wallet, then flush the '
'per-table DEK cache in shared memory so every backend reloads keys through '
'the full unwrap path.  Marks the wallet as open.';

-- ============================================================================
-- 4. wallet_lock() — flush DEK cache, mark wallet locked
-- ============================================================================
CREATE FUNCTION pg_vault_tde_wallet_lock()
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_lock_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_lock() FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_lock() IS
'Flush all plaintext DEK material from shared memory without restarting the '
'server.  After this call, any access to an encrypted table will attempt an '
'unwrap — which will fail if no passphrase source is configured.';

-- ============================================================================
-- 5. wallet_rotate_kek(new_passphrase text)
-- ============================================================================
CREATE FUNCTION pg_vault_tde_wallet_rotate_kek(new_passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_rotate_kek_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_rotate_kek(text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_rotate_kek(text) IS
'Re-wrap all per-table DEKs under a new passphrase-protected KEK without '
'touching encrypted tuple data.  Writes a new wallet file and flushes the '
'shmem cache.  Use for scheduled KEK rotation.';

-- ============================================================================
-- 6. wallet_export_bundle(dest_path text, label text)
-- ============================================================================
CREATE FUNCTION pg_vault_tde_wallet_export_bundle(dest_path text,
                                                   label     text DEFAULT 'backup')
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_export_bundle_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_export_bundle(text, text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_export_bundle(text, text) IS
'Write an HMAC-SHA256-authenticated binary bundle containing the PKCS#12 '
'wallet and all local-provider catalog entries to dest_path.  The HMAC key '
'is derived from the current wallet passphrase via PBKDF2-SHA256.  '
'dest_path is written with 0600 permissions.';

-- ============================================================================
-- 7. wallet_import_bundle(src_path text, passphrase text)
-- ============================================================================
CREATE FUNCTION pg_vault_tde_wallet_import_bundle(src_path   text,
                                                   passphrase text)
    RETURNS void
    LANGUAGE C STRICT SECURITY DEFINER
    AS 'MODULE_PATHNAME', 'pg_vault_tde_wallet_import_bundle_sql';

REVOKE ALL ON FUNCTION pg_vault_tde_wallet_import_bundle(text, text) FROM PUBLIC;

COMMENT ON FUNCTION pg_vault_tde_wallet_import_bundle(text, text) IS
'Restore a wallet and per-table DEK catalog from a bundle created by '
'pg_vault_tde_wallet_export_bundle().  Verifies the HMAC trailer with the '
'supplied passphrase before writing any data; fails cleanly if wrong.';

-- ============================================================================
-- 8. migrate_vault_to_wallet(new_passphrase text)
-- ============================================================================
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
-- 9. Mark tde_btree operator classes as DEFAULT
-- ============================================================================
-- v1.5 created these operator classes without the DEFAULT keyword, so
-- CREATE INDEX ... USING tde_btree (col) required an explicit opclass name.
-- PostgreSQL has no ALTER OPERATOR CLASS ... SET DEFAULT DDL; update the
-- catalog directly.
DO $$
DECLARE
    am_oid oid;
BEGIN
    SELECT oid INTO am_oid FROM pg_catalog.pg_am WHERE amname = 'tde_btree';
    IF am_oid IS NULL THEN
        RETURN;
    END IF;

    UPDATE pg_catalog.pg_opclass
       SET opcdefault = true
     WHERE opcmethod = am_oid
       AND opcname IN (
           'tde_text_ops',
           'tde_int4_ops',
           'tde_int8_ops',
           'tde_uuid_ops',
           'tde_numeric_ops',
           'tde_date_ops',
           'tde_timestamptz_ops',
           'tde_bytea_ops'
       );
END;
$$;

-- ============================================================================
-- 9. Migrate reencrypt_table function, C function name changed
-- ============================================================================

CREATE OR REPLACE FUNCTION pg_vault_tde_reencrypt_table(
    rel regclass,
    batch_size integer DEFAULT 1000
)
    RETURNS void
    LANGUAGE C
    AS 'MODULE_PATHNAME', 'pg_vault_tde_reencrypt_table_sql';

CREATE OR REPLACE FUNCTION pg_vault_tde_reencrypt_table(
        rel         text,
        batch_size  int DEFAULT 1000
    )
    RETURNS void
    LANGUAGE SQL SECURITY DEFINER AS $$
        SELECT pg_vault_tde_reencrypt_table(rel::regclass, batch_size);
$$;

REVOKE ALL   ON FUNCTION pg_vault_tde_reencrypt_table(text, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_vault_tde_reencrypt_table(text, int) TO pg_monitor;


