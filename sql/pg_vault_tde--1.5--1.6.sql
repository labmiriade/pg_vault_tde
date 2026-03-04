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
SET search_path TO pg_catalog;

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
-- 2. wallet_change_passphrase() — already declared in 1.5, now fully implemented
-- ============================================================================
-- No DDL change needed; the C implementation replaces the stub at dynamic
-- link time when the new .so is loaded.

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
