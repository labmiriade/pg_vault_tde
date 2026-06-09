-- pg_vault_tde--1.6--1.7.sql
--
-- Migration from pg_vault_tde 1.6 to 1.7.
--
-- v1.7 — Encrypted index keys for fixed-size types (tde_*_enc_ops)
-- ─────────────────────────────────────────────────────────────────
-- Key changes in this release:
--
--   1. New C support function tde_enc_bytea_cmp(bytea, bytea) -> integer:
--      three-way memcmp comparator for AES-256-SIV ciphertexts stored as bytea.
--      Used as btree support function 1 for all new enc_ops operator classes.
--
--   2. Shared operator family tde_enc_ops_family (btree): all five enc_ops
--      classes share the same (bytea, bytea) comparison contract.
--
--   3. Five new operator classes, each with STORAGE bytea:
--        tde_int4_enc_ops      FOR TYPE int4
--        tde_int8_enc_ops      FOR TYPE int8
--        tde_uuid_enc_ops      FOR TYPE uuid
--        tde_date_enc_ops      FOR TYPE date
--        tde_timestamptz_enc_ops  FOR TYPE timestamptz
--      aminsert/amrescan serialize the fixed-size Datum to canonical big-endian
--      bytes and then AES-256-SIV encrypt before storing in the index.
--      Range-scan ordering on enc_ops indexes is memcmp-based and has no
--      semantic meaning; only equality lookups are semantically valid.
--
--   4. Deprecation of v1.5 plaintext operator classes: DEFAULT is removed from
--      tde_{int4,int8,uuid,date,timestamptz}_ops and set on the enc_ops classes.
--      The v1.5 classes remain available for backwards compatibility.
--
--   5. New diagnostic function pg_vault_tde_check_plaintext_index_keys():
--      reports tde_btree indexes on encrypted_heap tables that still use
--      plaintext (v1.5) operator classes.
--
--   6. pg_vault_tde_health_check() extended with enc_ops_available column.
--
-- Copyright (c) 2026 Miriade S.r.l., Licensed under the PostgreSQL License.

-- NOTE: do NOT set search_path to pg_catalog here.  The functions created by
-- this script live in the extension schema (public).  Narrowing search_path
-- to pg_catalog causes COMMENT ON FUNCTION / REVOKE / GRANT to fail to
-- resolve unqualified names, and CREATE FUNCTION would land in the wrong
-- schema.  Let the extension mechanism control the search_path.

-- ============================================================================
-- §10.1 — Guard: superuser required
-- ============================================================================
-- ALTER EXTENSION UPDATE runs inside a transaction started by the extension
-- mechanism, but does not enforce superuser on its own.  Reject early to
-- produce a clear error message rather than a permission failure deep inside
-- a catalog UPDATE.

DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles
            WHERE rolname = current_user)
    THEN
        RAISE EXCEPTION 'pg_vault_tde upgrade requires superuser';
    END IF;
END;
$$;

-- ============================================================================
-- §10.2 — Register tde_enc_bytea_cmp SQL function
-- ============================================================================
-- This C function is the btree support function 1 (three-way comparator) for
-- all tde_*_enc_ops operator classes.  Both arguments are AES-256-SIV
-- ciphertexts stored as bytea.  Ordering is memcmp-based and has no semantic
-- meaning; equality is preserved because AES-SIV is deterministic.

CREATE FUNCTION tde_enc_bytea_cmp(bytea, bytea)
    RETURNS integer
    LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_enc_bytea_cmp';

COMMENT ON FUNCTION tde_enc_bytea_cmp(bytea, bytea) IS
'Three-way comparator for AES-256-SIV encrypted index keys stored as bytea. '
'Used as btree support function 1 for tde_*_enc_ops operator classes. '
'Ordering is memcmp-based and has no semantic meaning; equality is preserved.';

-- ============================================================================
-- §10.2b — Per-type SQL wrappers for the btree support function
-- ============================================================================
-- PostgreSQL's index_getprocinfo looks up support function 1 using the
-- opclass's opcintype (e.g. int4) as both lefttype and righttype — NOT the
-- STORAGE type (bytea).  See rel.h: "only default support procs for each
-- opclass are cached, namely those with lefttype and righttype equal to the
-- opclass's opcintype."
--
-- Solution: create one SQL function per original type, all pointing to the
-- same C symbol tde_enc_bytea_cmp.  At runtime btree calls the comparator
-- with bytea datums (because STORAGE bytea), so the C implementation reading
-- PG_GETARG_BYTEA_PP is correct regardless of the SQL-declared argument type.

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

-- ============================================================================
-- §10.3 — Shared operator family tde_enc_ops_family
-- ============================================================================
-- All five enc_ops classes share one family.  Each per-type comparator wrapper
-- is registered with its matching (type, type) key so index_getprocinfo finds
-- it via get_opfamily_proc(family, opcintype, opcintype, BTORDER_PROC).

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

-- ============================================================================
-- §10.4 — Operator classes (one per fixed-size type, no FUNCTION clause)
-- ============================================================================

-- ── tde_int4_enc_ops ────────────────────────────────────────────────────────
CREATE OPERATOR CLASS tde_int4_enc_ops
    FOR TYPE int4
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (int4, int4),
    STORAGE bytea;

-- ── tde_int8_enc_ops ────────────────────────────────────────────────────────
CREATE OPERATOR CLASS tde_int8_enc_ops
    FOR TYPE int8
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (int8, int8),
    STORAGE bytea;

-- ── tde_uuid_enc_ops ────────────────────────────────────────────────────────
CREATE OPERATOR CLASS tde_uuid_enc_ops
    FOR TYPE uuid
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (uuid, uuid),
    STORAGE bytea;

-- ── tde_date_enc_ops ────────────────────────────────────────────────────────
CREATE OPERATOR CLASS tde_date_enc_ops
    FOR TYPE date
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (date, date),
    STORAGE bytea;

-- ── tde_timestamptz_enc_ops ─────────────────────────────────────────────────
CREATE OPERATOR CLASS tde_timestamptz_enc_ops
    FOR TYPE timestamptz
    USING tde_btree
    FAMILY tde_enc_ops_family
AS
    OPERATOR 3  =  (timestamptz, timestamptz),
    STORAGE bytea;

-- ============================================================================
-- §10.5 — Promote enc_ops to DEFAULT; demote plaintext v1.5 ops
-- ============================================================================
-- PostgreSQL has no ALTER OPERATOR CLASS ... SET DEFAULT DDL command; the only
-- supported method is a direct catalog update (as done in the 1.5→1.6 migration
-- for setting DEFAULT on those same classes).
--
-- Step A: remove DEFAULT from the v1.5 plaintext operator classes.
-- Existing indexes using these classes are unaffected; only new CREATE INDEX
-- without an explicit opclass name will change behavior.
UPDATE pg_catalog.pg_opclass
   SET opcdefault = false
 WHERE opcmethod = (SELECT oid FROM pg_catalog.pg_am WHERE amname = 'tde_btree')
   AND opcname IN (
       'tde_int4_ops',
       'tde_int8_ops',
       'tde_uuid_ops',
       'tde_date_ops',
       'tde_timestamptz_ops'
   );

-- Step B: set DEFAULT on the new enc_ops classes.
-- From this point, CREATE INDEX ... USING tde_btree (col_int4) will
-- automatically use tde_int4_enc_ops (encrypted keys) instead of tde_int4_ops.
UPDATE pg_catalog.pg_opclass
   SET opcdefault = true
 WHERE opcmethod = (SELECT oid FROM pg_catalog.pg_am WHERE amname = 'tde_btree')
   AND opcname IN (
       'tde_int4_enc_ops',
       'tde_int8_enc_ops',
       'tde_uuid_enc_ops',
       'tde_date_enc_ops',
       'tde_timestamptz_enc_ops'
   );

-- ============================================================================
-- §10.6 — Diagnostic function: detect indexes with plaintext keys
-- ============================================================================
-- pg_vault_tde_check_plaintext_index_keys() returns one row per tde_btree
-- index that uses an operator class without STORAGE bytea (opckeytype = 0)
-- on a table that uses the encrypted_heap access method.
--
-- opckeytype = 0 means no STORAGE override: the index key type equals the
-- column type, which for fixed-size types (int4, int8, uuid, date, timestamptz)
-- means the key is stored in plaintext.
--
-- The suggestion column provides a ready-to-run REINDEX command.  After
-- reindexing with the enc_ops class, run ALTER INDEX ... USING tde_btree
-- (col <type>_enc_ops) or recreate the index explicitly.
--
-- Access is restricted to pg_monitor (and superuser) since this function reads
-- pg_index and resolves table/index names, which could reveal schema structure.

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
      AND opc.opckeytype = 0   -- opckeytype=0 means no STORAGE override (plaintext)
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
-- §10.7 — Replace pg_vault_tde_health_check() with v1.7 version
-- ============================================================================
-- The v1.5 / v1.6 version returned 7 columns:
--   version, enabled, kms_provider, dek_available, aad_binding,
--   wallet_open, checked_at
-- v1.7 adds enc_ops_available (bool) as the 7th column, shifting checked_at
-- to 8th position.  Because RETURNS TABLE changes shape we must DROP and
-- recreate.
--
-- ALTER EXTENSION pg_vault_tde DROP FUNCTION must come first so that the
-- DROP FUNCTION succeeds — inside ALTER EXTENSION UPDATE, owned objects
-- cannot be dropped directly without first disassociating them.

ALTER EXTENSION pg_vault_tde DROP FUNCTION pg_vault_tde_health_check();
DROP FUNCTION IF EXISTS pg_vault_tde_health_check();

CREATE FUNCTION pg_vault_tde_health_check()
    RETURNS TABLE (
        version           text,
        enabled           bool,
        kms_provider      text,
        dek_available     bool,
        aad_binding       bool,
        wallet_open       bool,
        enc_ops_available bool,
        checked_at        timestamptz
    )
    LANGUAGE SQL STABLE AS $$
    SELECT
        '1.7'::text                                              AS version,
        current_setting('pg_vault_tde.enabled', true)::bool     AS enabled,
        current_setting('pg_vault_tde.kms_provider', true)      AS kms_provider,
        pg_vault_tde_dek_available()                             AS dek_available,
        true                                                      AS aad_binding,
        false                                                     AS wallet_open,
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
'Columns: version (1.7), enabled, kms_provider, dek_available (round-trip '
'encrypt/decrypt probe), aad_binding, wallet_open, enc_ops_available '
'(true when tde_*_enc_ops operator classes are installed), checked_at.';
