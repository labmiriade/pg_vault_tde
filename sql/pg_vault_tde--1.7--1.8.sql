/* pg_vault_tde--1.7--1.8.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pg_vault_tde UPDATE TO '1.8'" to load this file. \quit



-- ============================================================================
-- Order Preserving Encryption (OPE) IAM Handler
-- ============================================================================
CREATE FUNCTION pg_vault_tde_iam_ope_handler(internal)
    RETURNS index_am_handler
    LANGUAGE C STRICT
    AS 'MODULE_PATHNAME', 'pg_vault_tde_iam_ope_handler';


-- ============================================================================
-- Order Preserving Encryption (OPE) Access method
-- ============================================================================
CREATE ACCESS METHOD tde_ope_btree
    TYPE INDEX
    HANDLER pg_vault_tde_iam_ope_handler;

COMMENT ON ACCESS METHOD tde_ope_btree IS
    'pg_vault_tde Index Access Method: Order-Revealing Encryption (ORE) for B-Tree indexes';
 

-- ============================================================================
-- Order Preserving Encryption (OPE) operator classes
-- ============================================================================
CREATE FUNCTION tde_ope_bytea_cmp(bytea, bytea)
    RETURNS integer
    LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_iam_ope_bytea_cmp';

COMMENT ON FUNCTION tde_ope_bytea_cmp(bytea, bytea) IS
'Three-way comparator for ORE encrypted index keys stored as bytea. '
'Used as btree support function 1 for tde_ope_btree operator classes. '
'Preserves relative order to support range scans (<, <=, =, >=, >).';

CREATE OPERATOR CLASS tde_ope_bytea_ops
    DEFAULT FOR TYPE bytea
    USING tde_ope_btree
AS
    OPERATOR 1 <  (bytea, bytea),
    OPERATOR 2 <= (bytea, bytea),
    OPERATOR 3 =  (bytea, bytea),
    OPERATOR 4 >= (bytea, bytea),
    OPERATOR 5 >  (bytea, bytea),
    FUNCTION 1 tde_ope_bytea_cmp(bytea, bytea);

-- Per-type SQL wrappers for support function 1 on fixed types
CREATE FUNCTION tde_ope_text_cmp(text, text)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_iam_ope_text_cmp';

CREATE FUNCTION tde_ope_int4_cmp(int4, int4)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_iam_ope_int4_cmp';

CREATE FUNCTION tde_ope_int8_cmp(int8, int8)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_iam_ope_int8_cmp';

CREATE FUNCTION tde_ope_uuid_cmp(uuid, uuid)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_iam_ope_uuid_cmp';

CREATE FUNCTION tde_ope_date_cmp(date, date)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_iam_ope_date_cmp';

CREATE FUNCTION tde_ope_timestamptz_cmp(timestamptz, timestamptz)
    RETURNS integer LANGUAGE C STRICT IMMUTABLE
    AS 'MODULE_PATHNAME', 'tde_iam_ope_timestamptz_cmp';

CREATE OPERATOR FAMILY tde_ope_enc_ops_family USING tde_ope_btree;

CREATE OPERATOR CLASS tde_ope_text_enc_ops
    DEFAULT FOR TYPE text
    USING tde_ope_btree
    FAMILY tde_ope_enc_ops_family
AS
    OPERATOR 1  <  (text, text),
    OPERATOR 2  <= (text, text),
    OPERATOR 3  =  (text, text),
    OPERATOR 4  >= (text, text),
    OPERATOR 5  >  (text, text),
	FUNCTION 1 tde_ope_text_cmp(text, text),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_ope_int4_enc_ops
    DEFAULT FOR TYPE int4
    USING tde_ope_btree
    FAMILY tde_ope_enc_ops_family
AS
    OPERATOR 1  <  (int4, int4),
    OPERATOR 2  <= (int4, int4),
    OPERATOR 3  =  (int4, int4),
    OPERATOR 4  >= (int4, int4),
    OPERATOR 5  >  (int4, int4),
	FUNCTION 1 tde_ope_int4_cmp(int4, int4),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_ope_int8_enc_ops
    DEFAULT FOR TYPE int8
    USING tde_ope_btree
    FAMILY tde_ope_enc_ops_family
AS
    OPERATOR 1  <  (int8, int8),
    OPERATOR 2  <= (int8, int8),
    OPERATOR 3  =  (int8, int8),
    OPERATOR 4  >= (int8, int8),
    OPERATOR 5  >  (int8, int8),
	FUNCTION 1 tde_ope_int8_cmp(int8, int8),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_ope_uuid_enc_ops
    DEFAULT FOR TYPE uuid
    USING tde_ope_btree
    FAMILY tde_ope_enc_ops_family
AS
    OPERATOR 1  <  (uuid, uuid),
    OPERATOR 2  <= (uuid, uuid),
    OPERATOR 3  =  (uuid, uuid),
    OPERATOR 4  >= (uuid, uuid),
    OPERATOR 5  >  (uuid, uuid),
	FUNCTION 1 tde_ope_uuid_cmp(uuid, uuid),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_ope_date_enc_ops
    DEFAULT FOR TYPE date
    USING tde_ope_btree
    FAMILY tde_ope_enc_ops_family
AS
    OPERATOR 1  <  (date, date),
    OPERATOR 2  <= (date, date),
    OPERATOR 3  =  (date, date),
    OPERATOR 4  >= (date, date),
    OPERATOR 5  >  (date, date),
	FUNCTION 1 tde_ope_date_cmp(date, date),
    STORAGE bytea;

CREATE OPERATOR CLASS tde_ope_timestamptz_enc_ops
    DEFAULT FOR TYPE timestamptz
    USING tde_ope_btree
    FAMILY tde_ope_enc_ops_family
AS
    OPERATOR 1  <  (timestamptz, timestamptz),
    OPERATOR 2  <= (timestamptz, timestamptz),
    OPERATOR 3  =  (timestamptz, timestamptz),
    OPERATOR 4  >= (timestamptz, timestamptz),
    OPERATOR 5  >  (timestamptz, timestamptz),
	FUNCTION 1 tde_ope_timestamptz_cmp(timestamptz, timestamptz),
    STORAGE bytea;
