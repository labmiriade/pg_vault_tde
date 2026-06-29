# tap/12_logical_repl_toast.t — logical replication of encrypted_heap TOAST values
#
# End-to-end validation of the custom WAL resource manager + stitch path: an
# encrypted_heap publisher (pg_vault_tde.toast_custom_rmgr = on) streams
# DECRYPTED rows — including externally TOASTed values — to a vanilla
# subscriber via a native CREATE SUBSCRIPTION pointed at a replication slot
# created with our output plugin.
#
# This promotes test/m1_custom_rmgr_test.sh PART B to a repeatable TAP test,
# modelled on PostgreSQL core's src/test/subscription/t/001_rep_changes.pl.
#
# Key setup detail (cf. m1): the subscriber must consume through OUR output
# plugin, so the slot is pre-created on the publisher with plugin
# 'pg_vault_tde' and the subscription attaches to it with create_slot = false.
# copy_data = false isolates the streaming (logical decoding) path — the part
# the custom rmgr drives — from the initial table sync.
#
# Coverage:
#   A) INSERT: inline / single-chunk / many-chunk / NULL / empty, plus a burst
#      of several many-chunk TOAST rows in ONE transaction (regression guard for
#      the streaming copy-back fix).
#   B) UPDATE / DELETE under REPLICA IDENTITY FULL + PK: non-key update with the
#      TOAST value unchanged ('u' path), update that rewrites the TOAST value,
#      large->small update, and DELETE (regression guard for the
#      HEAP_HASEXTERNAL / replica-identity-from-ciphertext fix — the right row
#      must be affected on the subscriber).
#   C) Multiple TOAST tables written in a single transaction (per-relation chunk
#      filtering in stitch).
#
# Requires REPLICA IDENTITY FULL + a primary key for UPDATE/DELETE; that is the
# supported configuration (DEFAULT is out of scope, see doc/).
use strict;
use warnings FATAL => 'all';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# ── Publisher: encrypted_heap + custom TOAST rmgr ───────────────────────────
my $pub = PostgreSQL::Test::Cluster->new('publisher');
$pub->init(allows_streaming => 'logical');
$pub->append_conf('postgresql.conf', <<'CONF');
shared_preload_libraries = 'pg_vault_tde'
pg_vault_tde.dev_mode = on
pg_vault_tde.toast_custom_rmgr = on
CONF
$pub->start;
$pub->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');

# ── Subscriber: vanilla PostgreSQL (plain heap, no extension) ───────────────
my $sub = PostgreSQL::Test::Cluster->new('subscriber');
$sub->init;
$sub->start;

my $connstr = $pub->connstr . ' dbname=postgres';

# Row signature for a table, computed identically on both nodes.  The publisher
# decrypts on read (TAM), the subscriber stores plaintext, so the signatures
# must match byte for byte when replication is correct.  length() catches a
# truncated / still-ciphertext value that happens to share an md5 prefix.
sub table_sig
{
    my ($node, $tbl) = @_;
    return $node->safe_psql('postgres', qq{
        SELECT coalesce(
                 string_agg(id || ':' ||
                            md5(coalesce(blob, '<NULL>')) || ':' ||
                            coalesce(length(blob)::text, '-'),
                            ',' ORDER BY id),
                 '<empty>')
        FROM $tbl
    });
}

# ── Schema: all tables + one publication, then the plugin slot ──────────────
$pub->safe_psql('postgres', <<'SQL');
CREATE TABLE t_ins (id int PRIMARY KEY, blob text) USING encrypted_heap;
ALTER TABLE t_ins ALTER COLUMN blob SET STORAGE EXTERNAL;

CREATE TABLE t_upd (id int PRIMARY KEY, k text, blob text) USING encrypted_heap;
ALTER TABLE t_upd ALTER COLUMN blob SET STORAGE EXTERNAL;
ALTER TABLE t_upd REPLICA IDENTITY FULL;

CREATE TABLE t_multi_a (id int PRIMARY KEY, blob text) USING encrypted_heap;
ALTER TABLE t_multi_a ALTER COLUMN blob SET STORAGE EXTERNAL;
CREATE TABLE t_multi_b (id int PRIMARY KEY, blob text) USING encrypted_heap;
ALTER TABLE t_multi_b ALTER COLUMN blob SET STORAGE EXTERNAL;

-- t_def keeps the default replica identity (PK) on purpose (negative case).
CREATE TABLE t_def (id int PRIMARY KEY, blob text) USING encrypted_heap;
ALTER TABLE t_def ALTER COLUMN blob SET STORAGE EXTERNAL;

-- t_copy exercises the initial-sync (COPY) path; published separately.
CREATE TABLE t_copy (id int PRIMARY KEY, blob text) USING encrypted_heap;
ALTER TABLE t_copy ALTER COLUMN blob SET STORAGE EXTERNAL;

CREATE PUBLICATION p_tde FOR TABLE t_ins, t_upd, t_multi_a, t_multi_b, t_def;
CREATE PUBLICATION p_copy FOR TABLE t_copy;
SELECT pg_create_logical_replication_slot('slot_tde', 'pg_vault_tde');
SELECT pg_create_logical_replication_slot('slot_copy', 'pg_vault_tde');
SQL

$sub->safe_psql('postgres', <<'SQL');
CREATE TABLE t_ins (id int PRIMARY KEY, blob text);
CREATE TABLE t_upd (id int PRIMARY KEY, k text, blob text);
ALTER TABLE t_upd REPLICA IDENTITY FULL;
CREATE TABLE t_multi_a (id int PRIMARY KEY, blob text);
CREATE TABLE t_multi_b (id int PRIMARY KEY, blob text);
CREATE TABLE t_def (id int PRIMARY KEY, blob text);
CREATE TABLE t_copy (id int PRIMARY KEY, blob text);
SQL

$sub->safe_psql('postgres', qq{
    CREATE SUBSCRIPTION s_tde
      CONNECTION '$connstr'
      PUBLICATION p_tde
      WITH (create_slot = false, slot_name = 'slot_tde', copy_data = false)
});
$sub->wait_for_subscription_sync($pub, 's_tde');

# ── A) INSERT shapes + single-txn burst ─────────────────────────────────────
$pub->safe_psql('postgres', <<'SQL');
INSERT INTO t_ins VALUES (1, 'inline value, no toast');
INSERT INTO t_ins SELECT 2, string_agg(md5(g::text), '')
    FROM generate_series(1, 150) g;                       -- ~4.8 KB single-chunk
INSERT INTO t_ins SELECT 3, string_agg(md5((g * 3)::text), '')
    FROM generate_series(1, 8000) g;                      -- ~256 KB many-chunk
INSERT INTO t_ins VALUES (4, NULL);
INSERT INTO t_ins VALUES (5, '');
SQL

# Burst: several many-chunk TOAST rows in ONE transaction.  This is the shape
# that crashed the walsender before the copy-back fix; it must replicate intact.
$pub->safe_psql('postgres', <<'SQL');
BEGIN;
INSERT INTO t_ins
    SELECT gid,
           (SELECT string_agg(md5((gid * 1000 + s)::text), '')
              FROM generate_series(1, 3000) s)
    FROM generate_series(10, 15) AS gid;
COMMIT;
SQL

$pub->wait_for_catchup('s_tde');
is(table_sig($sub, 't_ins'), table_sig($pub, 't_ins'),
   'INSERT inline/single-chunk/many-chunk/NULL/empty + burst replicated identically');

# ── B) UPDATE / DELETE under REPLICA IDENTITY FULL ──────────────────────────
$pub->safe_psql('postgres', <<'SQL');
INSERT INTO t_upd SELECT 1, 'key-a', string_agg(md5(g::text), '')
    FROM generate_series(1, 5000) g;                      -- many-chunk TOAST
INSERT INTO t_upd VALUES (2, 'key-b', 'small inline');
INSERT INTO t_upd SELECT 3, 'key-c', string_agg(md5((g + 7)::text), '')
    FROM generate_series(1, 6000) g;
SQL
$pub->wait_for_catchup('s_tde');
is(table_sig($sub, 't_upd'), table_sig($pub, 't_upd'),
   'UPDATE table seeded and replicated');

# Update a NON-toast column, leaving the TOAST value untouched ('u' path).
$pub->safe_psql('postgres', "UPDATE t_upd SET k = 'key-a2' WHERE id = 1");
$pub->wait_for_catchup('s_tde');
is(table_sig($sub, 't_upd'), table_sig($pub, 't_upd'),
   'UPDATE of non-key column keeps unchanged TOAST value correct on subscriber');

# Rewrite the TOAST value (new chunks).
$pub->safe_psql('postgres', <<'SQL');
UPDATE t_upd
   SET blob = (SELECT string_agg(md5((g * 11)::text), '') FROM generate_series(1, 9000) g)
 WHERE id = 1;
SQL
$pub->wait_for_catchup('s_tde');
is(table_sig($sub, 't_upd'), table_sig($pub, 't_upd'),
   'UPDATE rewriting the TOAST value replicated identically');

# large -> small (old_has_external branch).
$pub->safe_psql('postgres', "UPDATE t_upd SET blob = 'now small' WHERE id = 3");
$pub->wait_for_catchup('s_tde');
is(table_sig($sub, 't_upd'), table_sig($pub, 't_upd'),
   'UPDATE large->small TOAST replicated identically');

# DELETE a specific row: the matching (not a ciphertext-derived) row must go.
$pub->safe_psql('postgres', "DELETE FROM t_upd WHERE id = 1");
$pub->wait_for_catchup('s_tde');
is(table_sig($sub, 't_upd'), table_sig($pub, 't_upd'),
   'DELETE removes the correct row on the subscriber');
is($sub->safe_psql('postgres', 'SELECT count(*) FROM t_upd'), '2',
   'subscriber has exactly the surviving rows after DELETE');

# ── C) Two TOAST tables written in a single transaction ─────────────────────
$pub->safe_psql('postgres', <<'SQL');
BEGIN;
INSERT INTO t_multi_a SELECT 1, string_agg(md5((g)::text), '')   FROM generate_series(1, 7000) g;
INSERT INTO t_multi_b SELECT 1, string_agg(md5((g * 5)::text), '') FROM generate_series(1, 7000) g;
INSERT INTO t_multi_a VALUES (2, 'inline a');
INSERT INTO t_multi_b VALUES (2, 'inline b');
COMMIT;
SQL
$pub->wait_for_catchup('s_tde');
is(table_sig($sub, 't_multi_a'), table_sig($pub, 't_multi_a'),
   'multi-table txn: table A TOAST chunks routed to the right value');
is(table_sig($sub, 't_multi_b'), table_sig($pub, 't_multi_b'),
   'multi-table txn: table B TOAST chunks routed to the right value');

# ── D) Initial table sync (copy_data = true) via the TAM read path ──────────
# Pre-populate, then attach a copy_data = true subscription: the initial sync
# COPYs the table through the TAM (decrypt-on-read), so the subscriber receives
# plaintext even though logical decoding / stitch is not involved in the copy.
$pub->safe_psql('postgres', <<'SQL');
INSERT INTO t_copy VALUES (1, 'inline copy row');
INSERT INTO t_copy SELECT 2, string_agg(md5((g * 13)::text), '') FROM generate_series(1, 7000) g;
SQL
$sub->safe_psql('postgres', qq{
    CREATE SUBSCRIPTION s_copy
      CONNECTION '$connstr'
      PUBLICATION p_copy
      WITH (create_slot = false, slot_name = 'slot_copy', copy_data = true)
});
$sub->wait_for_subscription_sync($pub, 's_copy');
is(table_sig($sub, 't_copy'), table_sig($pub, 't_copy'),
   'initial COPY sync delivers decrypted inline + TOAST rows to the subscriber');

# ── E) Negative: REPLICA IDENTITY DEFAULT is out of scope for UPDATE/DELETE ──
# INSERT replicates fine under DEFAULT (no replica identity needed).  An UPDATE,
# though, makes the core derive the replica identity from the ENCRYPTED old
# tuple (reading ciphertext as if it were the PK), so the change targets the
# wrong key and the subscriber row diverges silently — exactly why FULL + PK is
# required (see doc/).  The contract asserted here is the predictable one: the
# walsender must NOT crash.
$pub->safe_psql('postgres', <<'SQL');
INSERT INTO t_def VALUES (101, 'def-insert-a');
INSERT INTO t_def VALUES (102, 'def-insert-b');
SQL
$pub->wait_for_catchup('s_tde');
is($sub->safe_psql('postgres', 'SELECT count(*) FROM t_def WHERE id IN (101, 102)'), '2',
   'INSERT under REPLICA IDENTITY DEFAULT replicates correctly');

$pub->safe_psql('postgres', "UPDATE t_def SET blob = 'def-updated' WHERE id = 101");
$pub->wait_for_catchup('s_tde');
is($pub->safe_psql('postgres', 'SELECT 1'), '1',
   'walsender survives UPDATE under DEFAULT replica identity (no crash; '
 . 'data divergence is the documented limitation, not a failure here)');

# Publisher must still be alive after all the decoding work.
is($pub->safe_psql('postgres', 'SELECT 1'), '1', 'publisher healthy after decode');

$sub->stop('fast');
$pub->stop('fast');

done_testing();
