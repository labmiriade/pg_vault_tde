# tap/38_partial_index_build.t — a partial index on encrypted_heap holds only
# the rows its predicate admits
#
# CREATE INDEX and REINDEX on encrypted_heap go through the TAM's own build
# scan, which decrypts each row before computing its keys.  It never
# evaluated the index predicate: a partial index received every row, so a
# valid UNIQUE ... WHERE was refused on duplicates outside the predicate, a
# plain partial index was as large as a full one, and amcheck's
# heapallindexed, which relies on the same scan, reported rows "missing" —
# and queries through a partial index returned wrong rows: the planner drops
# the quals the predicate implies, trusting the index to hold only rows that
# satisfy it (PSQLE-198).
#
# A plain heap twin with the same data is the reference: after CREATE INDEX
# and after REINDEX the encrypted table must accept the same UNIQUE partial
# index, refuse and accept the same inserts, end up with a partial index of
# the same size, pass amcheck, answer through a partial index what a
# sequential scan answers, answer through a tde_btree partial index, and keep
# the heap's reltuples a count of all its rows.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 11;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('partial_index');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.allow_plaintext_index = on\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', 'CREATE EXTENSION amcheck;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

# 1000 rows, code repeating every 10, only the first ten active.
for my $t (qw(ph pe))
{
    my $am = $t eq 'ph' ? 'heap' : 'encrypted_heap';
    $node->safe_psql('postgres', qq{
        CREATE TABLE $t (id int, code int, active bool, s text) USING $am;
        INSERT INTO $t SELECT g, g % 10, g <= 10, 's' || g FROM generate_series(1, 1000) g;
    });
}

my ($rc, $out, $err) = $node->psql('postgres',
    'SET client_min_messages = error; CREATE UNIQUE INDEX ph_code_active ON ph (code) WHERE active');
is($rc, 0, 'heap: the UNIQUE partial index builds') or diag $err;
($rc, $out, $err) = $node->psql('postgres',
    'SET client_min_messages = error; CREATE UNIQUE INDEX pe_code_active ON pe (code) WHERE active');
is($rc, 0, 'encrypted_heap: the same UNIQUE partial index builds') or diag $err;

($rc, $out, $err) = $node->psql('postgres', 'INSERT INTO pe VALUES (2000, 3, false, NULL)');
is($rc, 0, 'encrypted_heap: a row outside the predicate may repeat a code') or diag $err;
($rc, $out, $err) = $node->psql('postgres', 'INSERT INTO pe VALUES (2001, 3, true, NULL)');
like($err, qr/duplicate key value violates unique constraint "pe_code_active"/,
     'encrypted_heap: a row inside the predicate may not');

$node->safe_psql('postgres', q{
    SET client_min_messages = error;
    CREATE INDEX ph_id_small ON ph (id) WHERE id <= 10;
    CREATE INDEX pe_id_small ON pe (id) WHERE id <= 10;
    CREATE INDEX pe_s_small ON pe USING tde_btree (s) WHERE id <= 10;
    CREATE INDEX pe_code_live ON pe (code) WHERE active;
    VACUUM ANALYZE pe;
});
is($node->safe_psql('postgres', q{
       SET enable_seqscan = off; SET enable_bitmapscan = off;
       SELECT count(*) FROM pe WHERE code = 3 AND active}),
   $node->safe_psql('postgres', q{
       SET enable_indexscan = off; SET enable_indexonlyscan = off; SET enable_bitmapscan = off;
       SELECT count(*) FROM pe WHERE code = 3 AND active}),
   'encrypted_heap: a query through a partial index returns what a sequential scan does');
is($node->safe_psql('postgres', "SELECT pg_relation_size('pe_id_small')"),
   $node->safe_psql('postgres', "SELECT pg_relation_size('ph_id_small')"),
   'encrypted_heap: a partial index is the size of the heap twin\'s');

($rc, $out, $err) = $node->psql('postgres', q{
    SELECT bt_index_check(i, true)
    FROM unnest(ARRAY['pe_code_active', 'pe_id_small']::regclass[]) i});
is($rc, 0, 'encrypted_heap: amcheck heapallindexed passes on the partial indexes') or diag $err;

is($node->safe_psql('postgres', q{
       SET enable_seqscan = off; SET enable_bitmapscan = off;
       SELECT count(*) FROM pe WHERE s = 's7' AND id <= 10}), '1',
   'encrypted_heap: a tde_btree partial index answers');

is($node->safe_psql('postgres', "SELECT reltuples::int FROM pg_class WHERE oid = 'pe'::regclass"),
   '1001', 'encrypted_heap: reltuples still counts every row after a partial index build');

($rc, $out, $err) = $node->psql('postgres',
    'SET client_min_messages = error; REINDEX INDEX pe_code_active; REINDEX INDEX pe_id_small');
is($rc, 0, 'encrypted_heap: REINDEX of the partial indexes succeeds') or diag $err;
is($node->safe_psql('postgres', "SELECT pg_relation_size('pe_id_small')"),
   $node->safe_psql('postgres', "SELECT pg_relation_size('ph_id_small')"),
   'encrypted_heap: ... and leaves the partial index the size of the heap twin\'s');

$node->stop;
