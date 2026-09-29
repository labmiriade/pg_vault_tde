# tap/40_cluster_order.t — CLUSTER on encrypted_heap puts the rows in index
# order, as on a plain heap
#
# Core hands table_relation_copy_for_cluster() the clustering index and
# whether to sort; heapam then writes the rows through an index scan in that
# order, or sorts them first.  The TAM's copy_for_cluster always read the
# table sequentially and ignored both: CLUSTER compacted the table, kept every
# row, marked the index clustered — and left the order as it was
# (PSQLE-204).
#
# A plain heap twin with the same rows inserted in reverse is the reference.
# Both paths core can choose are forced in turn: the index scan
# (enable_sort = off) and the sort (enable_indexscan = off).  After each, the
# first rows in physical order, the contents, the out-of-line values and the
# index (amcheck heapallindexed) must match the twin.  A tde_btree index is
# ordered by the ciphertext of its keys, so CLUSTER on one must be refused,
# and VACUUM FULL must still work.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 13;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('cluster_order');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', 'CREATE EXTENSION amcheck;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

# Rows inserted in reverse; every tenth holds an out-of-line value; a dropped
# column holds some too.
for my $am (qw(heap encrypted_heap))
{
    my $t = $am eq 'heap' ? 'ch' : 'ce';
    $node->safe_psql('postgres', qq{
        SET client_min_messages = error;
        CREATE TABLE $t (id int PRIMARY KEY, s text, big text, gone text) USING $am;
        ALTER TABLE $t ALTER COLUMN big SET STORAGE EXTERNAL;
        ALTER TABLE $t ALTER COLUMN gone SET STORAGE EXTERNAL;
        INSERT INTO $t SELECT g, 's' || g,
               CASE WHEN g % 10 = 0 THEN repeat(md5(g::text), 400) END,
               CASE WHEN g % 7 = 0 THEN repeat(md5((-g)::text), 400) END
        FROM generate_series(1000, 1, -1) g;
        ALTER TABLE $t DROP COLUMN gone;
        DELETE FROM $t WHERE id % 13 = 0;
    });
}
$node->safe_psql('postgres', q{
    SET client_min_messages = error;
    CREATE INDEX ce_s ON ce USING tde_btree (s);
});

sub first_ids
{
    my ($t) = @_;
    return $node->safe_psql('postgres',
        "SELECT string_agg(id::text, ',') FROM (SELECT id FROM $t ORDER BY ctid LIMIT 5) s");
}

sub cluster_both
{
    my ($force) = @_;
    for my $t (qw(ch ce))
    {
        $node->safe_psql('postgres', "SET $force = off; CLUSTER $t USING ${t}_pkey");
    }
}

for my $case (['enable_sort', 'index scan'], ['enable_indexscan', 'sort'])
{
    my ($force, $path) = @$case;
    cluster_both($force);

    is(first_ids('ch'), '1,2,3,4,5', "heap ($path): CLUSTER orders the rows (control)");
    is(first_ids('ce'), first_ids('ch'),
       "CLUSTER ($path): the rows are in index order, as on the heap twin");
    is($node->safe_psql('postgres', q{
           SELECT count(*) FROM (
               (SELECT * FROM ce EXCEPT ALL SELECT * FROM ch)
               UNION ALL
               (SELECT * FROM ch EXCEPT ALL SELECT * FROM ce)) d}), '0',
       "CLUSTER ($path): the contents equal the heap twin");
    is($node->safe_psql('postgres', 'SELECT sum(length(t::text)) FROM ce t'),
       $node->safe_psql('postgres', 'SELECT sum(length(t::text)) FROM ch t'),
       "CLUSTER ($path): every whole row reads as on the heap twin");
    my ($rc, $out, $err) = $node->psql('postgres', "SELECT bt_index_check('ce_pkey', true)");
    is($rc, 0, "CLUSTER ($path): amcheck finds every row in the index") or diag $err;

    # Scramble the order again for the next case.
    $node->safe_psql('postgres', q{
        UPDATE ce SET s = s WHERE id % 2 = 0;
        UPDATE ch SET s = s WHERE id % 2 = 0;
        VACUUM ce; VACUUM ch;
    });
}

my ($rc, $out, $err) = $node->psql('postgres', 'CLUSTER ce USING ce_s');
like($err, qr/cannot cluster .* on tde_btree index "ce_s"/,
     'CLUSTER on a tde_btree index is refused');
($rc, $out, $err) = $node->psql('postgres', 'VACUUM FULL ce');
is($rc, 0, 'VACUUM FULL still works') or diag $err;
is($node->safe_psql('postgres', 'SELECT count(*) FROM ce'),
   $node->safe_psql('postgres', 'SELECT count(*) FROM ch'),
   'VACUUM FULL keeps every row');

$node->stop;
