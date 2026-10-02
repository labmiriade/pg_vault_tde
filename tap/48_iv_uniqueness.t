# tap/48_iv_uniqueness.t — no IV is used twice under one DEK
#
# AES-GCM loses both confidentiality and authentication if one IV is used
# twice under one key.  IVs are random, drawn from a per-process batch of 256
# (src/crypto/pg_vault_tde_crypto.c); a batch copied into another process — by
# a fork() after it was filled — would hand the same IVs out twice.  No
# PostgreSQL process forks after drawing an IV today, and since PSQLE-178 a
# process refills a batch it did not fill itself; nothing checked the property
# on disk.
#
# Four sessions write in turn — inserts, updates, out-of-line values — so their
# batches are drawn from side by side; the server restarts, and a rotation
# worker rewrites the table under the next DEK generation.  Then every tuple of
# the heap and of its TOAST relation, dead versions included, is read off the
# raw pages: the IV and the generation sit in the last 37 bytes of its data.
# No (generation, IV) pair may appear twice.
use strict;
use warnings;
use Test::More tests => 5;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('iv_unique');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n"
  . "autovacuum = off\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde; CREATE EXTENSION pageinspect;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', q{
    CREATE TABLE t (id int, v text, big text) USING encrypted_heap;
    ALTER TABLE t ALTER COLUMN big SET STORAGE EXTERNAL;
});

# Each session takes its own id range; the statements alternate between
# sessions, so each backend's batch is in use while the others are.
sub write_round
{
    my ($base) = @_;
    my @s = map { $node->background_psql('postgres', on_error_stop => 1) } 0 .. 3;
    for my $step (0 .. 9)
    {
        for my $k (0 .. 3)
        {
            my $lo = $base + $k * 1000 + $step * 50 + 1;
            my $hi = $lo + 49;
            $s[$k]->query_safe(qq{
                INSERT INTO t SELECT g, 's' || g,
                       CASE WHEN g % 10 = 0 THEN repeat(md5(g::text), 200) END
                FROM generate_series($lo, $hi) g;
                UPDATE t SET v = v || '.' WHERE id BETWEEN $lo AND $lo + 9;
            });
        }
    }
    $_->quit for @s;
}

write_round(0);
$node->restart;
write_round(10000);

$node->safe_psql('postgres',
    "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('t')");
$node->poll_query_until('postgres', q{
    SELECT status = 'complete' FROM pg_vault_tde_rotation_progress
    WHERE relid = 't'::regclass}) or die 'rotation never completed';
$node->safe_psql('postgres', q{
    INSERT INTO t SELECT g, 'after', repeat(md5(g::text), 200)
    FROM generate_series(20001, 20200) g;
});

my $census = $node->safe_psql('postgres', q{
    WITH rels(r) AS (
        VALUES ('t'::regclass),
               ((SELECT reltoastrelid FROM pg_class WHERE oid = 't'::regclass)::regclass)),
    tup AS (
        SELECT r = 't'::regclass AS heap,
               substring(i.t_data FROM length(i.t_data) - 36 FOR 12) AS iv,
               substring(i.t_data FROM length(i.t_data) - 7  FOR 8)  AS gen,
               substring(i.t_data FROM length(i.t_data) - 8  FOR 1)  AS ver
        FROM rels,
             LATERAL generate_series(0, (pg_relation_size(r) / 8192)::int - 1) b,
             LATERAL heap_page_items(get_raw_page(r::text, b)) i
        WHERE i.t_data IS NOT NULL AND length(i.t_data) >= 37)
    SELECT count(*) FILTER (WHERE ver <> '\x05'::bytea) || '|' ||
           count(*) FILTER (WHERE heap) || '|' ||
           count(*) FILTER (WHERE NOT heap) || '|' ||
           count(DISTINCT gen) || '|' ||
           count(*) || '|' || count(DISTINCT (gen, iv))
    FROM tup});
my ($not_v5, $heap, $toast, $gens, $total, $distinct) = split /\|/, $census;
diag "heap tuples $heap, TOAST chunks $toast, generations $gens";

is($not_v5, '0', 'every tuple read ends with a v5 trailer: IV, tag, version, generation');
cmp_ok($heap, '>', 6000, 'every version of every row was read off the heap pages');
cmp_ok($toast, '>', 1000, '... and the chunks of the TOAST relation');
is($gens, '2', '... under two DEK generations (before and after the rotation)');
is($distinct, $total, 'no IV is used twice under one DEK generation');

$node->stop;
