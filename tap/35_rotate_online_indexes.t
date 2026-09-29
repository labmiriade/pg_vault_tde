# tap/35_rotate_online_indexes.t — every index keeps finding every row across
# pg_vault_tde_rotate_online()
#
# The rotation rewrites each row with tuple_update(); a rewrite that cannot
# stay HOT puts the new version on another page, and the executor's UPDATE
# would then insert an entry for it into every index.  The rotation called the
# TAM directly and inserted none: it rebuilt its tde_btree indexes afterwards,
# on the belief that standard btree indexes need nothing, and left every
# other index pointing at the retired versions only.  After the rotation an
# index scan found no row at all, and a PRIMARY KEY or UNIQUE constraint —
# backed by a standard btree by default on an encrypted table — accepted
# duplicates (PSQLE-194).
#
# One table, 2000 rows padded so the rewrite cannot stay on its page, and five
# indexes: the PRIMARY KEY, a UNIQUE constraint, a plain btree, a partial one
# and a tde_btree.  After each step five checks: a lookup through each index,
# a range through the plain btree that must return every row, amcheck's
# heapallindexed on every btree, and a duplicate key and a duplicate unique
# value that must be refused.  Steps: before any rotation, rotation #1,
# VACUUM, a restart, rotation #2.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 27;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('rotate_indexes');
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

# The constraints get a standard btree with a WARNING; the plain and partial
# btree need allow_plaintext_index.
$node->safe_psql('postgres', q{
    SET client_min_messages = error;
    SET pg_vault_tde.allow_plaintext_index = on;
    CREATE TABLE ri (id int PRIMARY KEY, u text UNIQUE, k int, s text, pad text)
        USING encrypted_heap;
    CREATE INDEX ri_k ON ri USING btree (k);
    CREATE INDEX ri_k_even ON ri USING btree (k) WHERE k % 2 = 0;
    CREATE INDEX ri_s ON ri USING tde_btree (s);
    INSERT INTO ri SELECT g, 'u' || g, g, 's' || g, repeat('p', 300)
    FROM generate_series(1, 2000) g;
});

# Five assertions.
sub check
{
    my ($when) = @_;
    my $idx = q{SET enable_seqscan = off; SET enable_bitmapscan = off; };

    my ($rc, $out, $err) = $node->psql('postgres', $idx . q{
        SELECT (SELECT count(*) FROM ri WHERE id = 777) || ',' ||
               (SELECT count(*) FROM ri WHERE u = 'u777') || ',' ||
               (SELECT count(*) FROM ri WHERE k = 777) || ',' ||
               (SELECT count(*) FROM ri WHERE k = 778 AND k % 2 = 0) || ',' ||
               (SELECT count(*) FROM ri WHERE s = 's777')});
    is($out, '1,1,1,1,1', "$when: a lookup through each index finds its row") or diag $err;

    ($rc, $out, $err) = $node->psql('postgres', $idx
      . 'SELECT count(*) FROM ri WHERE k BETWEEN 1 AND 2000');
    is($out, '2000', "$when: the plain btree reaches every row") or diag $err;

    ($rc, $out, $err) = $node->psql('postgres', q{
        SELECT bt_index_check(i, true) FROM unnest(ARRAY[
            'ri_pkey', 'ri_u_key', 'ri_k', 'ri_k_even']::regclass[]) i});
    is($rc, 0, "$when: amcheck finds every row in every btree") or diag $err;

    ($rc, $out, $err) = $node->psql('postgres',
        "INSERT INTO ri VALUES (777, 'u_new', 0, 's_new', 'x')");
    like($err, qr/duplicate key value violates unique constraint "ri_pkey"/,
         "$when: a duplicate primary key is refused");

    ($rc, $out, $err) = $node->psql('postgres',
        "INSERT INTO ri VALUES (5000, 'u777', 0, 's_new', 'x')");
    like($err, qr/duplicate key value violates unique constraint "ri_u_key"/,
         "$when: a duplicate unique value is refused");
}

sub rotate
{
    my ($label) = @_;
    $node->safe_psql('postgres',
        "DELETE FROM pg_vault_tde_rotation_progress WHERE relid = 'ri'::regclass::oid");
    $node->safe_psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('ri')");
    $node->poll_query_until('postgres', q{
        SELECT status IN ('complete', 'failed')
        FROM pg_vault_tde_rotation_progress WHERE relid = 'ri'::regclass::oid})
      or die "$label never finished";
    is($node->safe_psql('postgres',
           "SELECT status FROM pg_vault_tde_rotation_progress "
         . "WHERE relid = 'ri'::regclass::oid"), 'complete', "$label completes");
}

check('before any rotation');

rotate('rotation #1');
check('after rotation #1');

$node->safe_psql('postgres', 'VACUUM ri');
check('after rotation #1 and VACUUM');

$node->restart;
$node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
check('after a restart');

rotate('rotation #2');
check('after rotation #2');

$node->stop;
