# tap/34_standby_rotation.t — a streaming standby across rotate_online() on the
# primary, then a promotion
#
# The rotation's commit callback moves the primary's shared DEK cache to the
# new key; nothing reaches the standby's cache but the replicated catalog row.
# A standby that had a relation's DEK cached kept it: the cache never replaced
# a valid entry, so every row of the new generation went through the catalog
# and the KMS — one unwrap per row — and after a promotion the node encrypted
# new rows with the cached, retired key under its old generation, while the
# catalog held only the new one.  They were lost at the promoted node's first
# restart (PSQLE-190).
#
#   t_read   cached on the standby before the rotation, read after it
#   t_write  cached before, never read after, written right after promotion
#   t_two    rotated twice while the standby held generation 1
#   t_cold   first read on the standby after the rotation: the control
#
# Each is compared against a plain-heap twin on the standby, on the promoted
# node after new writes, and after its restart.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 30;

my @tables = qw(t_read t_write t_two t_cold);
my %rows   = map { $_ => 100 } @tables;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $primary = PostgreSQL::Test::Cluster->new('standby_rot_primary');
$primary->init(allows_streaming => 1);
$primary->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$primary->start;
$primary->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$primary->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$primary->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
for my $t (@tables)
{
    $primary->safe_psql('postgres', qq{
        CREATE TABLE $t (id int, val text) USING encrypted_heap;
        INSERT INTO $t SELECT g, '${t}_' || g FROM generate_series(1, 100) g;
        CREATE TABLE ${t}_truth AS SELECT * FROM $t;
    });
}

# Same host: the standby opens the same local wallet under /var/lib/pg_vault_tde.
$primary->backup('bk');
my $standby = PostgreSQL::Test::Cluster->new('standby_rot_standby');
$standby->init_from_backup($primary, 'bk', has_streaming => 1);
$standby->start;
$primary->wait_for_replay_catchup($standby);

my $node;

# Two assertions: every tag verifies, and the contents equal the twin.
sub check_table
{
    my ($t, $when) = @_;
    my ($rc, $out, $err) = $node->psql('postgres',
        "SELECT total_tuples || '|' || failed_tuples "
      . "FROM pg_vault_tde_verify_integrity('$t')");
    is($out, "$rows{$t}|0", "$t $when: every tag verifies") or diag $err;
    ($rc, $out, $err) = $node->psql('postgres', qq{
        SELECT count(*) FROM (
            (SELECT * FROM $t EXCEPT ALL SELECT * FROM ${t}_truth)
            UNION ALL
            (SELECT * FROM ${t}_truth EXCEPT ALL SELECT * FROM $t)) d});
    is($out, '0', "$t $when: contents equal the plain-heap twin") or diag $err;
}

# DEK_ACCESS audit lines — one per catalog read + KMS unwrap — while $sql runs.
sub unwraps_for
{
    my ($sql) = @_;
    my $off = -s $node->logfile;
    $node->safe_psql('postgres', $sql);
    $node->safe_psql('postgres', 'SELECT 1');
    my @n = (slurp_file($node->logfile, $off) =~ /event=DEK_ACCESS/g);
    return scalar @n;
}

sub rotate
{
    my ($t, $label) = @_;
    $primary->safe_psql('postgres',
        "DELETE FROM pg_vault_tde_rotation_progress WHERE relid = '$t'::regclass::oid");
    $primary->safe_psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('$t')");
    $primary->poll_query_until('postgres', qq{
        SELECT status IN ('complete', 'failed')
        FROM pg_vault_tde_rotation_progress WHERE relid = '$t'::regclass::oid})
      or die "$label of $t never finished";
    is($primary->safe_psql('postgres',
           "SELECT status FROM pg_vault_tde_rotation_progress "
         . "WHERE relid = '$t'::regclass::oid"), 'complete', "$t: $label completes");
}

# ---- the standby caches three of the four DEKs --------------------------------
$node = $standby;
$node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
$node->safe_psql('postgres', "SELECT count(val) FROM $_") for qw(t_read t_write t_two);

# ---- rotations on the primary -------------------------------------------------
rotate($_, 'rotation #1') for @tables;
rotate('t_two', 'rotation #2');
$primary->wait_for_replay_catchup($standby);

is($node->safe_psql('postgres', q{
       SELECT string_agg(generation::text, ',' ORDER BY c.relname)
       FROM pg_vault_tde_catalog k JOIN pg_class c ON c.oid = k.relid
       WHERE c.relname IN ('t_read', 't_write', 't_two', 't_cold')}), '2,2,3,2',
   'standby: the replicated catalog is at the new generations');

# ---- reads on the standby -----------------------------------------------------
check_table($_, 'on the standby, after the rotation') for qw(t_read t_two t_cold);
is(unwraps_for('SELECT count(val) FROM t_read'), 0,
   't_read: a second scan on the standby unwraps nothing (the cache holds the new DEK)');
is(unwraps_for('SELECT count(val) FROM t_two'), 0,
   't_two: a second scan on the standby unwraps nothing');

# ---- promotion, then writes before any read of t_write ------------------------
$primary->stop;
$standby->promote;
$node->poll_query_until('postgres', 'SELECT NOT pg_is_in_recovery()')
  or die 'standby never left recovery';
for my $t (@tables)
{
    $node->safe_psql('postgres', qq{
        INSERT INTO $t SELECT g, '${t}_new_' || g FROM generate_series(101, 150) g;
        INSERT INTO ${t}_truth SELECT g, '${t}_new_' || g FROM generate_series(101, 150) g;
    });
    $rows{$t} = 150;
}
check_table($_, 'on the promoted node, after new writes') for @tables;

# ---- restart: only the catalog is left ----------------------------------------
$node->restart;
$node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
check_table($_, 'on the promoted node, after a restart') for @tables;

$node->stop;
