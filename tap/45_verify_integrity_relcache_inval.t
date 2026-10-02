# tap/45_verify_integrity_relcache_inval.t — pg_vault_tde_verify_integrity()
# is not fooled by a relcache invalidation of the table it scans
#
# verify_integrity() read the raw, encrypted tuples by pointing the table's
# relcache entry at heapam (rd_tableam) for the length of its scan, and
# decrypted each one itself.  A relcache invalidation of the table processed
# during the scan rebuilt the open entry, and rd_tableam was the TAM again:
# every later tuple came back already decrypted, failed as ciphertext ("too
# short", "decryption failed"), and the table was reported damaged while every
# row read (PSQLE-207).  Autovacuum sends such an invalidation whenever it
# updates the table's statistics; the soak test (tap/43) met it about a
# minute after a restart, when autovacuum first came by.
#
# Deterministic here: after a restart no DEK is cached, so the first tuple
# makes verify_integrity() read pg_vault_tde_catalog, and a session holding
# that table locked stops it there — its scan already open.  Meanwhile an
# update of the table's pg_class row, as autovacuum's statistics make,
# invalidates its relcache entry.  Released, verify_integrity() takes the lock,
# processes the invalidation, and scans on.  Every tuple must still verify.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 5;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('verify_inval');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n"
  . "autovacuum = off\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', q{
    CREATE TABLE enc (id int, k int, big text) USING encrypted_heap;
    ALTER TABLE enc ALTER COLUMN big SET STORAGE EXTERNAL;
    INSERT INTO enc SELECT g, g % 7, CASE WHEN g % 3 = 0 THEN repeat(md5(g::text), 400) END
    FROM generate_series(1, 200) g;
});

my $verify = "SELECT total_tuples || '|' || failed_tuples FROM pg_vault_tde_verify_integrity('enc')";
is($node->safe_psql('postgres', $verify), '200|0', 'every tuple verifies (control)');

$node->restart;
my $locker = $node->background_psql('postgres', on_error_stop => 0);
$locker->query_safe('BEGIN; LOCK TABLE pg_vault_tde_catalog IN ACCESS EXCLUSIVE MODE;');

my $v = $node->background_psql('postgres', on_error_stop => 0);
$v->query_until(qr/verifying/, "\\echo verifying\n$verify;\n");
ok($node->poll_query_until('postgres', q{
       SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
                      WHERE c.relname = 'pg_vault_tde_catalog' AND NOT l.granted)}),
   'verify_integrity() waits for its DEK, its scan open');

# An update of the table's pg_class row: what autovacuum's statistics do.
$node->safe_psql('postgres', "UPDATE pg_class SET relpages = relpages WHERE oid = 'enc'::regclass");
$locker->query_safe('COMMIT');
$locker->quit;

# The next query's output starts with what verify_integrity() printed.
my ($got) = $v->query('SELECT 1') =~ /^(\d+\|\d+)$/m;
$v->quit;
is($got, '200|0', 'after an invalidation mid-scan, every tuple still verifies');

is($node->safe_psql('postgres', 'SELECT count(*) FROM enc'), '200', 'every row reads');
is($node->safe_psql('postgres', $verify), '200|0', 'and verify_integrity() agrees when left alone');

$node->stop;
