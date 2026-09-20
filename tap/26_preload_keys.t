# tap/26_preload_keys.t — the startup DEK cache warm-up
#
# pg_vault_tde.preload_keys asks a background worker to unwrap every DEK in
# pg_vault_tde_catalog once the server is up, so the first query on an
# encrypted table does not pay a KMS round-trip.
#
# Both halves of the catalog and the wallet are per-database, and a background
# worker may connect exactly once in its life, so this is a launcher plus one
# short-lived worker per database rather than a single worker walking the
# cluster.  What that buys — and what this test checks — is that turning the
# GUC on for ONE database warms that database and leaves the others alone.
#
# The cache is shared memory, so "warm" is observable across connections: a
# fresh backend that has never touched the table still finds the key there.
# Reading the key is not directly visible from SQL, so the evidence is the
# worker's own log line, plus the negative case where it must be absent.
use strict;
use warnings;
use Test::More tests => 7;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('preload_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');

# Two databases with encrypted tables; only one will ask to be preloaded.
for my $db ('warm_db', 'cold_db')
{
    $node->safe_psql('postgres', "CREATE DATABASE $db;");
    $node->safe_psql($db, 'CREATE EXTENSION pg_vault_tde;');
    $node->safe_psql($db, "SELECT pg_vault_tde_wallet_init('test-password')");
    $node->safe_psql($db, "SELECT pg_vault_tde_wallet_unlock('test-password')");
    $node->safe_psql($db, qq{
        CREATE TABLE t1 (id int, val text) USING encrypted_heap;
        CREATE TABLE t2 (id int, val text) USING encrypted_heap;
        CREATE TABLE t3 (id int, val text) USING encrypted_heap;
        INSERT INTO t1 VALUES (1, '$db-one');
        INSERT INTO t2 VALUES (2, '$db-two');
        INSERT INTO t3 VALUES (3, '$db-three');
    });
}
ok(1, 'two databases with three encrypted tables each');

# Per-database, exactly as an operator would scope it.
$node->safe_psql('postgres',
    'ALTER DATABASE warm_db SET pg_vault_tde.preload_keys = on');

my $warm_oid = $node->safe_psql('postgres',
    "SELECT oid FROM pg_database WHERE datname = 'warm_db'");
my $cold_oid = $node->safe_psql('postgres',
    "SELECT oid FROM pg_database WHERE datname = 'cold_db'");
$_ =~ s/^\s+|\s+$//g for ($warm_oid, $cold_oid);

# Restart: the launcher is a static worker, so it runs once per postmaster.
#
# Take the log offset first and search only past it.  The launcher already ran
# at the first startup — against a cluster that had no encrypted database yet —
# so its "finished" line is in the log before the restart, and matching it
# would report success before the run under test had even begun.
my $logstart = -s $node->logfile;
$node->restart;

$node->wait_for_log(qr/DEK preload finished/, $logstart);
my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);

like($log, qr/DEK preload finished for \d+ database\(s\)/,
     'the preload launcher ran and finished')
    or diag "log tail:\n" . substr($log, -2000);

like($log, qr/preloaded 3 DEK\(s\) for database $warm_oid\b/,
     'warm_db had its three DEKs loaded')
    or diag "log tail:\n" . substr($log, -2000);

unlike($log, qr/preloaded \d+ DEK\(s\) for database $cold_oid\b/,
       'cold_db was visited but skipped, having never asked');

# Whatever the cache state, the data must be right in both.
is($node->safe_psql('warm_db', 'SELECT val FROM t2 WHERE id = 2'),
   'warm_db-two', 'preloaded database reads correctly');
is($node->safe_psql('cold_db', 'SELECT val FROM t2 WHERE id = 2'),
   'cold_db-two', 'non-preloaded database reads correctly');

# A preloaded key belongs to its own database: same table names, same shapes,
# and the cache is keyed by (dbid, relid), so warming one must not answer for
# the other.
is($node->safe_psql('cold_db', 'SELECT val FROM t1 WHERE id = 1'),
   'cold_db-one', 'warming one database did not leak its keys into the other');

$node->stop;
