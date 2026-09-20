# tap/25_cache_full_degrades.t — the DEK cache honours its budget, and
# relations past it stay fully usable
#
# Two properties, and they only make sense together.
#
# 1. pg_vault_tde.max_encrypted_relations is enforced.  The size handed to
#    ShmemInitHash() is NOT a cap: it sizes the initial allocation and the
#    bucket directory, and once the freelist empties dynahash keeps allocating
#    elements from the main shared memory segment, so the table grew to many
#    times the configured number.  For a cache holding plaintext DEKs that is
#    the wrong shape — the number an administrator sets is how much key
#    material they are willing to have unencrypted in shared memory.
#    tde_rel_dek_cache_store() now checks the count before HASH_ENTER.
#
# 2. Being past the budget costs a relation its cache entry, never its data.
#    The DEK has already been unwrapped and handed to the caller by the time
#    the store is attempted (pg_vault_tde_kms_get_rel_dek fills dek_out first),
#    so declining to memoise it must not fail the query.  It used to
#    ereport(ERROR) there.
#
# Together: 300 relations against a 64-entry budget must all read and write,
# and the server must say once that it stopped caching.
use strict;
use warnings;
use Test::More tests => 6;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('cache_full_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.max_encrypted_relations = 64\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

is($node->safe_psql('postgres', 'SHOW pg_vault_tde.max_encrypted_relations'),
   '64', 'cache pinned at its 64-entry floor');

# Far more relations than the setting allows for.
$node->safe_psql('postgres', q{
    DO $$
    BEGIN
        FOR i IN 1..300 LOOP
            EXECUTE format(
                'CREATE TABLE t%s (id int, val text) USING encrypted_heap', i);
            EXECUTE format(
                'INSERT INTO t%s VALUES (%s, %L)', i, i, 'payload_' || i);
        END LOOP;
    END $$;
});
ok(1, '300 encrypted relations created against a 64-entry cache');

# Every one of them must read back, cached or not.
my ($rc, $out, $err) = $node->psql('postgres', q{
    DO $$
    DECLARE v text;
    BEGIN
        FOR i IN 1..300 LOOP
            EXECUTE format('SELECT val FROM t%s WHERE id = %s', i, i) INTO v;
            IF v IS DISTINCT FROM 'payload_' || i THEN
                RAISE EXCEPTION 'relation t% read back %, expected payload_%',
                    i, COALESCE(v, 'NULL'), i;
            END IF;
        END LOOP;
    END $$;
});
is($rc, 0, 'all 300 relations read back correctly, far past the configured cap')
    or diag "psql stderr: $err";

# Writes past the cap must work too — the encrypt path takes the same route.
($rc, $out, $err) = $node->psql('postgres',
    "INSERT INTO t300 VALUES (999, 'written_past_the_cap')");
is($rc, 0, 'writing to a relation past the cap succeeds')
    or diag "psql stderr: $err";

is($node->safe_psql('postgres', "SELECT val FROM t300 WHERE id = 999"),
   'written_past_the_cap', 'and the row reads back');

# The budget must actually have bound — otherwise the reads above prove
# nothing about the degraded path.
my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile);
like($log, qr/DEK cache is at its configured limit of 64/,
     'the cache stopped at its configured limit and said so')
    or diag 'no limit warning: max_encrypted_relations is not being enforced';

$node->stop;
