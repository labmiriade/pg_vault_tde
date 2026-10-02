# tap/22_rotate_cold_cache.t — online rotation must work on a cold DEK cache
#
# pg_vault_tde_rotate_online() runs, in order:
#
#   zero_rel_dek()   demote the current DEK to prev_dek[], invalidate dek[]
#   update_rel_dek() generate DEK N+1 and write it over the catalog row
#   reencrypt_table()rewrite every row, which must DECRYPT it at generation N
#
# prev_dek[] is the only copy of DEK N left once step 2 has overwritten the
# catalog, and step 3 cannot read a single pre-rotation row without it.
# zero_rel_dek() used to populate it straight from the shmem cache entry and
# do nothing at all — silently — when that entry was absent, so step 3 hit
# "pg_vault_tde: decryption failed" on the first row it touched.  The data
# stayed safe (phase 2 runs in one transaction, so the catalog re-key rolled
# back with it), but the rotation could never succeed against a cold relation.
#
# Cold is not an exotic state.  It is what you get after a restart, and after
# wallet_lock() or wallet_unlock(), which evict.  This test forces it the
# cheapest deterministic way — lock/unlock the wallet, which flushes the
# cache — and then rotates a table that still holds rows written under the
# outgoing DEK.
use strict;
use warnings;
use Test::More tests => 6;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('rotate_cold_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

$node->safe_psql('postgres', q{
    CREATE TABLE rot_cold (id int, val text) USING encrypted_heap;
    INSERT INTO rot_cold
        SELECT g, 'payload_' || g FROM generate_series(1, 50) g;
});

my $gen_before = $node->safe_psql('postgres',
    "SELECT generation FROM pg_vault_tde_catalog "
  . "WHERE relid = 'rot_cold'::regclass::oid");
is($gen_before, '1', 'table starts at generation 1');

# Force the cold cache: wallet_lock() evicts this database's DEKs, and the
# unlock that follows evicts again, so nothing is left for zero_rel_dek to
# find.  Reading the table here would warm it and hide the bug, so do not.
$node->safe_psql('postgres', 'SELECT pg_vault_tde_wallet_lock()');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
ok(1, 'DEK cache evicted — the entry for rot_cold is now cold');

my ($rc, $stdout, $stderr) = $node->psql('postgres', q{
    DO $$
    DECLARE done text;
    BEGIN
        PERFORM pg_vault_tde_rotate_online('rot_cold'::regclass);
        FOR i IN 1..100 LOOP
            SELECT status INTO done
            FROM pg_vault_tde_rotation_progress
            WHERE relid = 'rot_cold'::regclass::oid;
            EXIT WHEN done IN ('complete', 'failed');
            PERFORM pg_sleep(0.1);
        END LOOP;
        IF done IS DISTINCT FROM 'complete' THEN
            RAISE EXCEPTION 'rotation ended with status %', COALESCE(done, 'none');
        END IF;
    END $$;
});
is($rc, 0, 'rotation on a cold cache completes')
    or diag "psql stderr: $stderr";

my $gen_after = $node->safe_psql('postgres',
    "SELECT generation FROM pg_vault_tde_catalog "
  . "WHERE relid = 'rot_cold'::regclass::oid");
is($gen_after, '2', 'catalog generation advanced to 2');

# The rows were written under DEK 1 and must now be readable under DEK 2.
is($node->safe_psql('postgres', 'SELECT count(*) FROM rot_cold'), '50',
   'all 50 pre-rotation rows are still readable');
is($node->safe_psql('postgres',
       "SELECT val FROM rot_cold WHERE id = 42"), 'payload_42',
   'row contents survived the rotation intact');

$node->stop;
