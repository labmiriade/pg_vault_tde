# tap/21_cache_key_cross_db.t — the shmem DEK cache must key on (dbid, relid)
#
# TdeRelDekMap lives in shared memory and is read by the backends of every
# database, but relid is only unique WITHIN a database.  CREATE DATABASE is a
# physical copy of the template's directory, so a cloned database hands out
# pg_class OIDs identical to its template's — the collision this test needs is
# guaranteed, not incidental.
#
# With a relid-only cache key, the first database to populate the entry hands
# its DEK to the other one.  The GCM AAD binds MyDatabaseId (tde_compute_aad),
# so the victim does not silently read wrong plaintext — it gets
# "AES-256-GCM authentication FAILED" on data that is perfectly intact.  A
# read outage on the wrong database, triggered by an unrelated database's
# traffic, which no single-database test can catch.
#
# Setup: clone db_a into db_b (same relid), TRUNCATE the clone's rows (they
# were sealed under db_a's dbid and are unreadable there by design), rotate
# db_b's DEK so the two databases genuinely hold different keys, then check
# each database still reads its own row whatever order they are touched in.
use strict;
use warnings;
use Test::More tests => 7;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('cache_key_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');

sub wallet_path
{
    my ($dbname) = @_;
    my $oid = $node->safe_psql('postgres',
        "SELECT oid FROM pg_database WHERE datname = '$dbname'");
    $oid =~ s/^\s+|\s+$//g;
    return "/var/lib/pg_vault_tde/$oid/wallet.p12";
}

sub wrapped_dek
{
    my ($dbname) = @_;
    return $node->safe_psql($dbname,
        "SELECT encode(wrapped_dek, 'hex') FROM pg_vault_tde_catalog "
      . "WHERE relid = 'tcoll'::regclass::oid");
}

# ── db_a: extension, wallet, one encrypted table ───────────────────────────
$node->safe_psql('postgres', 'CREATE DATABASE db_a;');
$node->safe_psql('db_a', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('db_a', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('db_a', "SELECT pg_vault_tde_wallet_unlock('test-password')");
$node->safe_psql('db_a', q{
    CREATE TABLE tcoll (id int, val text) USING encrypted_heap;
    INSERT INTO tcoll VALUES (1, 'sentinel_from_db_a');
});
ok(1, 'db_a has an encrypted table');

# ── db_b: physical clone — same pg_class OIDs, same catalog row ────────────
$node->safe_psql('postgres', 'CREATE DATABASE db_b TEMPLATE db_a;');

# The wallet is per-database (/var/lib/pg_vault_tde/<dboid>/wallet.p12).  Init
# creates db_b's directory; overwriting it with db_a's wallet gives both
# databases the same KEK, so db_b can unwrap the DEK it inherited in the clone
# — which the rotation below needs before it can replace it.
$node->safe_psql('db_b', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->command_ok(['cp', wallet_path('db_a'), wallet_path('db_b')],
    'db_b shares db_a\'s wallet KEK');
$node->safe_psql('db_b', "SELECT pg_vault_tde_wallet_unlock('test-password')");

# The whole premise: without the OID collision this test proves nothing.
my $relid_a = $node->safe_psql('db_a', "SELECT 'tcoll'::regclass::oid");
my $relid_b = $node->safe_psql('db_b', "SELECT 'tcoll'::regclass::oid");
is($relid_b, $relid_a, "tcoll has the same relid in both databases ($relid_a)");

# ── Give db_b a different DEK under that same relid ────────────────────────
# TRUNCATE first: the cloned rows carry db_a's dbid in their AAD and cannot be
# decrypted here, so leaving them would only make the rotation BGW fail.  The
# relid survives TRUNCATE (only the relfilenode changes), which is the point.
#
# db_b's cache entry is cold here — wallet_init/unlock evicted, and nothing in
# db_b has read the table yet.  That used to break the rotation on its own
# (zero_rel_dek could not stash a prev_dek it did not have); no warm-up read is
# needed now.  See tap/22_rotate_cold_cache.t.
$node->safe_psql('db_b', 'TRUNCATE tcoll;');
$node->safe_psql('db_b', q{
    DO $$
    DECLARE done boolean := false;
    BEGIN
        PERFORM pg_vault_tde_rotate_online('tcoll'::regclass);
        FOR i IN 1..100 LOOP
            SELECT (status = 'complete') INTO done
            FROM pg_vault_tde_rotation_progress
            WHERE relid = 'tcoll'::regclass::oid;
            EXIT WHEN done;
            PERFORM pg_sleep(0.1);
        END LOOP;
        IF NOT done THEN
            RAISE EXCEPTION 'rotation in db_b did not complete';
        END IF;
    END $$;
    INSERT INTO tcoll VALUES (1, 'sentinel_from_db_b');
});

# Guard against the test silently degrading into "same key, of course it works".
isnt(wrapped_dek('db_b'), wrapped_dek('db_a'),
    'db_a and db_b hold different DEKs for the same relid');

# ── Both databases must read back their own row ────────────────────────────
# db_a reads first: with a relid-only key it would find db_b's freshly-rotated
# DEK already sitting in the one shared entry.
my $read_a = $node->safe_psql('db_a', 'SELECT val FROM tcoll');
is($read_a, 'sentinel_from_db_a', 'db_a reads its own row, not db_b\'s DEK');

my $read_b = $node->safe_psql('db_b', 'SELECT val FROM tcoll');
is($read_b, 'sentinel_from_db_b', 'db_b reads its own row, not db_a\'s DEK');

# Re-read db_a now that db_b has populated the cache: catches an entry that is
# overwritten rather than kept side by side.
$read_a = $node->safe_psql('db_a', 'SELECT val FROM tcoll');
is($read_a, 'sentinel_from_db_a', 'db_a still reads its own row after db_b');

$node->stop;
