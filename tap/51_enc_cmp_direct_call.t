# tap/51_enc_cmp_direct_call.t — the tde_btree comparator refuses a direct call
#
# tde_enc_bytea_cmp is btree support function 1 for the tde_btree operator
# classes; it reads its two arguments as bytea (the stored SIV ciphertext).
# The per-type wrappers tde_int4_enc_cmp(int4,int4), tde_int8_enc_cmp(...),
# tde_uuid/date/timestamptz bind the same C function under non-bytea argument
# types and keep EXECUTE to PUBLIC.  Called straight from SQL, the C code read
# an integer (or a by-value datum) as a varlena pointer and dereferenced it,
# taking the whole cluster down — reachable by any role (PSQLE-221).
#
# The comparator must refuse a call whose argument type is known and is not
# bytea, and still work when the index machinery calls it (no expression info,
# bytea keys).
use strict;
use warnings;
use Test::More tests => 10;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('enc_cmp');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

my $logpos = -s $node->logfile;

# A table with a tde_btree enc_ops index, built before the crash tests so the
# index-path assertion runs on intact data.
$node->safe_psql('postgres', q{
    CREATE TABLE ti (id int, v text) USING encrypted_heap;
    CREATE INDEX ti_id ON ti USING tde_btree (id);
    INSERT INTO ti SELECT g, 'v' || g FROM generate_series(1, 200) g;
});

# ── Direct calls must be a clean ERROR, never a crash ─────────────────────
for my $call (
    ['int4',        'tde_int4_enc_cmp(1, 2)'],
    ['timestamptz', 'tde_timestamptz_enc_cmp(now(), now())'])
{
    my ($label, $expr) = @$call;
    my ($rc, undef, $err) = $node->psql('postgres', "SELECT $expr");
    isnt($rc, 0, "direct $label comparator call is refused, not run");
    unlike($err, qr/server closed the connection|terminated/,
        "... $label without crashing the backend");
}

# Reachable by any role: EXECUTE is PUBLIC.
$node->safe_psql('postgres', 'CREATE ROLE plain LOGIN;');
{
    my ($rc, undef, $err) = $node->psql('postgres',
        'SET ROLE plain; SELECT tde_int4_enc_cmp(1, 2);');
    isnt($rc, 0, 'a non-superuser calling the comparator is refused too');
    unlike($err, qr/server closed the connection|terminated/,
        '... and does not crash the cluster');
}

is($node->safe_psql('postgres', 'SELECT 1'), '1',
   'the cluster is still up after the direct calls');

# ── The genuine bytea comparator, and the index path, still work ──────────
is($node->safe_psql('postgres', q{SELECT tde_enc_bytea_cmp('\x01', '\x0102')},),
   '-1', 'tde_enc_bytea_cmp on real bytea still compares');

my $found = $node->safe_psql('postgres', q{
    SET enable_seqscan = off;
    SELECT v FROM ti WHERE id = 137;});
is($found, 'v137', 'a tde_btree equality lookup still finds its row');

ok(!$node->log_contains(qr/was terminated by signal|server process .* exited/, $logpos),
   'no crash was logged for the whole test');

$node->stop;
