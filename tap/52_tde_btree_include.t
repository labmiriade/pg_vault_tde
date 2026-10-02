# tap/52_tde_btree_include.t — tde_btree rejects INCLUDE columns
#
# tde_btree inherited btree's amcaninclude, so CREATE INDEX ... USING tde_btree
# (key) INCLUDE (col) was accepted.  An included column is a non-key payload:
# tde_iam_encrypt_index_datum only encrypts key attributes, so the INCLUDE
# value reached the leaf page in plaintext, bypassing allow_plaintext_index —
# and a bytea INCLUDE column drove TDE_IS_ENC_OPS_COL to read rd_opcintype past
# the key-attribute count (PSQLE-222).  tde_btree offers no index-only scan
# (amcanreturn is NULL), so an included column has no legitimate use here; the
# access method must refuse it.
use strict;
use warnings;
use Test::More tests => 7;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('btree_include');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

$node->safe_psql('postgres', q{
    CREATE TABLE t (k int, salary int, blob bytea, v text) USING encrypted_heap;
    INSERT INTO t SELECT g, g * 1000, ('\x' || lpad(to_hex(g), 8, '0'))::bytea, 'v' || g
    FROM generate_series(1, 100) g;
});

my $logpos = -s $node->logfile;

# ── INCLUDE is refused, whatever the payload type ─────────────────────────
{
    my ($rc, undef, $err) = $node->psql('postgres',
        'CREATE INDEX ti_inc ON t USING tde_btree (k) INCLUDE (salary);');
    isnt($rc, 0, 'tde_btree INCLUDE (int) is rejected');
    like($err, qr/included columns|INCLUDE/i,
        '... with an error about included columns');
}
{
    # The bytea payload is the one that drove the out-of-bounds read.
    my ($rc, undef, $err) = $node->psql('postgres',
        'CREATE INDEX ti_blob ON t USING tde_btree (k) INCLUDE (blob);');
    isnt($rc, 0, 'tde_btree INCLUDE (bytea) is rejected');
    unlike($err, qr/server closed the connection|terminated/,
        '... without crashing the backend');
}

is($node->safe_psql('postgres', 'SELECT 1'), '1', 'the cluster is still up');

# ── A plain tde_btree index (no INCLUDE) is unaffected ────────────────────
$node->safe_psql('postgres', 'CREATE INDEX ti_k ON t USING tde_btree (k);');
my $found = $node->safe_psql('postgres', q{
    SET enable_seqscan = off;
    SELECT v FROM t WHERE k = 42;});
is($found, 'v42', 'a tde_btree index without INCLUDE still answers equality');

ok(!$node->log_contains(qr/was terminated by signal|server process .* exited/, $logpos),
   'no crash was logged');

$node->stop;
