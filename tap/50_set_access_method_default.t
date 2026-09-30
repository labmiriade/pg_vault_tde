# tap/50_set_access_method_default.t — ALTER TABLE ... SET ACCESS METHOD DEFAULT
#
# SET ACCESS METHOD DEFAULT (PG17+) leaves the AlterTableCmd's `name` NULL: the
# target access method is default_table_access_method, resolved by core later.
# The ProcessUtility hook ran strcmp(cmd->name, "encrypted_heap") on it before
# any permission check, so `ALTER TABLE t SET ACCESS METHOD DEFAULT` from any
# role dereferenced NULL and took the whole cluster down with a crash recovery
# (PSQLE-220).
#
# The hook must read default_table_access_method when the name is NULL, and
# treat the statement exactly as the explicit form of the same target: a DEFAULT
# that resolves to encrypted_heap registers the table's DEK, any other default
# deregisters it.
use strict;
use warnings;
use Test::More tests => 8;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('sam_default');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

my $amof = q{SELECT a.amname FROM pg_class c JOIN pg_am a ON a.oid = c.relam
             WHERE c.oid = 't'::regclass};
my $has_dek = q{SELECT count(*) FROM pg_vault_tde_catalog
                WHERE relid = 't'::regclass};

# ── 1. DEFAULT while default_table_access_method = heap: no crash ─────────
# A plain role reaches the hook before core's permission check, so the crash
# needed no privilege; a superuser reaches the same line.
$node->safe_psql('postgres', 'CREATE TABLE t (id int, v text);');
my $logpos = -s $node->logfile;
my ($rc, $out, $err) = $node->psql('postgres',
    'ALTER TABLE t SET ACCESS METHOD DEFAULT;');
is($rc, 0, 'SET ACCESS METHOD DEFAULT does not crash the backend')
    or diag("stderr: $err");
unlike($err, qr/server closed the connection|terminated/,
    '... the connection survived the statement');
ok(!$node->log_contains(qr/was terminated by signal|server process .* exited/, $logpos),
    '... and the server logged no crash');
is($node->safe_psql('postgres', 'SELECT 1'), '1', '... the cluster is still up');
is($node->safe_psql('postgres', $amof), 'heap',
    '... the table took the default access method (heap)');

# ── 2. DEFAULT that resolves to encrypted_heap: the DEK is registered ─────
$node->safe_psql('postgres', 'DROP TABLE t;');
$node->safe_psql('postgres',
    "SET default_table_access_method = 'encrypted_heap';
     CREATE TABLE t (id int, v text);");   # created encrypted already; now
$node->safe_psql('postgres', 'ALTER TABLE t SET ACCESS METHOD heap;');  # move away
$node->safe_psql('postgres',
    "SET default_table_access_method = 'encrypted_heap';
     ALTER TABLE t SET ACCESS METHOD DEFAULT;");   # DEFAULT -> encrypted_heap
is($node->safe_psql('postgres', $amof), 'encrypted_heap',
    'DEFAULT resolving to encrypted_heap converts the table');
is($node->safe_psql('postgres', $has_dek), '1',
    '... and registers its DEK, so writes are encrypted');

$node->safe_psql('postgres', "INSERT INTO t VALUES (1, 'sekret_default_am');");
$node->safe_psql('postgres', 'CHECKPOINT;');
my $raw = $node->safe_psql('postgres',
    "SELECT position('sekret_default_am'::bytea in
            pg_read_binary_file(pg_relation_filepath('t'))) > 0");
is($raw, 'f', '... and the value is not in plaintext on disk');

$node->stop;
