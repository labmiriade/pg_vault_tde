# tap/24_shared_wallet_warning.t — warn before a KEK rotation that can only
# cover one of the databases sharing a wallet
#
# A rewrap walks pg_vault_tde_catalog, which CREATE EXTENSION creates
# separately in every database and which no backend can read across a database
# boundary, so it covers exactly the database it runs in.  The local provider
# then replaces the wallet file outright, which is cluster-wide as soon as
# pg_vault_tde.wallet_path points somewhere other than the per-database
# default.  The first database to rotate therefore strands every other
# database's wrapped DEKs under a KEK that no longer exists.
#
# It stays a WARNING, not an ERROR: a single-database cluster may legitimately
# set wallet_path, and refusing would break it.  What this test pins down is
# that the warning fires when the path is overridden and stays quiet on the
# per-database default — a warning that cried wolf on every custom path would
# just train DBAs to ignore it.
use strict;
use warnings;
use Test::More tests => 4;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('shared_wallet_node');
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
    CREATE TABLE w (id int, val text) USING encrypted_heap;
    INSERT INTO w VALUES (1, 'payload');
});

# ── Default per-database wallet: no warning ────────────────────────────────
my ($rc, $out, $err) = $node->psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');
is($rc, 0, 'KEK rotation succeeds on the per-database default wallet');
unlike($err, qr/covers only database/,
       'no shared-wallet warning when wallet_path is left at its default');

# ── Explicit wallet_path: warn ─────────────────────────────────────────────
# Copy the current wallet so the override points at a usable KEK, then redirect
# this database at it, exactly as an admin sharing one wallet would.
my $oid = $node->safe_psql('postgres',
    "SELECT oid FROM pg_database WHERE datname = 'postgres'");
$oid =~ s/^\s+|\s+$//g;
$node->command_ok(
    ['cp', "/var/lib/pg_vault_tde/$oid/wallet.p12", '/var/lib/pg_vault_tde/shared.p12'],
    'a shared wallet file is in place');

# ALTER DATABASE, not postgresql.conf: pg_vault_tde_wallet_init() persists the
# resolved path per-database (local_set_wallet -> ALTER DATABASE ... SET FROM
# CURRENT), and a database-level setting wins over the config file.  Sharing a
# wallet therefore means overriding it at the same level, on each database.
$node->safe_psql('postgres',
    "ALTER DATABASE postgres SET pg_vault_tde.wallet_path = "
  . "'/var/lib/pg_vault_tde/shared.p12'");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

($rc, $out, $err) = $node->psql('postgres', 'SELECT pg_vault_tde_rotate_kek()');
like($err, qr/covers only database/,
     'rotating with an overridden wallet_path warns that it covers one database')
    or diag "stderr was: $err";

$node->stop;
