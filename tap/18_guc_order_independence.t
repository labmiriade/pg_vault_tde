# tap/18_guc_order_independence.t — KMS GUCs behave as independent settings
#
# Regression test for the class of bugs caused by initialising the KMS
# provider from the pg_vault_tde.kms_provider GUC assign hook.
#
# PostgreSQL applies a database's pg_db_role_setting entries one at a time:
# ProcessGUCArray() walks the setconfig array in order (and GUCArrayAdd()
# replaces an existing name IN PLACE, so re-issuing ALTER DATABASE SET does
# not move it), while process_settings() applies the DATABASE_USER scope
# before the DATABASE one.  Any provider init() done at assign time therefore
# ran against a half-applied configuration, which produced:
#
#   - a spurious "wallet passphrase ... not set" WARNING on every connection
#     whenever kms_provider had been SET before the passphrase source;
#   - silently, a wallet_path frozen to the per-database default whenever
#     kms_provider had been SET before wallet_path — encrypted tables then
#     failed to wrap/unwrap against a wallet that was never the configured one.
#
# init() now runs lazily on first KMS use (tde_kms_provider()), so the order
# and the scope of the ALTER statements must no longer matter.
use strict;
use warnings;
use Test::More tests => 11;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('guc_order_node');
$node->init;
# Deliberately NO cluster-level kms_provider: every database configures its
# own, which is the path where the assign hook used to fire mid-configuration.
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n");
$node->start;

my $warn_re = qr/no wallet passphrase source configured|passphrase env var/;

# Wallet paths must be absolute: the server resolves wallet_path from its own
# working directory (PGDATA), not from the directory prove was started in.
my $wallet_dir = PostgreSQL::Test::Utils::tempdir_short();

# ---------------------------------------------------------------------------
# Case 1 — worst-case array order: kms_provider FIRST, wallet knobs after.
# ---------------------------------------------------------------------------
my $wallet_worst = "$wallet_dir/w_worst/wallet.p12";

$node->safe_psql('postgres', 'CREATE DATABASE ord_worst;');
$node->safe_psql('ord_worst', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('ord_worst', qq{
    ALTER DATABASE ord_worst SET pg_vault_tde.kms_provider = 'local';
    ALTER DATABASE ord_worst SET pg_vault_tde.wallet_path = '$wallet_worst';
    ALTER DATABASE ord_worst SET pg_vault_tde.wallet_passphrase_command = 'echo worst-pass';
});

my $offset = -s $node->logfile;

$node->safe_psql('ord_worst', "SELECT pg_vault_tde_wallet_init('worst-pass');");
$node->safe_psql('ord_worst', q{
    CREATE TABLE t_worst (id serial, val text) USING encrypted_heap;
    INSERT INTO t_worst (val) VALUES ('sentinel_worst');
});

ok(!$node->log_contains($warn_re, $offset),
   'no spurious passphrase WARNING when kms_provider is SET before the wallet GUCs');

is($node->safe_psql('ord_worst', 'SELECT val FROM t_worst;'), 'sentinel_worst',
   'encrypted round-trip works with kms_provider SET first');

ok(-e $wallet_worst, 'wallet created at the configured wallet_path');

my $worst_oid = $node->safe_psql('postgres',
    "SELECT oid FROM pg_database WHERE datname = 'ord_worst';");
ok(!-e "/var/lib/pg_vault_tde/$worst_oid/wallet.p12",
   'per-database default wallet_path is not used when wallet_path is configured');

is($node->safe_psql('ord_worst', 'SHOW pg_vault_tde.wallet_path;'), $wallet_worst,
   'SHOW pg_vault_tde.wallet_path reports the configured path');

# ---------------------------------------------------------------------------
# Case 2 — wallet_path left unset: SHOW must report the computed default.
# ---------------------------------------------------------------------------
$node->safe_psql('postgres', 'CREATE DATABASE ord_default;');
$node->safe_psql('ord_default', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('ord_default', q{
    ALTER DATABASE ord_default SET pg_vault_tde.kms_provider = 'local';
    ALTER DATABASE ord_default SET pg_vault_tde.wallet_passphrase_command = 'echo default-pass';
});

my $default_oid = $node->safe_psql('postgres',
    "SELECT oid FROM pg_database WHERE datname = 'ord_default';");
is($node->safe_psql('ord_default', 'SHOW pg_vault_tde.wallet_path;'),
   "/var/lib/pg_vault_tde/$default_oid/wallet.p12",
   'SHOW pg_vault_tde.wallet_path reports the per-database default when unset');

# ---------------------------------------------------------------------------
# Case 3 — mixed scopes.  process_settings() applies ALTER ROLE ... IN DATABASE
# before ALTER DATABASE, so here the provider is always selected first no
# matter how the setconfig arrays are ordered: reordering cannot fix this one.
# ---------------------------------------------------------------------------
my $wallet_scope = "$wallet_dir/w_scope/wallet.p12";

$node->safe_psql('postgres', 'CREATE DATABASE ord_scope;');
$node->safe_psql('ord_scope', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', qq{
    ALTER ROLE postgres IN DATABASE ord_scope SET pg_vault_tde.kms_provider = 'local';
    ALTER DATABASE ord_scope SET pg_vault_tde.wallet_path = '$wallet_scope';
    ALTER DATABASE ord_scope SET pg_vault_tde.wallet_passphrase_command = 'echo scope-pass';
});

$offset = -s $node->logfile;

$node->safe_psql('ord_scope', "SELECT pg_vault_tde_wallet_init('scope-pass');");
$node->safe_psql('ord_scope', q{
    CREATE TABLE t_scope (id serial, val text) USING encrypted_heap;
    INSERT INTO t_scope (val) VALUES ('sentinel_scope');
});

is($node->safe_psql('ord_scope', 'SELECT val FROM t_scope;'), 'sentinel_scope',
   'encrypted round-trip works with kms_provider at ROLE-IN-DATABASE scope');

ok(!$node->log_contains($warn_re, $offset),
   'no spurious passphrase WARNING when kms_provider is set at a higher scope');

# ---------------------------------------------------------------------------
# Case 4 — wallet_status() on a fresh connection reports the wallet as open.
# init() is lazy, so status must go through the provider accessor; otherwise it
# would report the state of the session ("nothing opened it yet") instead of
# the state of the wallet.
# ---------------------------------------------------------------------------
is($node->safe_psql('ord_worst',
       'SELECT wallet_open FROM pg_vault_tde_wallet_status();'), 't',
   'wallet_status() reports wallet_open on a fresh connection (auto-open)');

# ---------------------------------------------------------------------------
# Case 5 — changing a passphrase source mid-session drops the cached KEK.
# ---------------------------------------------------------------------------
my $unlock = $node->safe_psql('ord_worst', q{
    SELECT pg_vault_tde_wallet_unlock('worst-pass');
    SELECT 'before=' || wallet_open FROM pg_vault_tde_wallet_status();
    SET pg_vault_tde.wallet_passphrase_command = 'echo some-other-pass';
    SELECT 'after=' || wallet_open FROM pg_vault_tde_wallet_status();
});
like($unlock, qr/before=t.*after=f/s,
     'SET of a wallet GUC invalidates the KEK cached by wallet_unlock()');

# ---------------------------------------------------------------------------
# Case 6 — a cluster-level 'local' provider must not try to open a wallet in
# the postmaster, where there is no database and hence no wallet path.
# ---------------------------------------------------------------------------
$node->append_conf('postgresql.conf',
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo cluster-pass'\n");

$offset = -s $node->logfile;
$node->restart;

ok(!$node->log_contains(qr/cannot open wallet ""/, $offset),
   'cluster-level local provider does not attempt a wallet open in the postmaster');

$node->stop;
