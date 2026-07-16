# tap/15_basebackup_tde.t - pg_basebackup_tde wrapper (PSQLE-23)
# End-to-end: seal_keys_bytea, multi-database bundle capture around
# pg_basebackup, restore on a second node, unseal round-trip, and the
# CLI failure modes (missing passphrase, failed backup, tar format).
use strict;
use warnings;
use Test::More tests => 29;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use File::Spec;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $node = PostgreSQL::Test::Cluster->new('bb_primary');
$node->init(allows_streaming => 1);
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres',
    "CREATE TABLE s1 (id serial, payload text) USING encrypted_heap;");
$node->safe_psql('postgres',
    "INSERT INTO s1 (payload) VALUES ('secret-in-postgres');");

# Second database with the extension: the wrapper must seal it too.
$node->safe_psql('postgres', 'CREATE DATABASE seconddb');
$node->safe_psql('seconddb', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('seconddb', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('seconddb',
    "CREATE TABLE s2 (id serial, payload text) USING encrypted_heap;");
$node->safe_psql('seconddb',
    "INSERT INTO s2 (payload) VALUES ('secret-in-seconddb');");

# Database without the extension: must be skipped, no bundle.
$node->safe_psql('postgres', 'CREATE DATABASE plaindb');

# --- pg_vault_tde_seal_keys_bytea ---
my $magic = $node->safe_psql('postgres',
    "SELECT substring(pg_vault_tde_seal_keys_bytea('seal-pass') from 1 for 7)");
is($magic, '\x5444455345414c', 'bytea bundle starts with TDESEAL magic');

my $len_ok = $node->safe_psql('postgres',
    "SELECT length(pg_vault_tde_seal_keys_bytea('seal-pass')) > 116");
is($len_ok, 't', 'bytea bundle is longer than the empty-bundle minimum');

$node->safe_psql('postgres', 'CREATE ROLE lowpriv LOGIN');
my $stderr;
my $rc = $node->psql('postgres',
    "SET ROLE lowpriv; SELECT pg_vault_tde_seal_keys_bytea('seal-pass')",
    stderr => \$stderr);
isnt($rc, 0, 'seal_keys_bytea is rejected for non-superuser');
like($stderr, qr/superuser|permission denied/i,
    'non-superuser rejection mentions privileges');

# --- wrapper: backup + one bundle per database ---
my $backup_dir = $node->backup_dir . '/tde_backup';
{
    local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE} = 'seal-pass';
    $node->command_ok(
        ['pg_basebackup_tde', '-D', $backup_dir,
         '-h', $node->host, '-p', $node->port, '--checkpoint=fast'],
        'pg_basebackup_tde succeeds');
}
ok(-f "$backup_dir/PG_VERSION", 'backup directory contains PG_VERSION');
ok(-f "$backup_dir/pg_vault_tde_keys.postgres.sealed",
    'bundle written for postgres');
ok(-f "$backup_dir/pg_vault_tde_keys.seconddb.sealed",
    'bundle written for seconddb');
ok(!-e "$backup_dir/pg_vault_tde_keys.plaindb.sealed",
    'no bundle for database without the extension');

my $mode = (stat("$backup_dir/pg_vault_tde_keys.postgres.sealed"))[2] & 07777;
is($mode, 0600, 'bundle file is 0600');

my $bytes = PostgreSQL::Test::Utils::slurp_file(
    "$backup_dir/pg_vault_tde_keys.postgres.sealed");
is(substr($bytes, 0, 7), 'TDESEAL', 'bundle file starts with TDESEAL magic');

# --- restore the backup on a second node ---
# Same host, same database OIDs: the local wallets under /var/lib/pg_vault_tde
# are already in place, which stands in for the manual KEK transport step.
my $restored = PostgreSQL::Test::Cluster->new('bb_restore');
$restored->init_from_backup($node, 'tde_backup');
$restored->start;

is($restored->safe_psql('postgres', 'SELECT payload FROM s1 LIMIT 1'),
    'secret-in-postgres', 'restored postgres table decrypts');
is($restored->safe_psql('seconddb', 'SELECT payload FROM s2 LIMIT 1'),
    'secret-in-seconddb', 'restored seconddb table decrypts');

# Drift: dirty the catalog on the restored node, unseal from the bundle the
# wrapper stored inside the backup, expect the sealed generation back.
$restored->safe_psql('seconddb',
    "UPDATE pg_vault_tde_catalog SET generation = 999 WHERE wrapped_dek IS NOT NULL;");
my $bundle = File::Spec->rel2abs($restored->data_dir)
    . '/pg_vault_tde_keys.seconddb.sealed';
$restored->safe_psql('seconddb',
    "SELECT pg_vault_tde_unseal_keys('$bundle', 'seal-pass')");
is($restored->safe_psql('seconddb',
    'SELECT DISTINCT generation FROM pg_vault_tde_catalog WHERE wrapped_dek IS NOT NULL'),
    '1', 'unseal restores the sealed generation on the restored node');
$restored->stop;

# --- failure modes ---
my $fail_dir = $node->backup_dir . '/fail_backup';

# Missing passphrase: refused before anything happens.
{
    delete local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE};
    $node->command_fails_like(
        ['pg_basebackup_tde', '-D', $fail_dir,
         '-h', $node->host, '-p', $node->port],
        qr/PG_VAULT_TDE_SEAL_PASSPHRASE/,
        'missing passphrase env var is rejected');
}
ok(!-d $fail_dir, 'rejected run creates no target directory');

# pg_basebackup failure: sealing succeeded in memory, but nothing on disk.
{
    local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE} = 'seal-pass';
    $node->command_fails(
        ['pg_basebackup_tde', '-D', $fail_dir,
         '-h', $node->host, '-p', $node->port, '--invalid-flag-xyz'],
        'pg_basebackup failure propagates');
}
ok(!-d $fail_dir, 'failed backup leaves no bundle files behind');

# tar format: not supported in v1.
{
    local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE} = 'seal-pass';
    $node->command_fails_like(
        ['pg_basebackup_tde', '-D', $fail_dir, '-Ft',
         '-h', $node->host, '-p', $node->port],
        qr/tar/,
        'tar format is rejected');
}

# --- --keys-dir redirects the bundles ---
my $backup2  = $node->backup_dir . '/tde_backup2';
my $keys_dir = $node->backup_dir . '/keys2';
mkdir $keys_dir or die "mkdir $keys_dir: $!";
{
    local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE} = 'seal-pass';
    $node->command_ok(
        ['pg_basebackup_tde', '-D', $backup2, '--keys-dir', $keys_dir,
         '-h', $node->host, '-p', $node->port, '--checkpoint=fast'],
        'pg_basebackup_tde with --keys-dir succeeds');
}
ok(-f "$keys_dir/pg_vault_tde_keys.postgres.sealed",
    '--keys-dir receives the bundles');
ok(!-e "$backup2/pg_vault_tde_keys.postgres.sealed",
    'bundles are not duplicated into -D when --keys-dir is given');

# --- --seal-passphrase-file instead of the env var ---
my $backup3   = $node->backup_dir . '/tde_backup3';
my $pass_file = $node->backup_dir . '/seal.pass';
open(my $pf, '>', $pass_file) or die "open $pass_file: $!";
print $pf "seal-pass\n";
close $pf;
chmod 0600, $pass_file;
{
    delete local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE};
    $node->command_ok(
        ['pg_basebackup_tde', '-D', $backup3,
         '--seal-passphrase-file', $pass_file,
         '-h', $node->host, '-p', $node->port, '--checkpoint=fast'],
        'pg_basebackup_tde with --seal-passphrase-file succeeds without env var');
}
ok(-f "$backup3/pg_vault_tde_keys.postgres.sealed",
    '--seal-passphrase-file produces the bundles');

# Same passphrase as the env-var runs: the bundle must unseal.
$node->safe_psql('seconddb',
    "UPDATE pg_vault_tde_catalog SET generation = 999 WHERE wrapped_dek IS NOT NULL;");
$node->safe_psql('seconddb',
    "SELECT pg_vault_tde_unseal_keys('"
    . File::Spec->rel2abs($backup3) . "/pg_vault_tde_keys.seconddb.sealed', 'seal-pass')");
is($node->safe_psql('seconddb',
    'SELECT DISTINCT generation FROM pg_vault_tde_catalog WHERE wrapped_dek IS NOT NULL'),
    '1', 'bundle sealed via passphrase file unseals with the same passphrase');

# Unreadable passphrase file: refused before anything happens.
{
    delete local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE};
    $node->command_fails_like(
        ['pg_basebackup_tde', '-D', $fail_dir,
         '--seal-passphrase-file', $node->backup_dir . '/no_such.pass',
         '-h', $node->host, '-p', $node->port],
        qr/passphrase file/,
        'missing passphrase file is rejected');
}

$node->stop;
