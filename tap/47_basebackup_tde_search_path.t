# tap/47_basebackup_tde_search_path.t — pg_basebackup_tde calls the
# extension's own function, whatever search_path a database gives its sessions
#
# pg_basebackup_tde connects to every database with the extension and calls
# pg_vault_tde_seal_keys_bytea() there.  It ran that query with the session's
# search_path, and unqualified — and a database's owner, who need not be a
# superuser, sets the search_path of every session in it (ALTER DATABASE ...
# SET search_path) and creates schemas there.  An object of the same name in a
# schema ahead of the extension's was then what the tool ran, with the
# privileges of whoever ran the backup (PSQLE-178).  The client tools of core
# empty the search_path right after connecting and qualify every name; this
# one must too.
#
# The database's owner puts a schema of its own first in the database's
# search_path, with a function of the same name and signature that records
# being called.  A superuser runs pg_basebackup_tde: the function must never
# have run, and the bundle written for that database must be a real one.
use strict;
use warnings;
use Test::More tests => 4;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('bb_search_path');
$node->init(allows_streaming => 1);
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

$node->safe_psql('postgres', q{
    CREATE ROLE owner LOGIN;
    CREATE DATABASE ownerdb OWNER owner;
});
$node->safe_psql('ownerdb', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('ownerdb', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('ownerdb', q{
    CREATE TABLE secret (id int, v text) USING encrypted_heap;
    INSERT INTO secret VALUES (1, 'sealed');
});

# Everything below is what the owner may do in its own database.
$node->safe_psql('ownerdb', q{
    SET ROLE owner;
    CREATE SCHEMA mine;
    CREATE TABLE mine.calls (by_role name);
    CREATE FUNCTION mine.pg_vault_tde_seal_keys_bytea(text, text) RETURNS bytea
    LANGUAGE sql AS $$
        INSERT INTO mine.calls VALUES (current_user);
        SELECT '\x00'::bytea;
    $$;
    ALTER DATABASE ownerdb SET search_path = mine, public;
});

my $backup_dir = $node->backup_dir . '/bb';
{
    local $ENV{PG_VAULT_TDE_SEAL_PASSPHRASE} = 'seal-pass';
    $node->command_ok(
        ['pg_basebackup_tde', '-D', $backup_dir,
         '-h', $node->host, '-p', $node->port, '--checkpoint=fast'],
        'pg_basebackup_tde succeeds');
}

is($node->safe_psql('ownerdb', 'SELECT count(*) FROM mine.calls'), '0',
   'the function of the same name in the database owner\'s schema never ran');

my $bundle = "$backup_dir/pg_vault_tde_keys.ownerdb.sealed";
ok(-f $bundle, 'a bundle was written for ownerdb');
my $head = '';
if (open(my $fh, '<:raw', $bundle))
{
    read($fh, $head, 7);
    close($fh);
}
is($head, 'TDESEAL', '... and it is the extension\'s own sealed bundle');

$node->stop;
