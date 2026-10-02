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
# A second database has the extension in a schema of its own, off its
# search_path: up to 1.7.1 the unqualified call failed there ("function ...
# does not exist") and the whole backup with it.
use strict;
use warnings;
use Test::More tests => 7;
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

# A database with the extension in a schema of its own, off its search_path:
# the tool has to find it there, and the extension has to work with the
# empty search_path the tool now runs it under.
$node->safe_psql('postgres', 'CREATE DATABASE schemadb');
$node->safe_psql('schemadb', q{
    CREATE SCHEMA tde_ext;
    CREATE EXTENSION pg_vault_tde SCHEMA tde_ext;
});
$node->safe_psql('schemadb', "SELECT tde_ext.pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('schemadb', q{
    CREATE TABLE secret (id int, v text) USING encrypted_heap;
    INSERT INTO secret VALUES (1, 'sealed');
    ALTER DATABASE schemadb SET search_path = public;
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

my $bundle2 = "$backup_dir/pg_vault_tde_keys.schemadb.sealed";
ok(-f $bundle2, 'a bundle was written for schemadb, whose extension lives in tde_ext');
my $head2 = '';
if (open(my $fh, '<:raw', $bundle2))
{
    read($fh, $head2, 7);
    close($fh);
}
is($head2, 'TDESEAL', '... and it is a sealed bundle');
is($node->safe_psql('schemadb',
       "SELECT count(*) > 0 FROM tde_ext.pg_vault_tde_catalog"), 't',
   '... of a database that does have keys');

$node->stop;
