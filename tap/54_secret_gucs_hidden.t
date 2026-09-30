# tap/54_secret_gucs_hidden.t — the secret settings stay with the superuser
#
# pg_vault_tde.vault_token, vault_role_id, vault_secret_id and
# wallet_dev_mode_passphrase are GUC_SUPERUSER_ONLY, which the documentation
# read as "superuser only".  PostgreSQL shows such settings to every member of
# pg_read_all_settings, and grants that role to pg_monitor: SHOW, current_setting()
# and the setting and reset_val columns of pg_settings returned the values to a
# role that is not a superuser (PSQLE-224).
#
# A role that is not a superuser, pg_monitor member or not, must get a mask from
# SHOW and current_setting() and no pg_settings row; a superuser — the client
# tools read these settings with SHOW — still gets the value; and the server
# keeps using the values it holds.
use strict;
use warnings;
use Test::More tests => 15;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('secret_gucs');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.dev_mode = on\n"
  . "pg_vault_tde.wallet_dev_mode_passphrase = 'canary-devpass'\n"
  . "pg_vault_tde.vault_token = 'canary-token'\n"
  . "pg_vault_tde.vault_role_id = 'canary-role-id'\n"
  . "pg_vault_tde.vault_secret_id = 'canary-secret-id'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', 'CREATE ROLE mon LOGIN IN ROLE pg_monitor;');

my @secrets = qw(vault_token vault_role_id vault_secret_id wallet_dev_mode_passphrase);

# ── A pg_monitor member ───────────────────────────────────────────────────
for my $g (@secrets)
{
    my $show = $node->safe_psql('postgres',
        "SET ROLE mon; SHOW pg_vault_tde.$g;");
    my $cur = $node->safe_psql('postgres',
        "SET ROLE mon; SELECT current_setting('pg_vault_tde.$g');");
    ok($show !~ /canary/ && $cur !~ /canary/,
       "a pg_monitor member reads a mask for $g, not its value");
}
is($node->safe_psql('postgres', q{
    SET ROLE mon;
    SELECT count(*) FROM pg_settings
    WHERE  name IN ('pg_vault_tde.vault_token', 'pg_vault_tde.vault_role_id',
                    'pg_vault_tde.vault_secret_id',
                    'pg_vault_tde.wallet_dev_mode_passphrase');}),
   '0', '... and pg_settings has no row for any of them');
is($node->safe_psql('postgres', q{
    SET ROLE mon;
    SELECT count(*) FROM pg_settings
    WHERE  setting LIKE '%canary%' OR reset_val LIKE '%canary%'
       OR  boot_val LIKE '%canary%';}),
   '0', '... nor any column of any other row that carries a value');

# A role with no grant at all is refused, as before.
$node->safe_psql('postgres', 'CREATE ROLE plain LOGIN;');
my ($rc, undef, $err) = $node->psql('postgres',
    'SET ROLE plain; SHOW pg_vault_tde.vault_token;');
isnt($rc, 0, 'a role outside pg_read_all_settings is still refused');

# ── A superuser, and the server itself ────────────────────────────────────
is($node->safe_psql('postgres', 'SHOW pg_vault_tde.vault_token'), 'canary-token',
   'a superuser reads vault_token with SHOW, as the client tools do');
is($node->safe_psql('postgres', 'SHOW pg_vault_tde.vault_secret_id'), 'canary-secret-id',
   '... and vault_secret_id');
is($node->safe_psql('postgres', "SELECT current_setting('pg_vault_tde.vault_role_id')"),
   'canary-role-id', '... and vault_role_id through current_setting()');
is($node->safe_psql('postgres', 'SHOW pg_vault_tde.wallet_dev_mode_passphrase'),
   'canary-devpass', '... and wallet_dev_mode_passphrase');

# The reader is the current user: a pg_monitor member's SECURITY DEFINER
# function reads the mask even when a superuser runs it.
$node->safe_psql('postgres', q{
    CREATE SCHEMA mon_s AUTHORIZATION mon;
    SET ROLE mon;
    CREATE FUNCTION mon_s.read_token() RETURNS text
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
    AS $$ SELECT current_setting('pg_vault_tde.vault_token') $$;});
unlike($node->safe_psql('postgres', 'SELECT mon_s.read_token()'), qr/canary/,
   "a lesser role's SECURITY DEFINER code run by a superuser reads the mask");

# The server opens the wallet with the dev-mode passphrase it holds.
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('canary-devpass')");
$node->safe_psql('postgres', q{
    CREATE TABLE t (id int, v text) USING encrypted_heap;
    INSERT INTO t VALUES (1, 'kept');});
$node->restart;
is($node->safe_psql('postgres', 'SELECT v FROM t'), 'kept',
   'after a restart the server still opens the wallet with the passphrase it holds');

# An empty secret shows as empty to everyone: whether it is set is not hidden.
$node->safe_psql('postgres', q{ALTER SYSTEM SET pg_vault_tde.vault_token = '';});
$node->reload;
is($node->safe_psql('postgres', 'SET ROLE mon; SHOW pg_vault_tde.vault_token;'), '',
   'an unset secret reads as empty');
is($node->safe_psql('postgres', 'SHOW pg_vault_tde.vault_token'), '',
   '... for a superuser too');

$node->stop;
