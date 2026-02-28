# TAP test: verifica caricamento estensione
use strict;
use warnings;
use Test::More tests => 2;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

my $node = PostgreSQL::Test::Cluster->new('tde_node');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_vault_tde'");
$node->start;

ok($node->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0, 'CREATE EXTENSION works');
my $out = $node->safe_psql('postgres', "SELECT extname FROM pg_extension WHERE extname = 'pg_vault_tde';");
like($out, qr/^pg_vault_tde$/, 'Extension is present');
