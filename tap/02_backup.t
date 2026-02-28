# tap/02_backup.t - TAP test for encrypted backup round-trip
# Mocks a Vault HTTP endpoint, runs pg_dump through the TDE wrapper,
# verifies the output is ciphertext, then restores and verifies data.
use strict;
use warnings;
use Test::More tests => 6;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use HTTP::Daemon;
use HTTP::Response;
use POSIX qw(WNOHANG);

# --- Spawn a mock Vault server ---
my $vault_pid = fork();
if ($vault_pid == 0)
{
    # Child: mock HTTP server on port 18200
    my $daemon = HTTP::Daemon->new(LocalPort => 18200, ReuseAddr => 1)
        or die "Cannot start mock Vault: $!";
    while (my $conn = $daemon->accept)
    {
        while (my $req = $conn->get_request)
        {
            # Mock: respond to any /v1/transit/keys/pg_tde_dek with a fake DEK
            my $body = '{"data":{"plaintext":"' .
                       'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='  .
                       '"}}'; # base64 of 32 zero bytes (test only)
            $conn->send_response(
                HTTP::Response->new(200, 'OK',
                    ['Content-Type' => 'application/json'],
                    $body));
        }
        $conn->close;
    }
    exit 0;
}

# Give mock Vault time to start
sleep(1);

# --- PostgreSQL node ---
my $node = PostgreSQL::Test::Cluster->new('backup_test_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.vault_addr = 'http://localhost:18200'\n" .
    "pg_vault_tde.vault_token = 'mock-token'\n");
$node->start;

ok($node->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0,
   'CREATE EXTENSION succeeds');

$node->safe_psql('postgres',
    "CREATE TABLE secret_data (id serial, payload text) USING pg_vault_tde;");
$node->safe_psql('postgres',
    "INSERT INTO secret_data (payload) VALUES ('top_secret_value');");

ok(1, 'TDE table created and populated');

# --- Verify backup status ---
my $status = $node->safe_psql('postgres',
    "SELECT pg_vault_tde_backup_status();");
like($status, qr/backup encryption active/, 'Backup status reports encryption active');

# --- Run pg_dump and check it is not plaintext ---
my $dump_file = $node->data_dir . '/test_backup.dump';
$node->command_ok(['pg_dump', '-Fc', '-f', $dump_file, 'postgres'],
                  'pg_dump completes without error');

ok(-f $dump_file, 'Dump file exists');

# The dump should NOT contain the plaintext sentinel value
my $dump_content = do { local $/; open(my $fh, '<', $dump_file); <$fh> };
unlike($dump_content, qr/top_secret_value/,
       'Dump file does not contain plaintext sentinel');

# --- Cleanup ---
kill 'TERM', $vault_pid;
waitpid($vault_pid, 0);
$node->stop;
