# tap/27_preload_providers.t — the startup warm-up against Vault and PKCS#11
#
# tap/26 covers the preload with the local wallet.  The question this answers
# is whether it also works when the KEK lives outside the server: in Vault or
# OpenBao, or on a PKCS#11 token.
#
# There is no reason in the design why it should not — the worker calls
# pg_vault_tde_kms_get_rel_dek(), which goes through the provider vtable like
# any backend — but each provider needs its credential without a human, and
# that is provider-specific:
#
#   vault    a token from pg_vault_tde.vault_token, or an AppRole/Kubernetes
#            login; backends share one token through the shmem cache
#   pkcs11   a user PIN read with getenv() from the variable named by
#            pg_vault_tde.pkcs11_pin_env, which a background worker inherits
#            from the postmaster like any other process
#   local    a passphrase from wallet_passphrase_command/_env (tap/26)
#
# Each half skips when its backend is not available, so this runs as far as
# the environment allows.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use File::Temp qw(tempdir);

my $vault_addr = $ENV{VAULT_ADDR};
my ($module) = grep { $_ && -e $_ } (
    $ENV{SOFTHSM2_MODULE} // (),
    '/usr/lib/softhsm/libsofthsm2.so',
    '/usr/lib64/pkcs11/libsofthsm2.so',
    '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so');

plan skip_all => 'neither VAULT_ADDR nor SoftHSM2 available'
    unless $vault_addr || $module;

plan tests => ($vault_addr ? 3 : 0) + ($module ? 3 : 0);

# Create NREL tables, restart, and return the log written after the restart.
sub preload_and_capture
{
    my ($node, $nrel) = @_;

    $node->safe_psql('postgres',
        'ALTER DATABASE postgres SET pg_vault_tde.preload_keys = on');
    $node->safe_psql('postgres', qq{
        DO \$\$
        BEGIN
            FOR i IN 1..$nrel LOOP
                EXECUTE format(
                    'CREATE TABLE p%s (id int, val text) USING encrypted_heap', i);
                EXECUTE format('INSERT INTO p%s VALUES (%s, %L)',
                               i, i, 'payload_' || i);
            END LOOP;
        END \$\$;
    });

    # Search only past here: the launcher already ran at first startup, and
    # its "finished" line would otherwise match before the run under test.
    my $logstart = -s $node->logfile;
    $node->restart;
    $node->wait_for_log(qr/DEK preload finished/, $logstart);

    return PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
}

# ── Vault / OpenBao ────────────────────────────────────────────────────────
SKIP:
{
    skip 'VAULT_ADDR not set', 3 unless $vault_addr;

    my $node = PostgreSQL::Test::Cluster->new('preload_vault_node');
    $node->init;
    $node->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'vault'\n" .
        "pg_vault_tde.dev_mode = on\n" .
        "pg_vault_tde.vault_url = '$vault_addr'\n" .
        "pg_vault_tde.vault_token = 'test-token'\n" .
        "pg_vault_tde.vault_transit_mount = 'transit'\n" .
        "pg_vault_tde.vault_key_name = 'pg-tde-dek'\n");
    $node->start;
    $node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');

    my $log = preload_and_capture($node, 5);

    like($log, qr/preloaded 5 DEK\(s\) for database \d+/,
         'vault: all five DEKs unwrapped by the preload worker')
        or diag "log tail:\n" . substr($log, -1500);

    unlike($log, qr/preload stopped/,
           'vault: the pass ran to the end of the catalog');

    is($node->safe_psql('postgres', 'SELECT val FROM p3 WHERE id = 3'),
       'payload_3', 'vault: data reads back after the warm-up');

    $node->stop;
}

# ── PKCS#11 / HSM ──────────────────────────────────────────────────────────
SKIP:
{
    skip 'SoftHSM2 not installed', 3 unless $module;

    my $hsmdir = tempdir(CLEANUP => 1);
    mkdir "$hsmdir/tokens" or die "mkdir $hsmdir/tokens: $!";
    open my $cf, '>', "$hsmdir/softhsm2.conf" or die $!;
    print $cf "directories.tokendir = $hsmdir/tokens\n";
    print $cf "objectstore.backend = file\n";
    close $cf;

    # The postmaster must inherit both: the preload worker reads the PIN with
    # getenv(), which is exactly what makes it usable without a human.
    $ENV{SOFTHSM2_CONF}     = "$hsmdir/softhsm2.conf";
    $ENV{PG_TDE_PKCS11_PIN} = '1234';

    system('softhsm2-util', '--init-token', '--free',
           '--label', 'pgtde-preload',
           '--so-pin', '12345', '--pin', '1234') == 0
        or die 'softhsm2-util --init-token failed';

    my $node = PostgreSQL::Test::Cluster->new('preload_pkcs11_node');
    $node->init;
    $node->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'pkcs11'\n" .
        "pg_vault_tde.pkcs11_library = '$module'\n" .
        "pg_vault_tde.pkcs11_token_label = 'pgtde-preload'\n");
    $node->start;
    $node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    $node->safe_psql('postgres', 'SELECT pg_vault_tde_pkcs11_keygen();');

    my $log = preload_and_capture($node, 5);

    like($log, qr/preloaded 5 DEK\(s\) for database \d+/,
         'pkcs11: all five DEKs unwrapped by the preload worker')
        or diag "log tail:\n" . substr($log, -1500);

    unlike($log, qr/preload stopped/,
           'pkcs11: the pass ran to the end of the catalog');

    is($node->safe_psql('postgres', 'SELECT val FROM p3 WHERE id = 3'),
       'payload_3', 'pkcs11: data reads back after the warm-up');

    $node->stop;
}
