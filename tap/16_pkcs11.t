# tap/16_pkcs11.t - TAP test for the pkcs11 KMS provider (SoftHSM2)
#
# Provisions a throwaway SoftHSM2 token in a tempdir (no root needed),
# then exercises the full pkcs11 provider lifecycle: KEK provisioning via
# pg_vault_tde_pkcs11_keygen(), encrypted-table round-trip, on-disk
# ciphertext, restart (fresh-backend lazy C_Initialize — the fork-safety
# path), health check, KEK rotation, and clean failures with a wrong
# token label, a wrong PIN, an unprovisioned key label, and an invalid
# pkcs11_library path.  Also covers pkcs11_slot_id as an alternative to
# pkcs11_token_label, and the shared-memory KEK-version beacon that lets an
# already-connected backend pick up a rotation committed by a different
# connection without reconnecting (PSQLE-20).
#
# Skips entirely when SoftHSM2 is not installed (softhsm2-util + module).
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use File::Temp qw(tempdir);

# --- Locate SoftHSM2; skip if not installed -------------------------------
my @candidates = (
    $ENV{SOFTHSM2_MODULE} // (),
    '/usr/lib/softhsm/libsofthsm2.so',
    glob('/usr/lib/*/softhsm/libsofthsm2.so'),
    '/usr/local/lib/softhsm/libsofthsm2.so',
);
my ($module) = grep { defined && -f } @candidates;

if (!defined $module
    || system('softhsm2-util --version >/dev/null 2>&1') != 0)
{
    plan skip_all => 'SoftHSM2 not installed (softhsm2-util / libsofthsm2.so)';
}

plan tests => 19;

# --- Provision a throwaway token (no root needed) -------------------------
my $hsmdir = tempdir(CLEANUP => 1);
mkdir "$hsmdir/tokens" or die "mkdir $hsmdir/tokens: $!";
open my $cf, '>', "$hsmdir/softhsm2.conf" or die $!;
print $cf "directories.tokendir = $hsmdir/tokens\n";
print $cf "objectstore.backend = file\n";
close $cf;

# Both softhsm2-util and every postmaster/backend must see these.
$ENV{SOFTHSM2_CONF}     = "$hsmdir/softhsm2.conf";
$ENV{PG_TDE_PKCS11_PIN} = '1234';

system('softhsm2-util', '--init-token', '--free',
       '--label', 'pgtde-test',
       '--so-pin', '12345', '--pin', '1234') == 0
    or die 'softhsm2-util --init-token failed';

# --- Node with the pkcs11 provider -----------------------------------------
my $node = PostgreSQL::Test::Cluster->new('pkcs11_test_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'pkcs11'\n" .
    "pg_vault_tde.pkcs11_library = '$module'\n" .
    "pg_vault_tde.pkcs11_token_label = 'pgtde-test'\n");
$node->start;

# 1. Extension loads
ok($node->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0,
   'CREATE EXTENSION succeeds');

# 2. One-time KEK provisioning on the token
ok($node->psql('postgres', 'SELECT pg_vault_tde_pkcs11_keygen();') == 0,
   'pg_vault_tde_pkcs11_keygen() creates the KEK');

# 3. A second keygen must refuse to overwrite the KEK
my ($ret, $out, $err) =
    $node->psql('postgres', 'SELECT pg_vault_tde_pkcs11_keygen();');
like($err, qr/already exists/,
     'second keygen fails with "already exists"');

# 4. Encrypted-table round-trip
my $sentinel = 'pkcs11_top_secret_payload';
$node->safe_psql('postgres',
    'CREATE TABLE secret_pkcs11 (id serial, payload text) USING encrypted_heap;');
$node->safe_psql('postgres',
    "INSERT INTO secret_pkcs11 (payload) VALUES ('$sentinel');");
is($node->safe_psql('postgres',
        'SELECT payload FROM secret_pkcs11 WHERE id = 1;'),
   $sentinel, 'round-trip through encrypted_heap');

# 5. No plaintext on disk
$node->safe_psql('postgres', 'CHECKPOINT;');
my $relpath = $node->safe_psql('postgres',
    "SELECT pg_relation_filepath('secret_pkcs11');");
my $heap = PostgreSQL::Test::Utils::slurp_file(
    $node->data_dir . '/' . $relpath);
unlike($heap, qr/\Q$sentinel\E/, 'heap file does not contain the sentinel');

# 6. Fresh backends after restart re-attach lazily (fork-safety path):
#    dlopen + C_Initialize + login + KEK lookup all happen again from scratch.
$node->restart;
is($node->safe_psql('postgres',
        'SELECT payload FROM secret_pkcs11 WHERE id = 1;'),
   $sentinel, 'decryption works in a fresh backend after restart');

# 7. Health check reports the pkcs11 provider
like($node->safe_psql('postgres',
        'SELECT kms_provider FROM pg_vault_tde_health_check();'),
     qr/pkcs11/, 'health_check reports kms_provider=pkcs11');

# 8. KEK rotation end-to-end (prepare -> rewrap_all -> commit on the token)
ok($node->psql('postgres', 'SELECT pg_vault_tde_rotate_kek();') == 0,
   'pg_vault_tde_rotate_kek() succeeds');

# 9. Data still readable after rotation + restart (DEKs rewrapped under the
#    new KEK version; the old version stays on the token forever, immutable,
#    under "<label>.v<N>")
$node->restart;
is($node->safe_psql('postgres',
        'SELECT payload FROM secret_pkcs11 WHERE id = 1;'),
   $sentinel, 'decryption works after KEK rotation and restart');

$node->stop;

# 10. Wrong token label fails cleanly (no crash, clean SQL error)
my $node2 = PostgreSQL::Test::Cluster->new('pkcs11_bad_label_node');
$node2->init;
$node2->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'pkcs11'\n" .
    "pg_vault_tde.pkcs11_library = '$module'\n" .
    "pg_vault_tde.pkcs11_token_label = 'no-such-token'\n");
$node2->start;
$node2->psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
ok($node2->psql('postgres',
        'CREATE TABLE t_fail (id int) USING encrypted_heap;') != 0,
   'encrypted table creation fails cleanly with a wrong token label');
$node2->stop;

# 11. Wrong PIN fails cleanly (no crash, clean SQL error)
{
    local $ENV{PG_TDE_PKCS11_PIN} = 'wrong-pin';
    my $node3 = PostgreSQL::Test::Cluster->new('pkcs11_bad_pin_node');
    $node3->init;
    $node3->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'pkcs11'\n" .
        "pg_vault_tde.pkcs11_library = '$module'\n" .
        "pg_vault_tde.pkcs11_token_label = 'pgtde-test'\n");
    $node3->start;
    $node3->psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    ok($node3->psql('postgres',
            'CREATE TABLE t_fail (id int) USING encrypted_heap;') != 0,
       'encrypted table creation fails cleanly with a wrong PIN');
    $node3->stop;
}

# 12. Unprovisioned key label fails cleanly (correct token/PIN, but no KEK
#     exists yet under this label — pkcs11_find_current_version finds nothing)
{
    my $node4 = PostgreSQL::Test::Cluster->new('pkcs11_bad_keylabel_node');
    $node4->init;
    $node4->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'pkcs11'\n" .
        "pg_vault_tde.pkcs11_library = '$module'\n" .
        "pg_vault_tde.pkcs11_token_label = 'pgtde-test'\n" .
        "pg_vault_tde.pkcs11_key_label = 'no_such_kek'\n");
    $node4->start;
    $node4->psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    ok($node4->psql('postgres',
            'CREATE TABLE t_fail (id int) USING encrypted_heap;') != 0,
       'encrypted table creation fails cleanly with an unprovisioned key label');
    $node4->stop;
}

# 13. Invalid pkcs11_library path: CREATE EXTENSION still succeeds (init()
#     only WARNs — degraded-mode semantics, same as the local wallet
#     provider), but any operation that needs the HSM fails cleanly.
{
    my $node5 = PostgreSQL::Test::Cluster->new('pkcs11_bad_library_node');
    $node5->init;
    $node5->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'pkcs11'\n" .
        "pg_vault_tde.pkcs11_library = '/no/such/pkcs11-module.so'\n" .
        "pg_vault_tde.pkcs11_token_label = 'pgtde-test'\n");
    $node5->start;
    ok($node5->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0,
       'CREATE EXTENSION still succeeds with an invalid pkcs11_library path');
    ok($node5->psql('postgres',
            'CREATE TABLE t_fail (id int) USING encrypted_heap;') != 0,
       'encrypted table creation fails cleanly when pkcs11_library cannot be dlopen-ed');
    $node5->stop;
}

# 14. pkcs11_slot_id selects the token as an alternative to pkcs11_token_label
{
    my $slots_output = `softhsm2-util --show-slots 2>&1`;
    my ($slot_id, $current_slot);
    for my $line (split /\n/, $slots_output)
    {
        $current_slot = $1 if $line =~ /^Slot\s+(\d+)/;
        if (defined $current_slot && $line =~ /Label:\s*pgtde-test\s*$/)
        {
            $slot_id = $current_slot;
            last;
        }
    }

  SKIP:
    {
        skip 'could not determine the SoftHSM2 slot id for token "pgtde-test"', 1
            unless defined $slot_id;

        my $node6 = PostgreSQL::Test::Cluster->new('pkcs11_slotid_node');
        $node6->init;
        $node6->append_conf('postgresql.conf',
            "shared_preload_libraries = 'pg_vault_tde'\n" .
            "pg_vault_tde.kms_provider = 'pkcs11'\n" .
            "pg_vault_tde.pkcs11_library = '$module'\n" .
            "pg_vault_tde.pkcs11_slot_id = $slot_id\n");
        $node6->start;
        $node6->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
        $node6->safe_psql('postgres',
            "CREATE TABLE t_slotid (id int, payload text) USING encrypted_heap;");
        $node6->safe_psql('postgres',
            "INSERT INTO t_slotid VALUES (1, 'slot_id_ok');");
        is($node6->safe_psql('postgres',
                'SELECT payload FROM t_slotid WHERE id = 1;'),
           'slot_id_ok',
           'pkcs11_slot_id resolves the token correctly with no token_label set');
        $node6->stop;
    }
}

# 15. Cross-backend KEK rotation propagation (PSQLE-20): an already-connected
#     backend that never reconnects must pick up a rotation committed by a
#     DIFFERENT connection, and wrap new data under the new KEK version —
#     not stay pinned to the pre-rotation KEK indefinitely.
{
    my $node7 = PostgreSQL::Test::Cluster->new('pkcs11_propagation_node');
    $node7->init;
    $node7->append_conf('postgresql.conf',
        "shared_preload_libraries = 'pg_vault_tde'\n" .
        "pg_vault_tde.kms_provider = 'pkcs11'\n" .
        "pg_vault_tde.pkcs11_library = '$module'\n" .
        "pg_vault_tde.pkcs11_token_label = 'pgtde-test'\n" .
        "pg_vault_tde.pkcs11_key_label = 'pgtde_propagation_kek'\n");
    $node7->start;
    $node7->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
    $node7->safe_psql('postgres', 'SELECT pg_vault_tde_pkcs11_keygen();');

    # A long-lived session: creating its first encrypted_heap table resolves
    # and caches KEK v1 in THIS backend's per-process Pkcs11State.
    my $long_lived = $node7->background_psql('postgres');
    $long_lived->query_safe(
        'CREATE TABLE prop_before (id int, payload text) USING encrypted_heap;');
    $long_lived->query_safe(
        q{INSERT INTO prop_before VALUES (1, 'before_rotation');});

    # A SEPARATE, short-lived connection rotates the KEK to v2 and disconnects.
    # The long-lived session above is never touched or reconnected.
    ok($node7->psql('postgres', 'SELECT pg_vault_tde_rotate_kek();') == 0,
       'pg_vault_tde_rotate_kek() succeeds from a different connection');

    # Back on the SAME long-lived session: a brand-new encrypted table's DEK
    # gets wrapped under whatever KEK THIS backend currently believes is
    # current.
    $long_lived->query_safe(
        'CREATE TABLE prop_after (id int, payload text) USING encrypted_heap;');
    $long_lived->query_safe(
        q{INSERT INTO prop_after VALUES (1, 'after_rotation');});

    # Extract the 4-byte big-endian KEK version tag prefixed to wrapped_dek
    # (PKCS11_KEK_VERSION_LEN in pg_vault_tde_kms_pkcs11.c) for the new
    # table, read back through the SAME long-lived session.
    my $version = $long_lived->query_safe(
        'SELECT get_byte(wrapped_dek,0)*16777216 + get_byte(wrapped_dek,1)*65536 + ' .
        'get_byte(wrapped_dek,2)*256 + get_byte(wrapped_dek,3) ' .
        q{FROM pg_vault_tde_catalog WHERE relid = 'prop_after'::regclass;});
    chomp $version;
    is($version, '2',
       'a long-lived, never-reconnected backend wraps NEW data under the ' .
       'rotated KEK version (cross-backend propagation works)');

    $long_lived->quit;

    # Sanity: both pre- and post-rotation data still decrypt (old KEK
    # generations are immutable and never destroyed).
    is($node7->safe_psql('postgres', 'SELECT payload FROM prop_before;'),
       'before_rotation', 'pre-rotation data still decrypts after propagation');
    is($node7->safe_psql('postgres', 'SELECT payload FROM prop_after;'),
       'after_rotation', 'post-rotation data decrypts correctly');

    $node7->stop;
}
