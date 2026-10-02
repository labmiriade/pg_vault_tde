# tap/37_speculative_abort_toast.t — an INSERT ... ON CONFLICT that loses the
# race must not leave its out-of-line values behind
#
# ON CONFLICT checks the arbiter index first, then inserts the row
# speculatively, and only while inserting its index entries finds out whether
# a concurrent transaction took the key in between.  If one did, the row is
# killed with heap_abort_speculative(), which deletes its TOAST chunks only
# when the on-disk tuple has HEAP_HASEXTERNAL — and encrypted_heap never
# writes that bit.  The chunks stayed, referenced by nothing (PSQLE-197).
#
# The race is made deterministic without injection points, which packaged
# builds do not have: an expression index, created before the unique one so
# that it is filled first, calls a function that blocks on an advisory lock
# when the session has test.block set.  The racing INSERT stops after the
# speculative heap insert and before the unique index; another session then
# inserts the same key and commits; releasing the lock lets the first one
# find the conflict and abort.
#
# Run on encrypted_heap and on a plain heap table, for DO NOTHING and for DO
# UPDATE: the winning row must be there, and the TOAST relation must hold
# exactly one value.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 16;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('spec_abort_toast');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.allow_plaintext_index = on\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
$node->safe_psql('postgres', q{
    CREATE FUNCTION blocker(int) RETURNS int IMMUTABLE LANGUAGE plpgsql AS $$
    BEGIN
        IF current_setting('test.block', true) = 'on' THEN
            PERFORM pg_advisory_lock(42);
            PERFORM pg_advisory_unlock(42);
        END IF;
        RETURN $1;
    END $$;
    CREATE FUNCTION toast_values(regclass) RETURNS bigint LANGUAGE plpgsql AS $$
    DECLARE n bigint;
    BEGIN
        EXECUTE format('SELECT count(DISTINCT chunk_id) FROM %s',
                       (SELECT reltoastrelid::regclass FROM pg_class WHERE oid = $1))
        INTO n;
        RETURN n;
    END $$;
});

# Four assertions.
sub race
{
    my ($am, $action) = @_;
    my $t = ($am eq 'heap' ? 'h' : 'e') . '_' . ($action =~ /UPDATE/ ? 'upd' : 'nothing');
    my $label = "$am, DO $action";

    # The expression index first: it is filled before the unique one.
    $node->safe_psql('postgres', qq{
        SET client_min_messages = error;
        CREATE TABLE $t (k int, big text) USING $am;
        ALTER TABLE $t ALTER COLUMN big SET STORAGE EXTERNAL;
        CREATE INDEX ${t}_block ON $t (blocker(k));
        CREATE UNIQUE INDEX ${t}_k ON $t (k);
    });

    my $holder = $node->background_psql('postgres');
    $holder->query_safe('SELECT pg_advisory_lock(42)');

    my $racer = $node->background_psql('postgres', on_error_stop => 0);
    $racer->query_safe("SET test.block = 'on'");
    $racer->query_until(qr/racer_sent/, qq{
\\echo racer_sent
INSERT INTO $t VALUES (1, repeat(md5('racer'), 400))
    ON CONFLICT (k) DO $action;
});
    ok($node->poll_query_until('postgres', q{
            SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                           WHERE wait_event_type = 'Lock' AND wait_event = 'advisory'
                             AND query LIKE 'INSERT%')}),
       "$label: the racing INSERT waits between its speculative insert and the unique index");

    $node->safe_psql('postgres',
        "INSERT INTO $t VALUES (1, repeat(md5('winner'), 400))");
    $holder->query_safe('SELECT pg_advisory_unlock(42)');
    $holder->quit;

    my $done = eval { $racer->query_safe('SELECT 1'); 1 };
    ok($done, "$label: the racing INSERT completes") or diag $@;
    $racer->quit;

    my $expect = $action =~ /UPDATE/ ? 'racer' : 'winner';
    is($node->safe_psql('postgres', "SELECT count(*) || ':' || (big = repeat(md5('$expect'), 400)) FROM $t GROUP BY big"),
       '1:true', "$label: one row, holding the $expect value");

    $node->safe_psql('postgres', "VACUUM $t");
    is($node->safe_psql('postgres', "SELECT toast_values('$t')"), '1',
       "$label: the TOAST relation holds that one value only");
}

race($_->[0], $_->[1]) for (['heap', 'NOTHING'], ['heap', 'UPDATE SET big = excluded.big'],
                            ['encrypted_heap', 'NOTHING'],
                            ['encrypted_heap', 'UPDATE SET big = excluded.big']);

$node->stop;
