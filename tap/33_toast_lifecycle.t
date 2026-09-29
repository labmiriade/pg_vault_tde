# tap/33_toast_lifecycle.t — out-of-line values go through every write path
# exactly as on a plain heap table
#
# The TAM does its own TOAST bookkeeping: it toasts before encrypting, deletes
# replaced values itself, and rewrites relations in its own copy_for_cluster.
# Each of those has disagreed with core at some point, and every time the
# symptom was either a value that could no longer be read or chunks nothing
# referenced any more:
#
#   PSQLE-189  rotate_online() left the chunks under the retired DEK
#   PSQLE-191  UPDATE from out-of-line to compressed inline deleted twice
#   PSQLE-192  DELETE left the chunks of dropped columns behind; VACUUM FULL
#              kept dropped columns' pointers into the TOAST relation it
#              replaced, so reading the whole row failed, and after the 189
#              fix so did the next rotation
#
# So the oracle is a plain heap twin with the same columns and the same data,
# put through the same statements.  After every step three things must match:
# the visible contents, a read of every whole row (which detoasts dropped
# columns too), and the number of out-of-line values each TOAST relation still
# holds — fewer is a loss, more is a leak.  A rotation has no heap
# equivalent; the twin gets an UPDATE of every row, which is what the
# rotation performs.  Concurrency is test/isolation/specs/toast_update_concurrency.spec.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('toast_lifecycle');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");

# Out-of-line values a TOAST relation holds, live rows or not.
$node->safe_psql('postgres', q{
    CREATE FUNCTION toast_values(regclass) RETURNS bigint LANGUAGE plpgsql AS $$
    DECLARE n bigint;
    BEGIN
        EXECUTE format('SELECT count(DISTINCT chunk_id) FROM %s',
                       (SELECT reltoastrelid::regclass FROM pg_class WHERE oid = $1))
        INTO n;
        RETURN n;
    END $$;
});

# Runs $sql on both tables: every %t becomes the table name.
sub both
{
    my ($sql, $what) = @_;
    for my $t (qw(enc twin))
    {
        (my $s = $sql) =~ s/%t/$t/g;
        my ($rc, $out, $err) = $node->psql('postgres', $s);
        is($rc, 0, "$t: $what") or diag $err;
    }
}

# Three assertions: contents, whole rows, out-of-line values.
sub check
{
    my ($when) = @_;
    my ($rc, $out, $err) = $node->psql('postgres', q{
        SELECT count(*) FROM (
            (SELECT * FROM enc EXCEPT ALL SELECT * FROM twin)
            UNION ALL
            (SELECT * FROM twin EXCEPT ALL SELECT * FROM enc)) d});
    is($out, '0', "$when: contents equal the heap twin") or diag $err;

    my $twin = $node->safe_psql('postgres',
        'SELECT coalesce(sum(length(t::text)), 0) FROM twin t');
    ($rc, $out, $err) = $node->psql('postgres',
        'SELECT coalesce(sum(length(t::text)), 0) FROM enc t');
    is($out, $twin, "$when: every whole row reads as on the heap twin") or diag $err;

    $twin = $node->safe_psql('postgres', "SELECT toast_values('twin')");
    ($rc, $out, $err) = $node->psql('postgres', "SELECT toast_values('enc')");
    is($out, $twin, "$when: the TOAST relation holds $twin values, as on the heap twin")
      or diag $err;
}

sub rotate
{
    my ($label) = @_;
    $node->safe_psql('postgres',
        "DELETE FROM pg_vault_tde_rotation_progress WHERE relid = 'enc'::regclass::oid");
    $node->safe_psql('postgres',
        "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('enc')");
    $node->poll_query_until('postgres', q{
        SELECT status IN ('complete', 'failed')
        FROM pg_vault_tde_rotation_progress WHERE relid = 'enc'::regclass::oid})
      or die "$label never finished";
    is($node->safe_psql('postgres',
           "SELECT status FROM pg_vault_tde_rotation_progress "
         . "WHERE relid = 'enc'::regclass::oid"), 'complete', "enc: $label completes");
    my ($rc, $out, $err) = $node->psql('postgres', 'UPDATE twin SET id = id');
    is($rc, 0, "twin: every row updated in place of $label") or diag $err;
}

# 40 rows.  ext and gone1/gone2 are stored out of line uncompressed, cmp
# compressed; each column is short or NULL on some rows, so some rows keep an
# out-of-line value only in a column that is about to be dropped.
$node->safe_psql('postgres', q{
    CREATE TABLE enc (id int, flag int, ext text, cmp text, gone1 text, gone2 text)
        USING encrypted_heap;
    CREATE TABLE twin (LIKE enc) USING heap;
});
both(q{
    ALTER TABLE %t ALTER COLUMN ext SET STORAGE EXTERNAL;
    ALTER TABLE %t ALTER COLUMN gone1 SET STORAGE EXTERNAL;
    ALTER TABLE %t ALTER COLUMN gone2 SET STORAGE EXTERNAL;
    INSERT INTO %t
    SELECT g, 0,
           CASE WHEN g % 4 = 0 THEN NULL
                WHEN g % 4 = 1 THEN 'short_' || g
                ELSE repeat(md5(g::text), 400) END,
           CASE WHEN g % 3 = 0 THEN 'short_' || g
                ELSE (SELECT string_agg(md5((g * 1000 + i)::text) || repeat('-', 32), '')
                      FROM generate_series(1, 400) i) END,
           CASE WHEN g % 2 = 0 THEN repeat(md5((-g)::text), 400) END,
           CASE WHEN g % 5 = 0 THEN repeat(md5((g + 100)::text), 400) END
    FROM generate_series(1, 40) g;
    ALTER TABLE %t DROP COLUMN gone1;
}, 'created, filled, one column dropped');
check('after DROP COLUMN');

both('UPDATE %t SET flag = 1 WHERE id <= 10', 'UPDATE that keeps every value');
check('after an UPDATE that keeps every value');

both(q{UPDATE %t SET ext = repeat(md5((id * 7)::text), 400) WHERE id BETWEEN 11 AND 16},
     'UPDATE to a new out-of-line value');
check('after an UPDATE to a new out-of-line value');

both(q{UPDATE %t SET cmp = repeat('x', 6000) WHERE id BETWEEN 17 AND 22},
     'UPDATE from out of line to compressed inline');
check('after an UPDATE from out of line to compressed inline');

both(q{UPDATE %t SET ext = NULL, cmp = 'short' WHERE id BETWEEN 23 AND 26},
     'UPDATE from out of line to NULL and short');
check('after an UPDATE from out of line to NULL and short');

# 29: only cmp out of line; 30: everything but cmp; 33: nothing out of line;
# 36: only the dropped gone1.
both('DELETE FROM %t WHERE id IN (29, 30, 33, 36)', 'DELETE');
both('VACUUM %t', 'VACUUM');
check('after DELETE and VACUUM');

# Rows 20 and 25 now keep an out-of-line value only in the dropped gone2.
both('ALTER TABLE %t DROP COLUMN gone2', 'second column dropped');
both('VACUUM FULL %t', 'VACUUM FULL');
check('after VACUUM FULL');

rotate('rotation #1');
check('after rotation #1');

$node->restart;
$node->psql('postgres', "SELECT pg_vault_tde_wallet_unlock('test-password')");
check('after a restart');

rotate('rotation #2');
both('VACUUM FULL %t', 'second VACUUM FULL');
check('after rotation #2 and a second VACUUM FULL');

both('DELETE FROM %t', 'DELETE of every row');
both('VACUUM %t', 'VACUUM');
check('after deleting every row');

$node->stop;
done_testing();
