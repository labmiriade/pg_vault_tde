# tap/49_hot_update_short_indexed.t — an UPDATE that changes a short indexed
# value always reaches the index
#
# heap_update() decides HOT — and with it whether the executor inserts index
# entries at all — by comparing the indexed attributes of the old and the new
# tuple byte by byte, as they lie on disk.  Since the v5 layout (PSQLE-165)
# those bytes are ciphertext at each value's own offset, under a fresh IV per
# row version: a changed value of L bytes encrypts to the old ciphertext with
# probability 256^-L.  For a 1-byte value that is one UPDATE in 256: it goes
# HOT, the index keeps the old key only, a lookup of the new value misses the
# row, one of the old value returns it, and UNIQUE lets a duplicate in
# (PSQLE-219).  1.7.1 never took a HOT update here.
#
# Each table holds one row whose indexed value alternates between two 1-byte
# values, one UPDATE per transaction so that pruning keeps room on the page
# for a HOT update.  After every UPDATE: the transaction took no HOT update, an
# index scan finds the row by its new value and not by the old one, and a
# second row with the new value is refused.  4000 UPDATEs per table: on the
# unfixed code the chance that none of them collides is (255/256)^4000, 2e-7.
# A plain heap twin, whose UPDATEs leave the indexed value alone, shows the
# churn does leave room for HOT.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

plan tests => 9;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('hot_short');
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
    SET client_min_messages = error;
    CREATE TABLE et (id int, c text) USING encrypted_heap;
    CREATE UNIQUE INDEX et_c ON et USING tde_btree (c);
    INSERT INTO et VALUES (1, 'a');

    CREATE TABLE eb (id int, b bool) USING encrypted_heap;
    CREATE UNIQUE INDEX eb_b ON eb USING btree (b);
    INSERT INTO eb VALUES (1, false);

    CREATE TABLE ph (id int, c text) USING heap;
    CREATE UNIQUE INDEX ph_c ON ph USING btree (c);
    INSERT INTO ph VALUES (1, 'a');

    -- n UPDATEs of tbl.col, alternating v2, v1, v2, ...; one per transaction.
    CREATE PROCEDURE churn(tbl regclass, col text, v1 text, v2 text, n int,
                           INOUT hot int DEFAULT 0, INOUT missed int DEFAULT 0,
                           INOUT stale int DEFAULT 0, INOUT dup int DEFAULT 0)
    LANGUAGE plpgsql AS $$
    DECLARE
        newv text;
        oldv text;
        k    int;
        h0   int;
    BEGIN
        FOR i IN 1 .. n LOOP
            IF i % 2 = 1 THEN newv := v2; oldv := v1;
                         ELSE newv := v1; oldv := v2; END IF;

            -- A backend's counters add up until it next reports them.
            h0 := pg_stat_get_xact_tuples_hot_updated(tbl);
            EXECUTE format('UPDATE %s SET %I = %L', tbl, col, newv);
            hot := hot + pg_stat_get_xact_tuples_hot_updated(tbl) - h0;

            EXECUTE format('SELECT count(*) FROM %s WHERE %I = %L', tbl, col, newv) INTO k;
            IF k <> 1 THEN missed := missed + 1; END IF;
            EXECUTE format('SELECT count(*) FROM %s WHERE %I = %L', tbl, col, oldv) INTO k;
            IF k <> 0 AND v1 <> v2 THEN stale := stale + 1; END IF;

            BEGIN
                EXECUTE format('INSERT INTO %s (id, %I) VALUES (2, %L)', tbl, col, newv);
                dup := dup + 1;
                EXECUTE format('DELETE FROM %s WHERE id = 2', tbl);
            EXCEPTION WHEN unique_violation THEN
                NULL;
            END;

            COMMIT;
        END LOOP;
    END $$;
});

my $force_index = 'SET enable_seqscan = off; SET enable_bitmapscan = off; '
               . 'SET enable_indexonlyscan = off;';

for my $case (['et', 'c', 'a', 'b', 'tde_btree on a 1-character text'],
              ['eb', 'b', 'false', 'true', 'btree on a bool'])
{
    my ($t, $col, $v1, $v2, $label) = @$case;
    my ($hot, $missed, $stale, $dup) = split /\|/,
        $node->safe_psql('postgres', "$force_index CALL churn('$t', '$col', '$v1', '$v2', 4000)");

    is($hot, 0, "$label: no UPDATE that changed the value went HOT");
    is($missed, 0, "$label: after every UPDATE the index finds the row by its new value");
    is($stale, 0, "$label: ... and no longer by its old one");
    is($dup, 0, "$label: ... and UNIQUE refuses a second row with the new value");
}

my ($hot) = split /\|/,
    $node->safe_psql('postgres', "$force_index CALL churn('ph', 'c', 'a', 'a', 200)");
cmp_ok($hot, '>', 0, 'heap twin: the same churn leaves room for HOT updates');

$node->stop;
