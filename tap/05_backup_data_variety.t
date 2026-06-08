# tap/05_backup_data_variety.t - Data type coverage: TOAST, Unicode, bytea, bulk rows, sequences
use strict;
use warnings;
use Test::More tests => 14;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

my $node = PostgreSQL::Test::Cluster->new('data_variety_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n" .
    "pg_vault_tde.kms_provider = 'local'\n" .
    "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

ok($node->psql('postgres', 'CREATE EXTENSION pg_vault_tde;') == 0,
    'CREATE EXTENSION succeeds');

$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# Multi-column table with many data types
$node->safe_psql('postgres', q{
    CREATE TABLE types_table (
        id        serial PRIMARY KEY,
        t_text    text,
        t_int     int,
        t_bool    bool,
        t_numeric numeric(12,4),
        t_ts      timestamptz,
        t_jsonb   jsonb,
        t_bytea   bytea,
        t_uuid    uuid
    ) USING encrypted_heap;

    INSERT INTO types_table
        (t_text, t_int, t_bool, t_numeric, t_ts, t_jsonb, t_bytea, t_uuid)
    VALUES
        ('hello', 42, true, 3.1415, '2025-01-01 00:00:00+00',
         '{"key":"value","n":1}', '\\xDEADBEEF',
         'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11');
});
ok(1, 'Multi-type TDE table created');

# TOAST: 128 KB text value (forces multiple 64 KB encryption blocks in dump AND TOAST in PG)
$node->safe_psql('postgres', q{
    CREATE TABLE toast_table (id serial PRIMARY KEY, big text) USING encrypted_heap;
});
$node->safe_psql('postgres',
    "INSERT INTO toast_table (big) VALUES (repeat('X', 131072));");
ok(1, 'TOAST-sized row inserted (128 KB)');

# NULL values
$node->safe_psql('postgres', q{
    CREATE TABLE nulls_table (id serial PRIMARY KEY, val text) USING encrypted_heap;
    INSERT INTO nulls_table (val) VALUES (NULL), ('not_null'), (NULL);
});

# Empty table (schema only)
$node->safe_psql('postgres', q{
    CREATE TABLE empty_table (id serial PRIMARY KEY, val text) USING encrypted_heap;
});

# Unicode and emoji
$node->safe_psql('postgres', q{
    CREATE TABLE unicode_table (id serial PRIMARY KEY, val text) USING encrypted_heap;
    INSERT INTO unicode_table (val) VALUES
        (E'こんにちは世界'),
        ('emoji: \U0001F511\U0001F5DD'),
        (E'éàüñç');
});

# Bytea with NUL bytes
$node->safe_psql('postgres', q{
    CREATE TABLE bytea_table (id serial PRIMARY KEY, val bytea) USING encrypted_heap;
    INSERT INTO bytea_table (val) VALUES
        ('\\x000102FEFF'),
        ('\\x00'),
        ('\\xDEADBEEFCAFEBABE');
});

# Bulk rows — 1000 rows via generate_series
$node->safe_psql('postgres', q{
    CREATE TABLE bulk_table (id serial PRIMARY KEY, val text) USING encrypted_heap;
    INSERT INTO bulk_table (val) SELECT 'row_' || g FROM generate_series(1,1000) g;
});
ok(1, 'Variety of tables created (NULL, empty, unicode, bytea, 1000 rows)');

my $dump_file = $node->data_dir . '/variety_test.dump';
$node->command_ok(
    ['pg_dump_tde', '-o', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'pg_dump_tde completes without error');

my $dump_content = PostgreSQL::Test::Utils::slurp_file($dump_file);
unlike($dump_content, qr/hello/,          'Dump does not contain text sentinel');
unlike($dump_content, qr/DEADBEEF/i,      'Dump does not contain bytea sentinel');
unlike($dump_content, qr/\x{3053}/,       'Dump does not contain Unicode sentinel');

# Drop all tables before restore
$node->safe_psql('postgres',
    'DROP TABLE types_table, toast_table, nulls_table, empty_table,
                unicode_table, bytea_table, bulk_table;');

$node->command_ok(
    ['pg_restore_tde', '-i', $dump_file, '-U', 'postgres', '-d', 'postgres'],
    'pg_restore_tde completes without error');

# Verify multi-type round-trip
my $r1 = $node->safe_psql('postgres', "SELECT t_text, t_int, t_bool FROM types_table WHERE id = 1;");
like($r1, qr/hello.*42.*t/s, 'Multi-type values restored correctly');

# Verify TOAST round-trip
my $big_len = $node->safe_psql('postgres', 'SELECT length(big) FROM toast_table;');
is($big_len, '131072', 'TOAST large value (128 KB) restored with correct length');

# Verify NULL round-trip
my $null_count = $node->safe_psql('postgres',
    "SELECT count(*) FROM nulls_table WHERE val IS NULL;");
is($null_count, '2', 'NULL values restored correctly');

# Verify empty table schema restored
my $empty_count = $node->safe_psql('postgres', 'SELECT count(*) FROM empty_table;');
is($empty_count, '0', 'Empty table schema restored with 0 rows');

# Verify bulk row count
my $bulk_count = $node->safe_psql('postgres', 'SELECT count(*) FROM bulk_table;');
is($bulk_count, '1000', '1000-row table restored with correct count');

$node->stop;
