# tap/53_toast_encryption_off.t — toast_encryption = off never leaves TOAST
# unreadable
#
# The TOAST pipeline encrypts every chunk it writes (pg_vault_tde_toast_save_datum)
# whatever the TOAST relation's access method; the read side decrypts only when
# that relation is encrypted_heap.  pg_vault_tde.toast_encryption = off made
# pg_vault_tde_toast_am() return heap: a table created — or rewritten by VACUUM
# FULL, CLUSTER, SET ACCESS METHOD — with the setting off got a heap TOAST
# relation holding encrypted chunks, read back undecrypted, so every out-of-line
# value failed ("unexpected chunk number ...") (PSQLE-223).  The setting never
# produced the plaintext TOAST the documentation promised.
#
# The TOAST relation of an encrypted_heap table must always be encrypted_heap,
# and setting the parameter off must say that it no longer has an effect.
#
# A table left in that state by 1.7.1 has a heap TOAST relation of chunks
# encrypted with its key: the README's repair gives the TOAST relation the
# encrypted_heap access method.  The last part builds that state and runs the
# procedure as the README writes it.
use strict;
use warnings;
use Test::More tests => 13;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('toast_off');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

my $toast_am = q{SELECT a.amname FROM pg_class c
                 JOIN pg_class t ON t.oid = c.reltoastrelid
                 JOIN pg_am a ON a.oid = t.relam
                 WHERE c.oid = 't'::regclass};
my $intact = q{SELECT big = repeat('SEKRET_TOAST_', 2000) FROM t WHERE id = 1};

# ── A table created with the setting off ──────────────────────────────────
my ($rc, undef, $err) = $node->psql('postgres', q{
    SET pg_vault_tde.toast_encryption = off;
    CREATE TABLE t (id int, big text) USING encrypted_heap;
    ALTER TABLE t ALTER COLUMN big SET STORAGE EXTERNAL;
    INSERT INTO t VALUES (1, repeat('SEKRET_TOAST_', 2000));
});
is($rc, 0, 'a table can be created and written with toast_encryption = off');
like($err, qr/toast_encryption.*no effect/i,
    '... and a WARNING says the setting no longer has an effect');
is($node->safe_psql('postgres', $toast_am), 'encrypted_heap',
    '... its TOAST relation is encrypted_heap all the same');
is($node->safe_psql('postgres', $intact), 't',
    '... and the out-of-line value reads back intact');

$node->safe_psql('postgres', 'CHECKPOINT;');
is($node->safe_psql('postgres', q{
    SELECT position('SEKRET_TOAST_'::bytea in pg_read_binary_file(pg_relation_filepath(
        (SELECT reltoastrelid FROM pg_class WHERE oid = 't'::regclass)))) > 0}),
   'f', '... and is not in plaintext in the TOAST file');

# ── A rewrite with the setting off ────────────────────────────────────────
$node->psql('postgres', q{
    SET pg_vault_tde.toast_encryption = off;
    VACUUM FULL t;
});
is($node->safe_psql('postgres', $toast_am), 'encrypted_heap',
    'VACUUM FULL with the setting off keeps an encrypted_heap TOAST relation');
is($node->safe_psql('postgres', $intact), 't',
    '... and the value still reads back');

# ── The README repair of a table left unreadable by 1.7.1 ─────────────────
# The state 1.7.1 left: an encrypted_heap table whose TOAST relation is heap
# and holds chunks encrypted with the table's key.
$node->safe_psql('postgres', q{
    CREATE TABLE hurt (id int, big text) USING encrypted_heap;
    ALTER TABLE hurt ALTER COLUMN big SET STORAGE EXTERNAL;
    INSERT INTO hurt VALUES (1, repeat('SEKRET_TOAST_', 2000)), (2, 'short');
    UPDATE pg_class SET relam = (SELECT oid FROM pg_am WHERE amname = 'heap')
    WHERE  oid = (SELECT reltoastrelid FROM pg_class WHERE oid = 'hurt'::regclass);
});
# sum(length(...)) makes the executor read every value of every row; a
# count(*) over the same subquery would let the planner drop t::text.
my $read_all = 'SELECT sum(length(t::text)) > 0 FROM hurt t';

my ($rrc, undef, $rerr) = $node->psql('postgres', $read_all);
isnt($rrc, 0, 'an affected table cannot read its out-of-line values');
like($rerr, qr/unexpected chunk number/, '... with the error the README names');

# Step 1 of the README, verbatim.
is($node->safe_psql('postgres', q{
    SELECT c.oid::regclass AS table_name
    FROM   pg_class c
    JOIN   pg_am    ca ON ca.oid = c.relam
    JOIN   pg_class t  ON t.oid  = c.reltoastrelid
    JOIN   pg_am    ta ON ta.oid = t.relam
    WHERE  ca.amname = 'encrypted_heap' AND ta.amname <> 'encrypted_heap';}),
   'hurt', 'step 1 finds exactly the affected table');

# Step 3.
my $toast = $node->safe_psql('postgres',
    "SELECT reltoastrelid::regclass FROM pg_class WHERE oid = 'hurt'::regclass");
$node->safe_psql('postgres', qq{
    UPDATE pg_class
    SET    relam = (SELECT oid FROM pg_am WHERE amname = 'encrypted_heap')
    WHERE  oid = '$toast'::regclass;});

# Step 4.
is($node->safe_psql('postgres', $read_all), 't',
   'after step 3 every value of every row reads back');
is($node->safe_psql('postgres',
       q{SELECT big = repeat('SEKRET_TOAST_', 2000) FROM hurt WHERE id = 1}), 't',
   '... the out-of-line value intact');
is($node->safe_psql('postgres',
       q{SELECT failed_tuples FROM pg_vault_tde_verify_integrity('hurt')}), '0',
   '... and verify_integrity() reports no failed tuple');

$node->stop;
