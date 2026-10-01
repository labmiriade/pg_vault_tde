# tap/57_toast_rmgr_vm_logging.t — the custom TOAST rmgr logs the visibility
# map buffer it clears
#
# tde_toast_wal_insert() is a clone of heap_insert, used when
# pg_vault_tde.toast_custom_rmgr is on.  PostgreSQL's fix of 2026-07-15
# ("WAL logging of operations that clear bits in tables' visibility maps",
# PG 18.6 and the 17 minor of that day) locks the visibility-map buffer before
# the critical section and registers it in the record; the clone still cleared
# the bit without registering the buffer, so the change was invisible to the
# WAL summarizer — incremental backups — and got no full-page image, leaving a
# torn visibility-map page uncorrected (PSQLE-227).
#
# An insert into an all-visible TOAST page must produce a record under the
# custom rmgr that references two blocks: the heap page and the visibility-map
# page.  A plain heap table is the oracle: core's own record for the same
# situation references two blocks as well.
#
# Skipped when the server was built before that fix: the clone then matches the
# heap_insert it was cloned from, which is what it must do.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $RMGR_ID = 161;

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('rmgr_vm');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n"
  . "pg_vault_tde.toast_custom_rmgr = on\n"
  . "autovacuum = off\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# Does this server carry the core fix?  Its own heap_insert is the reference:
# if core does not register the buffer either, the clone is right as it is.
sub blkrefs_of
{
    my ($start, $end, $rmgr) = @_;
    my ($stdout, $stderr);
    IPC::Run::run [
        'pg_waldump',
        '--path'  => $node->data_dir,
        '--start' => $start,
        '--end'   => $end,
        '--rmgr'  => $rmgr,
      ],
      '>' => \$stdout, '2>' => \$stderr;
    # a record that cleared a visibility-map bit references two blocks
    return scalar grep { /blkref #1:/ } split /^(?=rmgr:)/m, $stdout;
}

# ── The oracle: a plain heap table, logged by core ────────────────────────
$node->safe_psql('postgres', q{
    CREATE TABLE plain_t (id int, v text);
    INSERT INTO plain_t VALUES (1, 'x');
    VACUUM (FREEZE) plain_t;});
my $h_start = $node->safe_psql('postgres', 'SELECT pg_current_wal_lsn()');
$node->safe_psql('postgres', "INSERT INTO plain_t VALUES (2, 'y')");
my $h_end = $node->safe_psql('postgres', 'SELECT pg_current_wal_lsn()');
my $core_logs_vm = blkrefs_of($h_start, $h_end, 'heap');

if (!$core_logs_vm)
{
    plan skip_all =>
      'this PostgreSQL predates the visibility-map WAL logging fix; '
      . 'the clone matches its heap_insert';
}
plan tests => 4;
pass('core registers the visibility-map buffer, so the clone must too');

# ── The encrypted TOAST relation, logged by the custom rmgr ───────────────
$node->safe_psql('postgres', q{
    CREATE TABLE toast_t (id int, big text) USING encrypted_heap;
    ALTER TABLE toast_t ALTER COLUMN big SET STORAGE EXTERNAL;
    -- a TOAST chunk is about 2 kB and four fit on a page: two chunks now
    -- leave room for the next insert on the same, all-visible page.
    INSERT INTO toast_t VALUES (1, repeat('a', 2500));
    VACUUM (FREEZE) toast_t;});

my $allvis = $node->safe_psql('postgres', q{
    SELECT relallvisible > 0 FROM pg_class
    WHERE oid = (SELECT reltoastrelid FROM pg_class WHERE oid = 'toast_t'::regclass)});
is($allvis, 't', 'the TOAST relation has an all-visible page to clear');

my $start = $node->safe_psql('postgres', 'SELECT pg_current_wal_lsn()');
$node->safe_psql('postgres', "INSERT INTO toast_t VALUES (2, repeat('b', 2500))");
my $end = $node->safe_psql('postgres', 'SELECT pg_current_wal_lsn()');

cmp_ok(blkrefs_of($start, $end, sprintf('custom%03d', $RMGR_ID)), '>', 0,
    "a custom$RMGR_ID record registers the visibility-map buffer it cleared");

is($node->safe_psql('postgres',
       q{SELECT big = repeat('b', 2500) FROM toast_t WHERE id = 2}), 't',
   'the out-of-line value still reads back');

$node->stop;
