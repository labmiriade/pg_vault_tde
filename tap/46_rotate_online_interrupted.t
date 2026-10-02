# tap/46_rotate_online_interrupted.t — a rotate_online() stopped halfway
# through its rewrite leaves the table as it was, and can be run again
#
# The rotation worker commits a 'running' progress row, rewrites every row of
# the table under a new DEK in one transaction — rows, out-of-line values,
# index entries — and commits the new key with it.  Nothing tested what is
# left when that transaction never commits (PSQLE-211): the worker cancelled
# (an ERROR), terminated (a FATAL, which no PG_CATCH sees), or the server
# stopped immediately.
#
# The worker is held halfway: an expression index calls gate(id), which for
# row 500 of 1000 waits on an advisory lock this test holds, and a rotation
# makes an index entry for every row it rewrites.  Then it is interrupted.
# Afterwards, and again after a restart: every tag verifies, the rows, whole
# rows and out-of-line values equal a plain heap twin, amcheck finds every
# row in every btree, and the DEK generation is unchanged.  Then a new
# rotation must complete and leave the table as readable, one generation on.
# Once per KMS provider available.
#
# The progress row: a cancel always ended in the worker's PG_CATCH, which
# records 'failed'.  A terminate (pg_terminate_backend(), a smart or fast
# shutdown) was a FATAL, which no PG_CATCH sees, and left it 'running' for
# good; the worker now takes SIGTERM as a cancel.  After an immediate stop
# nothing can run: the row stays 'running', and the README says how to tell —
# no pg_vault_tde rotation process exists.
use strict;
use warnings;
use Test::More;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use File::Temp qw(tempdir);
END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

my $vault_addr = $ENV{VAULT_ADDR};
my ($module) = grep { $_ && -e $_ } (
    $ENV{SOFTHSM2_MODULE} // (),
    '/usr/lib/softhsm/libsofthsm2.so',
    '/usr/lib64/pkcs11/libsofthsm2.so',
    '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so');

my @providers = ('local');
push @providers, 'vault'  if $vault_addr;
push @providers, 'pkcs11' if $module;
my @how = qw(cancel terminate immediate);
plan tests => scalar(@providers) * scalar(@how) * 25;

my ($node, $p);

sub new_node
{
    my $n = PostgreSQL::Test::Cluster->new("rot_int_$p");
    $n->init;
    my $conf = "shared_preload_libraries = 'pg_vault_tde'\n"
             . "pg_vault_tde.allow_plaintext_index = on\n";
    if ($p eq 'local')
    {
        system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
        $conf .= "pg_vault_tde.kms_provider = 'local'\n"
               . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n";
    }
    elsif ($p eq 'vault')
    {
        $conf .= "pg_vault_tde.kms_provider = 'vault'\n"
               . "pg_vault_tde.dev_mode = on\n"
               . "pg_vault_tde.vault_url = '$vault_addr'\n"
               . "pg_vault_tde.vault_token = 'test-token'\n"
               . "pg_vault_tde.vault_transit_mount = 'transit'\n"
               . "pg_vault_tde.vault_key_name = 'pg-tde-dek'\n";
    }
    else
    {
        my $hsmdir = tempdir(CLEANUP => 1);
        mkdir "$hsmdir/tokens" or die "mkdir $hsmdir/tokens: $!";
        open my $cf, '>', "$hsmdir/softhsm2.conf" or die $!;
        print $cf "directories.tokendir = $hsmdir/tokens\nobjectstore.backend = file\n";
        close $cf;
        $ENV{SOFTHSM2_CONF}     = "$hsmdir/softhsm2.conf";
        $ENV{PG_TDE_PKCS11_PIN} = '1234';
        system('softhsm2-util', '--init-token', '--free', '--label', 'pgtde-int',
               '--so-pin', '12345', '--pin', '1234') == 0
          or die 'softhsm2-util --init-token failed';
        $conf .= "pg_vault_tde.kms_provider = 'pkcs11'\n"
               . "pg_vault_tde.pkcs11_library = '$module'\n"
               . "pg_vault_tde.pkcs11_token_label = 'pgtde-int'\n";
    }
    $n->append_conf('postgresql.conf', $conf);
    $n->start;
    $n->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde; CREATE EXTENSION amcheck;');
    $n->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')") if $p eq 'local';
    $n->safe_psql('postgres', 'SELECT pg_vault_tde_pkcs11_keygen()') if $p eq 'pkcs11';
    $n->safe_psql('postgres', q{
        CREATE FUNCTION gate(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS $$
        BEGIN
            IF $1 = 500 THEN
                PERFORM pg_advisory_lock_shared(42);
                PERFORM pg_advisory_unlock_shared(42);
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
    return $n;
}

sub make_table
{
    my ($t) = @_;
    for my $am (qw(encrypted_heap heap))
    {
        my $n = $am eq 'heap' ? "${t}_twin" : $t;
        $node->safe_psql('postgres', qq{
            SET client_min_messages = error;
            CREATE TABLE $n (id int PRIMARY KEY, s text, big text, gone text) USING $am;
            ALTER TABLE $n ALTER COLUMN big SET STORAGE EXTERNAL;
            ALTER TABLE $n ALTER COLUMN gone SET STORAGE EXTERNAL;
            INSERT INTO $n SELECT g, 's' || g,
                   CASE WHEN g % 4 = 0 THEN repeat(md5(g::text), 400) END,
                   CASE WHEN g % 9 = 0 THEN repeat(md5((-g)::text), 400) END
            FROM generate_series(1, 1000) g;
            ALTER TABLE $n DROP COLUMN gone;
            CREATE INDEX ${n}_gate ON $n (gate(id));
        });
    }
}

sub generation
{
    return $node->safe_psql('postgres',
        "SELECT generation FROM pg_vault_tde_catalog WHERE relid = '$_[0]'::regclass");
}

# Six assertions: tags, contents, whole rows, out-of-line values, btrees.
sub check_table
{
    my ($t, $when) = @_;
    my $q = sub { my ($rc, $out, $err) = $node->psql('postgres', $_[0]); $rc ? "ERROR: $err" : $out };
    is($q->("SELECT total_tuples || '|' || failed_tuples FROM pg_vault_tde_verify_integrity('$t')"),
       '1000|0', "$p $t $when: every tag verifies");
    is($q->(qq{SELECT count(*) FROM (
                  (SELECT * FROM $t EXCEPT ALL SELECT * FROM ${t}_twin)
                  UNION ALL
                  (SELECT * FROM ${t}_twin EXCEPT ALL SELECT * FROM $t)) d}),
       '0', "$p $t $when: the rows equal the heap twin");
    is($q->("SELECT sum(length(x::text)) FROM $t x"),
       $q->("SELECT sum(length(x::text)) FROM ${t}_twin x"),
       "$p $t $when: every whole row reads as on the twin");
    is($q->("SELECT toast_values('$t')"), $q->("SELECT toast_values('${t}_twin')"),
       "$p $t $when: as many out-of-line values as the twin");
    is($q->("SELECT bt_index_check('${t}_pkey', true)"), '',
       "$p $t $when: amcheck finds every row in the primary key");
    is($q->("SELECT bt_index_check('${t}_gate', true)"), '',
       "$p $t $when: amcheck finds every row in the expression index");
}

sub worker_pid
{
    return $node->safe_psql('postgres', q{
        SELECT pid FROM pg_stat_activity WHERE backend_type = 'pg_vault_tde rotation'});
}

sub status_of
{
    return $node->safe_psql('postgres',
        "SELECT status FROM pg_vault_tde_rotation_progress WHERE relid = '$_[0]'::regclass");
}

# A named sub sees the file's $p, not a foreach alias of it: assign it.
for my $prov (@providers)
{
    $p = $prov;
    $node = new_node();
    for my $how (@how)
    {
        my $t = "rot_$how";
        make_table($t);
        my $gen = generation($t);

        my $holder = $node->background_psql('postgres', on_error_stop => 0);
        $holder->query_safe('SELECT pg_advisory_lock(42)');
        $node->safe_psql('postgres',
            "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('$t')");
        ok($node->poll_query_until('postgres', q{
               SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                              WHERE backend_type = 'pg_vault_tde rotation'
                                AND wait_event = 'advisory')}),
           "$p $how: the worker waits halfway through the rewrite");
        is(status_of($t), 'running', "$p $how: the progress row says 'running'");

        my $pid = worker_pid();
        if ($how eq 'immediate')
        {
            $node->stop('immediate');
            eval { $holder->quit; };
            $node->start;
        }
        else
        {
            $node->safe_psql('postgres',
                $how eq 'cancel' ? "SELECT pg_cancel_backend($pid)"
                                 : "SELECT pg_terminate_backend($pid)");
            $holder->query_safe('SELECT pg_advisory_unlock(42)');
            $holder->quit;
        }
        ok($node->poll_query_until('postgres', q{
               SELECT NOT EXISTS (SELECT 1 FROM pg_stat_activity
                                  WHERE backend_type = 'pg_vault_tde rotation')}),
           "$p $how: the worker is gone");

        check_table($t, "after $how");
        is(generation($t), $gen, "$p $how: the DEK generation is unchanged");
        is(status_of($t), $how eq 'immediate' ? 'running' : 'failed',
           $how eq 'immediate'
             ? "$p $how: the progress row still says 'running' (documented)"
             : "$p $how: the progress row says 'failed'");
        $node->restart;
        check_table($t, "after $how and a restart");

        $node->safe_psql('postgres',
            "SET client_min_messages = warning; SELECT pg_vault_tde_rotate_online('$t')");
        $node->poll_query_until('postgres', qq{
            SELECT status IN ('complete', 'failed') FROM pg_vault_tde_rotation_progress
            WHERE relid = '$t'::regclass});
        is(status_of($t), 'complete', "$p $how: a new rotation completes");
        is(generation($t), $gen + 1, "$p $how: ... one generation on");
        $node->safe_psql('postgres', "UPDATE ${t}_twin SET id = id");
        check_table($t, "after $how and a new rotation");
    }
    $node->stop;
}
