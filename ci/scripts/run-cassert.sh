#!/usr/bin/env bash
# ci/scripts/run-cassert.sh — Run the suites against an assert-enabled server.
#
# This is the stage that can see what every other stage misses.
#
# --enable-cassert does two things for us.  It executes the Assert() calls the
# codebase is already full of — none of which run in any packaged build — and
# it turns on MEMORY_CONTEXT_CHECKING, which fills freed chunks with a poison
# pattern and validates the chunk header on every pfree().  A pfree() of an
# already-freed chunk becomes an immediate, loud failure instead of a silent
# no-op.  That is exactly the failure mode the PG_CATCH handlers in the TAM
# write paths can produce, and exactly what a release build swallows: the
# error aborts the transaction, the memory context is deleted moments later,
# and aset.c never notices.
#
# Two server configurations are needed, so the stage starts the server twice:
#
#   Phase 1  wallet_dev_mode_passphrase SET     — the four regression files,
#                                                 in run-regress.sh order; they
#                                                 expect every backend to be
#                                                 able to self-unlock
#   Phase 2  wallet_dev_mode_passphrase UNSET   — the error-path suite, which
#                                                 needs wallet_lock() to stick
#
# Exit code: 0 clean, 13 on assertion failure or suite failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# lib.sh sets -e; this script checks exit codes explicitly and must not die on
# the first expected non-zero (a grep that finds nothing, a psql that errors).
set +e

CONTAINER="pg-tde-cassert-$$"
CA_IMAGE="${PG_CASSERT_IMAGE:-pg-tde-cassert}"
PGDATA_DIR=/var/lib/postgresql/data
REGRESS_PASS=tde_regression_pass_2026

cleanup() { $RT rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

log_stage "CASSERT (assert-enabled server)"

log_info "Building $CA_IMAGE (PostgreSQL from source, --enable-cassert) ..."
log_info "  first build compiles PostgreSQL and takes a while; later runs hit the layer cache"
$RT build \
    --build-arg PG_VERSION="${PG_SOURCE_VERSION:-18.6}" \
    -f "$CI_DIR/containers/pg-cassert.Containerfile" \
    -t "$CA_IMAGE:latest" \
    "$REPO_ROOT" 2>&1 | tail -3
log_ok "Image $CA_IMAGE built"

$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run -d --name "$CONTAINER" --entrypoint sleep "$CA_IMAGE:latest" infinity >/dev/null

cx() { $RT exec "$CONTAINER" "$@"; }

# Confirm we really are on an instrumented server.  A silently-stock server
# would make this whole stage a green light that checks nothing.
if ! cx pg_config --configure 2>/dev/null | grep -q -- '--enable-cassert'; then
    log_error "CASSERT: server is NOT built with --enable-cassert"
    exit 13
fi
log_ok "Server confirmed: $(cx pg_config --version) with --enable-cassert"

log_info "initdb ..."
if ! cx initdb -D "$PGDATA_DIR" -U postgres --auth=trust >/dev/null 2>&1; then
    log_error "CASSERT: initdb failed"
    cx initdb -D "$PGDATA_DIR" -U postgres --auth=trust 2>&1 | tail -20
    exit 13
fi

# ── Helpers ──────────────────────────────────────────────────────────────
start_server() {   # $1 = extra postgresql.conf lines
    cx bash -c "cat > $PGDATA_DIR/postgresql.auto.conf <<'CONF'
shared_preload_libraries = 'pg_vault_tde'
pg_vault_tde.dev_mode = on
pg_vault_tde.kms_provider = 'local'
pg_vault_tde.wallet_auto_open = off
log_min_messages = warning
fsync = off
$1
CONF"
    if ! cx pg_ctl -D "$PGDATA_DIR" -o "-k /tmp" -l /tmp/pg.log -w -t 60 start >/dev/null 2>&1; then
        log_error "CASSERT: server failed to start"
        cx bash -c 'tail -40 /tmp/pg.log' 2>/dev/null || true
        exit 13
    fi
}
stop_server() {
    # An assertion failure kills the backend and the postmaster restarts into
    # recovery, so a plain "fast" stop can fail and leave phase 2 running
    # against phase 1's state.  Fall back to immediate, then wait it out.
    cx pg_ctl -D "$PGDATA_DIR" -m fast -w -t 60 stop >/dev/null 2>&1 \
        || cx pg_ctl -D "$PGDATA_DIR" -m immediate -w -t 30 stop >/dev/null 2>&1 \
        || cx bash -c 'pkill -9 -x postgres' >/dev/null 2>&1
    cx bash -c 'rm -f '"$PGDATA_DIR"'/postmaster.pid' >/dev/null 2>&1
}
q() { cx psql -h /tmp -U postgres "$@"; }

# Assertion failures land in the server log as "TRAP: failed Assert", and a
# MEMORY_CONTEXT_CHECKING violation as a chunk-header complaint.  Either one
# means the run found something, whatever the suite's own exit code said.
assert_log_clean() {   # $1 = phase label
    if cx grep -qiE "TRAP: failed Assert|FailedAssertion|could not find block containing chunk|detected write past chunk end" /tmp/pg.log 2>/dev/null; then
        log_error "CASSERT: assertion failure during $1"
        cx grep -iE -B3 -A12 "TRAP: failed Assert|FailedAssertion|could not find block containing chunk|detected write past chunk end" /tmp/pg.log | head -60
        return 1
    fi
    return 0
}

RC=0

# ── Phase 1: regression suite ────────────────────────────────────────────
# The four files share cluster state, so they run in order and the first
# failure stops the phase.  The exit status matters as much as the output: a
# backend killed by an assertion prints no "FAILED" line at all.
log_info "Phase 1: regression suite, dev passphrase SET ..."
start_server "pg_vault_tde.wallet_dev_mode_passphrase = '$REGRESS_PASS'"
q -v ON_ERROR_STOP=1 -c "CREATE EXTENSION pg_vault_tde;" >/dev/null 2>&1
q -v ON_ERROR_STOP=1 -c "SELECT pg_vault_tde_wallet_init('$REGRESS_PASS');" >/dev/null 2>&1

START=$(timer_start)
for f in regression_test regression_test_v15 regression_test_v16 regression_test_v17; do
    $RT cp "$REPO_ROOT/sql/$f.sql" "$CONTAINER:/tmp/$f.sql"
    OUT=$(q -v ON_ERROR_STOP=1 -f "/tmp/$f.sql" 2>&1)
    if [ $? -ne 0 ] || grep -qE "TEST [0-9]+[a-z]? FAILED|FATAL" <<<"$OUT"; then
        log_error "CASSERT: $f.sql failed under assertions"
        tail -30 <<<"$OUT"
        RC=13
        break
    fi
    log_ok "  $f.sql: $(grep -cE 'TEST [0-9]+[a-z]? PASSED' <<<"$OUT") passed"
done
[ "$RC" -eq 0 ] && log_ok "Phase 1 passed ($(timer_fmt "$(timer_elapsed "$START")"))"
assert_log_clean "phase 1 (regression suite)" || RC=13
stop_server

# ── Phase 2: error-path suite ────────────────────────────────────────────
# The point of the whole stage: 145 aborted writes through the PG_CATCH
# handlers, with the allocator validating every pfree().
log_info "Phase 2: error-path suite, dev passphrase UNSET ..."
# Phase 1 left a wallet behind under a different passphrase; the error-path
# suite calls wallet_init() and would fail on the existing file.  Both phases
# share one PGDATA, so clear it here rather than paying for a second initdb.
cx bash -c 'rm -f /tmp/pg.log; rm -rf /var/lib/pg_vault_tde/*'
start_server ""
$RT cp "$REPO_ROOT/sql/regression_test_errorpath.sql" "$CONTAINER:/tmp/errorpath.sql"

START=$(timer_start)
if ! q -v ON_ERROR_STOP=1 -f /tmp/errorpath.sql >/dev/null 2>&1; then
    log_error "CASSERT: error-path suite failed under assertions"
    q -v ON_ERROR_STOP=1 -f /tmp/errorpath.sql 2>&1 | tail -30
    RC=13
else
    log_ok "Phase 2 passed ($(timer_fmt "$(timer_elapsed "$START")"))"
fi
assert_log_clean "phase 2 (error-path suite)" || RC=13
stop_server

if [ "$RC" -ne 0 ]; then
    log_error "CASSERT: FAILED"
    exit "$RC"
fi

log_ok "CASSERT: both suites clean on an assert-enabled server"
exit 0
