#!/usr/bin/env bash
# ci/scripts/run-errorpath.sh — Run the error-path regression suite (tests 141-153)
#
# Exercises the PG_CATCH handlers in the TAM write paths, which no success-path
# test can reach.  See sql/regression_test_errorpath.sql for the mechanism.
#
# Two things make this stage different from run-regress.sh, and both are
# load-bearing:
#
#   1. pg_vault_tde.wallet_dev_mode_passphrase is NOT set.  run-regress.sh sets
#      it so every backend can self-unlock; with it set, wallet_lock() is
#      undone on the next DEK request and every statement in the suite would
#      succeed instead of failing — the tests would pass without ever entering
#      a PG_CATCH.  Test 141 detects that and aborts, but the right fix is to
#      never set the GUC here.
#
#   2. The whole suite runs in ONE psql session.  The unlocked-wallet state is
#      per-backend, not shared memory, so splitting the script across
#      connections would leave the wallet locked for the setup phase too.
#
# Exit code: 0 on success, 9 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-errorpath-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "ERROR-PATH TESTS (141-153)"

build_pg_test_image

log_info "Starting $CONTAINER (kms_provider=local, NO dev_mode passphrase) ..."
$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run --rm -d \
    --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
    postgres \
        -c "shared_preload_libraries=pg_vault_tde" \
        -c "pg_vault_tde.dev_mode=on" \
        -c "pg_vault_tde.kms_provider=local" \
        -c "pg_vault_tde.wallet_auto_open=off" \
        -c "log_min_messages=warning" >/dev/null

wait_pg_ready "$CONTAINER"

log_info "Creating extension ..."
if ! container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -c \
        "CREATE EXTENSION IF NOT EXISTS pg_vault_tde;"; then
    log_error "ERROR-PATH: CREATE EXTENSION failed"
    $RT logs "$CONTAINER" --tail 50 2>/dev/null || true
    exit 9
fi

# Copy fresh SQL in case the image is cached with an older copy.
$RT cp "$REPO_ROOT/sql/regression_test_errorpath.sql" \
       "$CONTAINER:/tmp/regression_test_errorpath.sql"

log_info "Running regression_test_errorpath.sql (tests 141-153) ..."
START=$(timer_start)
if container_psql "$CONTAINER" -v ON_ERROR_STOP=1 \
        -f /tmp/regression_test_errorpath.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "ERROR-PATH: ALL 13 TESTS PASSED ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "ERROR-PATH: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 80 2>/dev/null || true
    exit 9
fi

# The suite asserts its own invariants, but a handler bug can also kill the
# backend outright — in which case psql reports a connection failure and the
# postmaster logs the signal.  Check the server log independently.
log_info "Scanning server log for crashes and allocator complaints ..."
if $RT logs "$CONTAINER" 2>&1 | grep -qiE \
        "terminated by signal|PANIC|double free|could not find block containing chunk|segmentation fault"; then
    log_error "ERROR-PATH: server log reports a crash or allocator error"
    $RT logs "$CONTAINER" 2>&1 | grep -iE \
        "terminated by signal|PANIC|double free|could not find block containing chunk|segmentation fault" \
        | head -20
    exit 9
fi
log_ok "ERROR-PATH: server log clean (no crash, no allocator error)"

log_ok "ERROR-PATH COMPLETE: tests 141-153 all passed"
exit 0
