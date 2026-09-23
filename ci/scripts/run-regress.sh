#!/usr/bin/env bash
# ci/scripts/run-regress.sh — Run the full pg_vault_tde regression suite
#
# Starts a standalone pg-test container configured with kms_provider=local,
# initialises the local wallet, and runs all four regression SQL files.

#
# Exit code: 0 on success, 2 on test failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-regress-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "REGRESSION TESTS (45 v1.4 + 20 v1.5 + 36 v1.6 + 41 v1.7 = 142 total)"

build_pg_test_image

# ── Start container with kms_provider=local configured ───────────────────
#
# We inline the container start instead of using start_pg_container() because
# we need to add extra postgres -c flags AFTER the image name (postgres args),
# whereas start_pg_container extra_args are passed as container runtime args
# (before the image name).
#
log_info "Starting pg-tde-regress container with kms_provider=local ..."
$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run --rm -d \
    --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    -p "${PG_TEST_PORT:-15432}:5432" \
    "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
    postgres \
        -c "shared_preload_libraries=pg_vault_tde" \
        -c "pg_vault_tde.dev_mode=on" \
        -c "pg_vault_tde.kms_provider=local" \
        -c "pg_vault_tde.wallet_auto_open=off" \
        -c "pg_vault_tde.wallet_dev_mode_passphrase=tde_regression_pass_2026" \
        -c "log_min_messages=warning"

wait_pg_ready "$CONTAINER"

# Verify extension is loaded
log_info "Verifying pg_vault_tde extension ..."
container_psql "$CONTAINER" -c \
    "SELECT extname, extversion FROM pg_extension WHERE extname = 'pg_vault_tde';"

# Initialise wallet so wallet_init() sets the global shmem DEK.
# The passphrase matches wallet_dev_mode_passphrase so subsequent
# wrap/unwrap operations in the tests work without interactive unlock.
log_info "Initialising local wallet ..."
if ! container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -c \
        "SELECT pg_vault_tde_wallet_init('tde_regression_pass_2026');"; then
    log_error "REGRESSION: wallet_init failed"
    $RT logs "$CONTAINER" --tail 30 2>/dev/null || true
    exit 2
fi
log_ok "Local wallet initialised"

# pageinspect lets the storage-level tests read raw pages.  Without it they
# take their SKIP branch and assert nothing: TEST 61 (TOAST chunks encrypted
# on the page) and TEST 144 (the on-disk tuple is physically walkable) were
# silent no-ops in CI until this line existed.  Guarded on availability so a
# base image without contrib still runs the rest of the suite.
log_info "Installing pageinspect (storage-level assertions) ..."
container_psql "$CONTAINER" -c \
    "DO \$\$ BEGIN
         IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pageinspect') THEN
             CREATE EXTENSION IF NOT EXISTS pageinspect;
         ELSE
             RAISE NOTICE 'pageinspect unavailable — storage-level tests will skip';
         END IF;
     END \$\$;"

# Copy fresh regression SQL (in case image is cached with old version)
$RT cp "$REPO_ROOT/sql/regression_test.sql"    "$CONTAINER:/tmp/regression_test.sql"
$RT cp "$REPO_ROOT/sql/regression_test_v15.sql" "$CONTAINER:/tmp/regression_test_v15.sql"
$RT cp "$REPO_ROOT/sql/regression_test_v16.sql" "$CONTAINER:/tmp/regression_test_v16.sql"
$RT cp "$REPO_ROOT/sql/regression_test_v17.sql" "$CONTAINER:/tmp/regression_test_v17.sql"

# ── Phase 1: v1.4 baseline (45 tests, numbered 1-52) ────────────────────────────────────
log_info "Running v1.4 regression_test.sql (45 tests) ..."
START=$(timer_start)
if ! container_psql "$CONTAINER" -f /tmp/regression_test.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_error "REGRESSION v1.4: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 50 2>/dev/null || true
    exit 2
fi
log_ok "v1.4 baseline: ALL 45 TESTS PASSED ($(timer_fmt "$(timer_elapsed "$START")"))"

# ── Version guard ─────────────────────────────────────────────────────────
# Only pg_vault_tde--1.7.sql is shipped (DATA in the Makefile) and the .control
# declares default_version = 1.7, so CREATE EXTENSION lands on 1.7 and there is
# no upgrade chain to walk. This asserts that instead of pretending to walk one.
#
LIVE_VERSION=$(container_psql "$CONTAINER" -tAc \
    "SELECT extversion FROM pg_extension WHERE extname='pg_vault_tde';")
if [ "$LIVE_VERSION" != "1.7" ]; then
    log_error "REGRESSION: expected pg_vault_tde 1.7, found '${LIVE_VERSION}'"
    exit 2
fi
log_ok "pg_vault_tde at ${LIVE_VERSION}"

# ── Phase 2: v1.5 TDD tests (20 tests, numbers 53-72) ───────────────────
log_info "Running v1.5 TDD regression_test_v15.sql (tests 53-72) ..."
START=$(timer_start)
if container_psql "$CONTAINER" -f /tmp/regression_test_v15.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "REGRESSION v1.5 TDD: ALL 20 TESTS PASSED ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "REGRESSION v1.5 TDD: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 80 2>/dev/null || true
    exit 2
fi

# ── Phase 3: v1.6 wallet tests (tests 73-109) ────────────────────────────
log_info "Running v1.6 wallet regression_test_v16.sql (tests 73-109) ..."
START=$(timer_start)
if container_psql "$CONTAINER" -f /tmp/regression_test_v16.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "REGRESSION v1.6 wallet: tests 73-109 OK ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "REGRESSION v1.6 wallet: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 80 2>/dev/null || true
    exit 2
fi

# ── Phase 4: v1.7 wallet tests (tests 111-140 + 154-164) ────────────────────────────
log_info "Running v1.7 wallet regression_test_v17.sql (tests 111-140 + 154-164) ..."
START=$(timer_start)
if container_psql "$CONTAINER" -f /tmp/regression_test_v17.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "REGRESSION v1.7 wallet: tests 111-140 + 154-164 OK ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "REGRESSION v1.7 wallet: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 80 2>/dev/null || true
    exit 2
fi

log_ok "REGRESSION COMPLETE: ALL 142 TESTS PASSED (v1.4 × 45 + v1.5 × 20 + v1.6 × 36 + v1.7 × 41)"
exit 0
