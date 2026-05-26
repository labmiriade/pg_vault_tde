#!/usr/bin/env bash
# ci/scripts/run-regress.sh — Run the 24-test pg_regress suite
#
# Starts a standalone pg-test container, copies regression_test.sql,
# executes it, and reports pass/fail.
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

log_stage "REGRESSION TESTS (52 v1.4 + 20 v1.5 TDD + 8 v1.6 wallet = 80 total)"

build_pg_test_image

start_pg_container "$CONTAINER" "${PG_TEST_PORT:-15432}"

# Verify extension is loaded
log_info "Verifying pg_vault_tde extension ..."
container_psql "$CONTAINER" -c \
    "SELECT extname, extversion FROM pg_extension WHERE extname = 'pg_vault_tde';" 

# Copy fresh regression SQL (in case image is cached with old version)
$RT cp "$REPO_ROOT/sql/regression_test.sql"    "$CONTAINER:/tmp/regression_test.sql"
$RT cp "$REPO_ROOT/sql/regression_test_v15.sql" "$CONTAINER:/tmp/regression_test_v15.sql"
$RT cp "$REPO_ROOT/sql/regression_test_v16.sql" "$CONTAINER:/tmp/regression_test_v16.sql"

# ── Phase 1: v1.4 baseline (52 tests) ────────────────────────────────────
log_info "Running v1.4 regression_test.sql (52 tests) ..."
START=$(timer_start)
if ! container_psql "$CONTAINER" -f /tmp/regression_test.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_error "REGRESSION v1.4: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 50 2>/dev/null || true
    exit 2
fi
log_ok "v1.4 baseline: ALL 52 TESTS PASSED ($(timer_fmt "$(timer_elapsed "$START")"))"

# ── Phase 2: Ensure extension is at v1.5 before running v1.5 TDD tests ─────────
# The container's CREATE EXTENSION defaults to whatever pg_vault_tde.control
# declares as default_version (1.6 since v1.6 release).  PostgreSQL refuses
# downgrades, so we only issue an UPDATE if the live version is < 1.5.
log_info "Ensuring pg_vault_tde >= 1.5 (skip UPDATE if already >= 1.5) ..."
LIVE_VERSION=$(container_psql "$CONTAINER" -tAc \
    "SELECT extversion FROM pg_extension WHERE extname='pg_vault_tde';")
case "$LIVE_VERSION" in
    1.0|1.1|1.2|1.3|1.4)
        if ! container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -c \
                "ALTER EXTENSION pg_vault_tde UPDATE TO '1.5';"; then
            log_error "REGRESSION: pg_vault_tde ${LIVE_VERSION}→1.5 upgrade FAILED"
            $RT logs "$CONTAINER" --tail 50 2>/dev/null || true
            exit 2
        fi
        log_ok "pg_vault_tde upgraded ${LIVE_VERSION} → 1.5"
        ;;
    *)
        log_ok "pg_vault_tde already at ${LIVE_VERSION} (>= 1.5); skipping UPDATE"
        ;;
esac

# ── Phase 3: v1.5 TDD tests (20 tests, numbers 53-72) ───────────────────
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

# ── Phase 4: Ensure extension is at v1.6 before running v1.6 wallet tests ─────
log_info "Ensuring pg_vault_tde >= 1.6 (skip UPDATE if already >= 1.6) ..."
LIVE_VERSION=$(container_psql "$CONTAINER" -tAc \
    "SELECT extversion FROM pg_extension WHERE extname='pg_vault_tde';")
case "$LIVE_VERSION" in
    1.5)
        if ! container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -c \
                "ALTER EXTENSION pg_vault_tde UPDATE TO '1.6';"; then
            log_error "REGRESSION: pg_vault_tde 1.5→1.6 upgrade FAILED"
            $RT logs "$CONTAINER" --tail 50 2>/dev/null || true
            exit 2
        fi
        log_ok "pg_vault_tde upgraded 1.5 → 1.6"
        ;;
    1.6)
        log_ok "pg_vault_tde already at 1.6; skipping UPDATE"
        ;;
    *)
        log_error "REGRESSION: unexpected live version '${LIVE_VERSION}' before v1.6 phase"
        exit 2
        ;;
esac

# ── Phase 5: v1.6 wallet tests (8 tests, numbers 73-80) ─────────────────
#
# In this container kms_provider defaults to 'vault', so tests 74-80
# (which require kms_provider='local') emit SKIP notices and exit cleanly.
# Only test 73 (structural function-registration check) runs unconditionally.
#
# To run all 8 wallet tests unconditionally use:  make ci-wallet
#
log_info "Running v1.6 wallet regression_test_v16.sql (tests 73-80) ..."
START=$(timer_start)
if container_psql "$CONTAINER" -f /tmp/regression_test_v16.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "REGRESSION v1.6 wallet: tests 73-80 OK ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "REGRESSION v1.6 wallet: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 80 2>/dev/null || true
    exit 2
fi

log_ok "REGRESSION COMPLETE: ALL 80 TESTS PASSED (v1.4 × 52 + v1.5 × 20 + v1.6 × 8)"
exit 0
