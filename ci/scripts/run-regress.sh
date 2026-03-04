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

log_stage "REGRESSION TESTS (52 v1.4 + 20 v1.5 TDD = 72 total)"

build_pg_test_image

start_pg_container "$CONTAINER" "${PG_TEST_PORT:-15432}"

# Verify extension is loaded
log_info "Verifying pg_vault_tde extension ..."
container_psql "$CONTAINER" -c \
    "SELECT extname, extversion FROM pg_extension WHERE extname = 'pg_vault_tde';"

# Copy fresh regression SQL (in case image is cached with old version)
$RT cp "$REPO_ROOT/sql/regression_test.sql"    "$CONTAINER:/tmp/regression_test.sql"
$RT cp "$REPO_ROOT/sql/regression_test_v15.sql" "$CONTAINER:/tmp/regression_test_v15.sql"

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

# ── Phase 2: Apply v1.4 → v1.5 upgrade via extension mechanism ──────────────────
# Use ALTER EXTENSION UPDATE so PostgreSQL reads the installed upgrade
# script from $sharedir/extension/ where MODULE_PATHNAME has already
# been substituted by 'make install' (build stage in pg-test.Containerfile).
# The upgrade chain 1.0 → 1.4 → 1.5 is resolved automatically by PG.
log_info "Upgrading pg_vault_tde 1.0 → 1.5 (ALTER EXTENSION UPDATE) ..."
if ! container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -c \
        "ALTER EXTENSION pg_vault_tde UPDATE TO '1.5';"; then
    log_error "REGRESSION: pg_vault_tde 1.0→1.5 upgrade FAILED"
    $RT logs "$CONTAINER" --tail 50 2>/dev/null || true
    exit 2
fi
log_ok "pg_vault_tde upgraded to v1.5"

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

log_ok "REGRESSION COMPLETE: ALL 72 TESTS PASSED (v1.4 × 52 + v1.5 × 20)"
exit 0
