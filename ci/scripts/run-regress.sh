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

log_stage "REGRESSION TESTS (48 tests)"

build_pg_test_image

start_pg_container "$CONTAINER" "${PG_TEST_PORT:-15432}"

# Verify extension is loaded
log_info "Verifying pg_vault_tde extension ..."
container_psql "$CONTAINER" -c \
    "SELECT extname, extversion FROM pg_extension WHERE extname = 'pg_vault_tde';"

# Copy fresh regression SQL (in case image is cached with old version)
$RT cp "$REPO_ROOT/sql/regression_test.sql" "$CONTAINER:/tmp/regression_test.sql"

# Run the regression suite
log_info "Running regression_test.sql ..."
START=$(timer_start)

if container_psql "$CONTAINER" -f /tmp/regression_test.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "REGRESSION: ALL 48 TESTS PASSED ($(timer_fmt "$ELAPSED"))"
    exit 0
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "REGRESSION: FAILED after $(timer_fmt "$ELAPSED")"
    # Dump server log for diagnostics
    $RT logs "$CONTAINER" --tail 50 2>/dev/null || true
    exit 2
fi
