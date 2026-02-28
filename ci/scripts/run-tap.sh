#!/usr/bin/env bash
# ci/scripts/run-tap.sh — Run TAP tests inside the pg-test container
#
# TAP tests exercise:
#   - 01_load.t: Extension loading and basic function availability
#   - 02_backup.t: Backup hook integration with mock Vault via HTTP::Daemon
#
# Exit code: 0 on success, 3 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-tap-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "TAP TESTS"

build_pg_test_image

start_pg_container "$CONTAINER" "${PG_TEST_PORT:-15432}"

# Copy latest TAP test files into the container
$RT cp "$REPO_ROOT/tap/." "$CONTAINER:/test/tap/"

log_info "Running TAP tests with prove ..."
START=$(timer_start)

# TAP tests need the PG bin dir in PATH and PGDATA set
if $RT exec -u postgres "$CONTAINER" bash -c '
    export PATH="/usr/lib/postgresql/18/bin:$PATH"
    export PGDATA="/var/lib/postgresql/data"
    cd /test
    prove -v tap/*.t 2>&1
'; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "TAP: ALL TESTS PASSED ($(timer_fmt "$ELAPSED"))"
    exit 0
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "TAP: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 30 2>/dev/null || true
    exit 3
fi
