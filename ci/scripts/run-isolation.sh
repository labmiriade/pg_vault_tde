#!/usr/bin/env bash
# ci/scripts/run-isolation.sh — Run isolation (concurrency) tests
#
# Executes the DEK rotation isolation spec which verifies that concurrent
# reads/writes during key rotation behave correctly under MVCC.
#
# Exit code: 0 on success, 4 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-isolation-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "ISOLATION TESTS"

build_pg_test_image

start_pg_container "$CONTAINER" "${PG_TEST_PORT:-15432}"

# Copy latest isolation spec
$RT cp "$REPO_ROOT/isolation/." "$CONTAINER:/test/isolation/"

log_info "Running isolation specs ..."
START=$(timer_start)

# pg_isolation_regress needs PGDATA and the PG bin path
if $RT exec -u postgres "$CONTAINER" bash -c '
    export PATH="/usr/lib/postgresql/18/bin:$PATH"
    export PGDATA="/var/lib/postgresql/data"
    cd /test
    # Run isolation tester against each spec
    for spec in isolation/*.spec; do
        specname=$(basename "$spec" .spec)
        echo "Running isolation spec: $specname"
        pg_isolation_regress \
            --inputdir=isolation \
            --dbname=postgres \
            "$specname" 2>&1 || exit 4
    done
    echo "All isolation specs passed"
'; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "ISOLATION: ALL SPECS PASSED ($(timer_fmt "$ELAPSED"))"
    exit 0
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "ISOLATION: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 30 2>/dev/null || true
    exit 4
fi
