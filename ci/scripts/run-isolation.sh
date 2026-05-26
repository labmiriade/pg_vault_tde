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

# Copy latest isolation specs + expected output
$RT cp "$REPO_ROOT/test/isolation/." "$CONTAINER:/test/isolation/"

log_info "Running isolation specs ..."
START=$(timer_start)

# pg_isolation_regress conventions:
#   --inputdir must contain specs/ and expected/ subdirectories
#   --outputdir receives results/ and regression.out (needs to be writable by postgres)
#
# /test is root-owned; use a writable temp dir as outputdir.
# After a successful first run (no expected file), copy actual → expected so
# subsequent runs act as regression guards.
if $RT exec -u postgres "$CONTAINER" bash -c '
    export PATH="/usr/lib/postgresql/18/bin:/usr/lib/postgresql/18/lib/pgxs/src/test/isolation:$PATH"
    export PGDATA="/var/lib/postgresql/data"
    OUTDIR=$(mktemp -d /tmp/isolation_out.XXXXXX)
    ALL_PASS=true
    for spec in /test/isolation/specs/*.spec; do
        specname=$(basename "$spec" .spec)
        echo "Running isolation spec: $specname"
        pg_isolation_regress \
            --inputdir=/test/isolation \
            --outputdir="$OUTDIR" \
            --dbname=tde_isolation \
            "$specname" 1>/dev/null || ALL_PASS=false
    done
    $ALL_PASS && echo "All isolation specs passed"
'; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "ISOLATION: ALL SPECS PASSED ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "ISOLATION: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 30 2>/dev/null || true

    $RT exec -u postgres "$CONTAINER" bash -c '
        echo "=====FAILED TEST DIFF=========="
        cat /tmp/isolation_out.*/regression.diffs 2>/dev/null || echo "regression.diffs file not found"
    '
    exit 4
fi
log_ok "v1.4 baseline: ALL ISOLATION TESTS PASSED ($(timer_fmt "$(timer_elapsed "$START")"))"


