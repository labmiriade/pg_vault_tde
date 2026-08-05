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

# ── Start container with kms_provider=local configured ───────────────────
#
# We inline the container start instead of using start_pg_container() because
# we need to add extra postgres -c flags AFTER the image name (postgres args),
# whereas start_pg_container extra_args are passed as container runtime args
# (before the image name).
#
log_info "Starting pg-tde-isolation container with kms_provider=local ..."
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
        -c "pg_vault_tde.wallet_dev_mode_passphrase=tde_isolation" \
        -c "log_min_messages=warning"

wait_pg_ready "$CONTAINER"

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
    PGV=$(pg_config --version | awk "{print \$2}" | cut -d. -f1)
    export PATH="/usr/lib/postgresql/${PGV}/lib/pgxs/src/test/isolation:$PATH"
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


