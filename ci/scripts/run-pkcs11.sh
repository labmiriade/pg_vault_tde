#!/usr/bin/env bash
# ci/scripts/run-pkcs11.sh — pkcs11 KMS provider TAP test (SoftHSM2)
#
# Runs tap/16_pkcs11.t inside the pg-test container.  SoftHSM2 is installed
# in the image (ci/containers/pg-test.Containerfile); the test provisions
# its own throwaway token in a tempdir, so no service container and no
# extra setup are needed — unlike the Vault stages.
#
# Usage:
#   bash ci/scripts/run-pkcs11.sh
#   make ci-pkcs11
#
# Exit code: 0 on success, 3 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-pkcs11-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "PKCS11 PROVIDER TAP TEST (SoftHSM2)"

build_pg_test_image

# The TAP test spawns its own PostgreSQL nodes; the container's default
# postgres server is just a harmless background occupant.
$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run --rm -d \
    --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
    postgres \
    -c "shared_preload_libraries=pg_vault_tde" \
    -c "log_min_messages=warning"

wait_pg_ready "$CONTAINER"

# Copy latest TAP test files into the container
$RT cp "$REPO_ROOT/tap/." "$CONTAINER:/test/tap/"

log_info "Running tap/16_pkcs11.t with prove ..."
START=$(timer_start)

if $RT exec -u postgres "$CONTAINER" bash -c '
    PGV=$(pg_config --version | awk "{print \$2}" | cut -d. -f1)
    export PATH="/usr/lib/postgresql/${PGV}/bin:$PATH"
    export PGDATA="/var/lib/postgresql/data"
    export PERL5LIB="/usr/lib/postgresql/${PGV}/lib/pgxs/src/test/perl${PERL5LIB:+:$PERL5LIB}"
    export PG_REGRESS="/usr/lib/postgresql/${PGV}/lib/pgxs/src/test/regress/pg_regress"
    cd /test
    prove -v --failures tap/16_pkcs11.t
'; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "PKCS11: TAP TEST PASSED ($(timer_fmt "$ELAPSED"))"
    exit 0
else
    ELAPSED=$(timer_elapsed "$START")
    $RT cp "$CONTAINER":/test/log "$REPO_ROOT"/test/tap 2>/dev/null || true
    log_error "PKCS11: FAILED after $(timer_fmt "$ELAPSED")"
    exit 3
fi
