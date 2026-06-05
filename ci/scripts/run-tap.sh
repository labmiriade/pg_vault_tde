#!/usr/bin/env bash
# ci/scripts/run-tap.sh — Run TAP tests inside the pg-test container
#
# TAP tests exercise:
#   - 01_load.t:         Extension loading and basic function availability
#   - 02_backup_local.t: Backup round-trip with the local wallet KMS provider
#   - 03_backup_vault.t: Backup round-trip with a real Vault Transit backend;
#                        skipped automatically if VAULT_ADDR is not set.
#
# This script:
#   1. Builds the pg-tde-test image
#   2. Starts a real Vault container (from ci/dump-compose.yml)
#   3. Starts the pg-tde-test container on the same network as Vault
#   4. Runs prove inside the container with VAULT_ADDR pointing at Vault
#   5. Tears down both containers on exit
#
# Exit code: 0 on success, 3 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-tap-$$"
VAULT_ADDR="http://real-vault:8200"

cleanup() {
    stop_container "$CONTAINER"
    $COMPOSE_CMD -f "$CI_DIR/dump-compose.yml" down -v 2>/dev/null || true
}
trap cleanup EXIT

log_stage "TAP TESTS"

build_pg_test_image

# ── Start Vault ────────────────────────────────────────────────────────────
log_info "Starting Vault container ..."
$COMPOSE_CMD -f "$CI_DIR/dump-compose.yml" up -d vault

log_info "Waiting for Vault (real-vault) ..."
for i in $(seq 1 30); do
    if $RT exec real-vault wget -q --spider http://127.0.0.1:8200/v1/sys/health 2>/dev/null; then
        log_ok "Vault ready (${i}s)"
        break
    fi
    if [[ $i -eq 30 ]]; then
        log_error "Vault failed to start within 30s"
        exit 3
    fi
    sleep 1
done

# Detect the network created by compose (podman-compose prefixes with project name)
VAULT_NETWORK=$($RT inspect real-vault --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' | awk '{print $1}')
log_info "Vault network: $VAULT_NETWORK"

# ── Start pg-tde-test container on the Vault network ──────────────────────
$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run --rm -d \
    --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    -e VAULT_ADDR="$VAULT_ADDR" \
    --network "$VAULT_NETWORK" \
    "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
    postgres \
    -c "shared_preload_libraries=pg_vault_tde" \
    -c "pg_vault_tde.dev_mode=on" \
    -c "log_min_messages=warning"

wait_pg_ready "$CONTAINER"

# Copy latest TAP test files into the container
$RT cp "$REPO_ROOT/tap/." "$CONTAINER:/test/tap/"

log_info "Running TAP tests with prove ..."
START=$(timer_start)

if $RT exec -u postgres "$CONTAINER" bash -c '
    export PATH="/usr/lib/postgresql/18/bin:$PATH"
    export PGDATA="/var/lib/postgresql/data"
    export PERL5LIB="/usr/lib/postgresql/18/lib/pgxs/src/test/perl${PERL5LIB:+:$PERL5LIB}"
    export PG_REGRESS="/usr/lib/postgresql/18/lib/pgxs/src/test/regress/pg_regress"
    cd /test
    prove -v tap/*.t 2>&1
'; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "TAP: ALL TESTS PASSED ($(timer_fmt "$ELAPSED"))"
    exit 0
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "TAP: FAILED after $(timer_fmt "$ELAPSED")"
    exit 3
fi
