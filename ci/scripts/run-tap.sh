#!/usr/bin/env bash
# ci/scripts/run-tap.sh — Run TAP tests inside the pg-test container
#
# Runs every tap/*.t file (18 at the time of writing); see the TAP Tests table
# in doc/pg_vault_tde.md for what each one covers.  A few examples:
#   - 01_load.t:                   Extension loading and function availability
#   - 02_backup_local.t:           Backup round-trip, local wallet KMS provider
#   - 03_backup_vault.t:           Backup round-trip against a real Vault Transit
#                                  backend; skip_all when VAULT_ADDR is not set
#   - 18_guc_order_independence.t: KMS GUCs are order- and scope-independent
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

# Tee prove's output: the failure branch needs the "Test Summary Report" to know
# which test files failed.
PROVE_OUT=$(mktemp)
trap 'rm -f "$PROVE_OUT"; cleanup' EXIT

if $RT exec -u postgres "$CONTAINER" bash -c '
    PGV=$(pg_config --version | awk "{print \$2}" | cut -d. -f1)
    export PATH="/usr/lib/postgresql/${PGV}/bin:$PATH"
    export PGDATA="/var/lib/postgresql/data"
    export PERL5LIB="/usr/lib/postgresql/${PGV}/lib/pgxs/src/test/perl${PERL5LIB:+:$PERL5LIB}"
    export PG_REGRESS="/usr/lib/postgresql/${PGV}/lib/pgxs/src/test/regress/pg_regress"
    cd /test
    prove -v --failures tap/*.t 
' 2>&1 | tee "$PROVE_OUT"; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "TAP: ALL TESTS PASSED ($(timer_fmt "$ELAPSED"))"
    exit 0
else
    ELAPSED=$(timer_elapsed "$START")
    $RT cp "$CONTAINER":/test/log "$REPO_ROOT"/test/tap

    # PostgreSQL::Test redirects every diagnostic — psql stderr, the server's
    # own ERROR/PANIC lines, the croak that killed the script — into
    # test/log/regress_log_<test>, and only the bare TAP stream reaches the
    # console.  A failing build therefore prints "Dubious, test returned N" and
    # nothing else, and the cause is only reachable by downloading the
    # artifact.  Echo the tail of each failing test's log so the build output
    # names the failing statement on its own.
    for t in $(awk '/\(Wstat:/ {print $1}' "$PROVE_OUT"); do
        f="$REPO_ROOT/test/tap/log/regress_log_$(basename "$t" .t)"
        [[ -f "$f" ]] || continue
        echo ""
        echo "──── ${f##*/} (last 80 lines) ────"
        tail -n 80 "$f"
    done

    log_error "TAP: FAILED after $(timer_fmt "$ELAPSED")"
    exit 3
fi
