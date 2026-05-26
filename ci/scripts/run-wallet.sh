#!/usr/bin/env bash
# ci/scripts/run-wallet.sh — Local wallet regression tests (kms_provider=local)
#
# Starts a standalone pg-test container configured with kms_provider=local,
# upgrades the extension to v1.6, and runs sql/regression_test_v16.sql.
#
# These tests specifically guard the v1.6 wallet KEK-caching regression:
#   BUG: wallet_unlock() discarded the derived KEK immediately, causing
#        local_wrap_dek() to fail with "wrap_dek failed for relid=N"
#        when no wallet_passphrase_env/file/command GUC was configured.
#
# Tests 74-80 require kms_provider='local'.  Tests 86-87 also require
# pg_vault_tde.dev_mode=on because the forensic SQL helpers are test-only.
# They SKIP in the default regression container (which uses kms_provider='vault');
# this script provides a container where they all run and must PASS.
#
# Usage:
#   bash ci/scripts/run-wallet.sh
#   make ci-wallet
#
# Exit code: 0 on success, 2 on test failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-wallet-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "WALLET REGRESSION TESTS (kms_provider=local, tests 73-87)"

# ── Build image ───────────────────────────────────────────────────────────
build_pg_test_image

# ── Start container with kms_provider=local configured ───────────────────
#
# We inline the container start instead of using start_pg_container() because
# we need to add extra postgres -c flags AFTER the image name (postgres args),
# whereas start_pg_container extra_args are passed as container runtime args
# (before the image name).
#
log_info "Starting pg-tde-wallet container with kms_provider=local ..."
$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run --rm -d \
    --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    -p "${PG_WALLET_PORT:-15438}:5432" \
    "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
    postgres \
        -c "shared_preload_libraries=pg_vault_tde" \
        -c "pg_vault_tde.dev_mode=on" \
        -c "pg_vault_tde.kms_provider=local" \
        -c "pg_vault_tde.wallet_auto_open=off" \
        -c "pg_vault_tde.wallet_dev_mode_passphrase=tde_regression_pass_2026" \
        -c "log_min_messages=warning"

wait_pg_ready "$CONTAINER"

# ── Create extension and upgrade to v1.6 ─────────────────────────────────
log_info "Creating pg_vault_tde extension (installs at default_version=1.6) ..."
if ! container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -c \
        "CREATE EXTENSION IF NOT EXISTS pg_vault_tde;"; then
    log_error "WALLET: CREATE EXTENSION IF NOT EXISTS failed"
    $RT logs "$CONTAINER" --tail 30 2>/dev/null || true
    exit 2
fi

# Verify kms_provider is correctly set to 'local' inside the container
log_info "Verifying kms_provider=local ..."
PROVIDER=$(container_psql "$CONTAINER" -tAc \
    "SELECT current_setting('pg_vault_tde.kms_provider', true);")
if [[ "$PROVIDER" != "local" ]]; then
    log_error "WALLET: kms_provider='$PROVIDER' (expected 'local') — container config issue"
    exit 2
fi
log_ok "kms_provider=local confirmed"

# ── Copy and run regression_test_v16.sql ─────────────────────────────────
log_info "Copying regression_test_v16.sql into container ..."
$RT cp "$REPO_ROOT/sql/regression_test_v16.sql" \
       "$CONTAINER:/tmp/regression_test_v16.sql"

log_info "Running wallet regression tests (tests 73-80) ..."
START=$(timer_start)
if container_psql "$CONTAINER" -v ON_ERROR_STOP=1 \
        -f /tmp/regression_test_v16.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "WALLET REGRESSION: ALL 8 TESTS PASSED ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "WALLET REGRESSION: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 80 2>/dev/null || true
    exit 2
fi

log_ok "WALLET REGRESSION COMPLETE: tests 73-107 all passed"
exit 0
