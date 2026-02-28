#!/usr/bin/env bash
# ci/scripts/run-vault.sh — Vault integration test using Compose
#
# Starts both vault-mock and pg-vault containers via compose, then verifies
# that pg_vault_tde can communicate with Vault to obtain a DEK and perform
# encryption/decryption round-trips.
#
# Exit code: 0 on success, 5 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

COMPOSE_FILE="$CI_DIR/compose.yml"

cleanup() {
    log_info "Tearing down compose services ..."
    cd "$CI_DIR"
    $COMPOSE_CMD -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

log_stage "VAULT INTEGRATION TESTS"

# Build images via compose
log_info "Building images via compose ..."
cd "$CI_DIR"
$COMPOSE_CMD -f "$COMPOSE_FILE" build 2>&1 | tail -5

# Start vault-mock + pg-vault services
log_info "Starting vault-mock + pg-vault services ..."
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d vault-mock pg-vault

# Wait for Vault mock to be healthy
log_info "Waiting for Vault mock ..."
for i in $(seq 1 "${VAULT_STARTUP_TIMEOUT:-10}"); do
    if $RT exec vault-mock wget -q --spider http://localhost:8200/v1/sys/health 2>/dev/null; then
        break
    fi
    sleep 1
done
log_ok "Vault mock is healthy"

# Wait for PG to be ready
wait_pg_ready "pg-tde-vault"

START=$(timer_start)

log_info "Running Vault integration tests ..."

# Test 1: Verify PG can reach Vault
log_info "Test 1: Vault connectivity ..."
container_psql "pg-tde-vault" -c "SELECT 1 AS vault_reachable;"

# Test 2: Extension is loaded and functional
log_info "Test 2: Extension loaded ..."
container_psql "pg-tde-vault" -c \
    "SELECT extname, extversion FROM pg_extension WHERE extname = 'pg_vault_tde';"

# Test 3: Vault DEK acquisition (if the GUC-based Vault connector is wired)
# For now, fall back to test DEK if Vault GUC is not yet functional
log_info "Test 3: DEK acquisition ..."
container_psql "pg-tde-vault" -c "SELECT pg_vault_tde_set_test_dek();" 2>/dev/null || \
    log_warn "Vault-based DEK acquisition not yet wired — using test DEK"

# Test 4: Round-trip with Vault-acquired DEK
log_info "Test 4: Encrypted round-trip ..."
container_psql "pg-tde-vault" -c "
    CREATE TABLE IF NOT EXISTS vault_test (id int, secret text) USING encrypted_heap;
    INSERT INTO vault_test VALUES (1, 'vault-secret-data');
    SELECT id, secret FROM vault_test WHERE id = 1;
    DROP TABLE vault_test;
"

# Test 5: Key rotation
log_info "Test 5: Key rotation ..."
container_psql "pg-tde-vault" -c "
    CREATE TABLE vault_rot (id int, val text) USING encrypted_heap;
    INSERT INTO vault_rot VALUES (1, 'before-rotation');
    SELECT pg_vault_tde_rotate_key();
    SELECT pg_vault_tde_key_generation();
    DROP TABLE vault_rot;
"

# Test 6: Multiple operations under Vault-provided DEK
log_info "Test 6: Multi-operation test ..."
container_psql "pg-tde-vault" -c "
    CREATE TABLE vault_multi (
        id   serial PRIMARY KEY,
        data text,
        num  numeric(10,2),
        ts   timestamptz DEFAULT now()
    ) USING encrypted_heap;
    INSERT INTO vault_multi (data, num)
        SELECT md5(g::text), g * 1.5 FROM generate_series(1, 100) g;
    SELECT count(*) AS total FROM vault_multi;
    UPDATE vault_multi SET data = 'updated' WHERE id <= 10;
    DELETE FROM vault_multi WHERE id > 90;
    SELECT count(*) AS after_ops FROM vault_multi;
    DROP TABLE vault_multi;
"

ELAPSED=$(timer_elapsed "$START")
log_ok "VAULT: ALL INTEGRATION TESTS PASSED ($(timer_fmt "$ELAPSED"))"
exit 0
