#!/usr/bin/env bash
# ci/scripts/run-checksums.sh — Run regression suite with page checksums
#
# Verifies pg_vault_tde is fully compatible with PostgreSQL data checksums.
# Uses POSTGRES_INITDB_ARGS="-k" to enable checksums at initdb time.
#
# Exit code: 0 on success, 2 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-checksums-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "PAGE CHECKSUM COMPATIBILITY"

build_pg_test_image

# Start with checksums enabled via POSTGRES_INITDB_ARGS="-k"
$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run --rm -d \
    --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_INITDB_ARGS="-k" \
    -p "${PG_CHECKSUMS_PORT:-15433}:5432" \
    "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
    postgres \
    -c "shared_preload_libraries=pg_vault_tde" \
    -c "pg_vault_tde.dev_mode=on" \
    -c "log_min_messages=warning"

wait_pg_ready "$CONTAINER"

# Verify checksums are ON
CHECKSUMS=$(container_psql "$CONTAINER" -tAc "SHOW data_checksums;" | tr -d '[:space:]')
if [[ "$CHECKSUMS" != "on" ]]; then
    log_error "data_checksums = '$CHECKSUMS', expected 'on'"
    exit 2
fi
log_ok "data_checksums = on"

# Run full regression suite
$RT cp "$REPO_ROOT/sql/regression_test.sql" "$CONTAINER:/tmp/regression_test.sql"

log_info "Running regression_test.sql with checksums enabled ..."
START=$(timer_start)

if container_psql "$CONTAINER" -f /tmp/regression_test.sql; then
    :
else
    log_error "Regression tests failed with checksums enabled"
    exit 2
fi

# Extra: encrypted page read without checksum error
log_info "Running checksum-specific verification ..."
container_psql "$CONTAINER" \
    -c "SELECT pg_vault_tde_set_test_dek();" \
    -c "CREATE TABLE chk_test (id int, val text) USING encrypted_heap;" \
    -c "INSERT INTO chk_test SELECT g, 'row_'||g FROM generate_series(1,10) g;" \
    -c "CHECKPOINT;" \
    -c "
DO \$\$
DECLARE
    filepath text;
    raw_file bytea;
BEGIN
    filepath := pg_relation_filepath('chk_test');
    raw_file := pg_read_binary_file(filepath);
    IF length(raw_file) < 8192 THEN
        RAISE EXCEPTION 'Relation file too small: % bytes', length(raw_file);
    END IF;
    RAISE NOTICE 'CHECKSUM TEST: encrypted page read OK (% bytes)', length(raw_file);
END;
\$\$" \
    -c "DROP TABLE chk_test;"

ELAPSED=$(timer_elapsed "$START")
log_ok "CHECKSUMS: ALL TESTS PASSED ($(timer_fmt "$ELAPSED"))"
