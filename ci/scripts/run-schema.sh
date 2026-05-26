#!/usr/bin/env bash
# ci/scripts/run-schema.sh — Multi-database and multi-schema regression tests
#
# Starts a standalone pg-test container and runs regression_test_schema.sql,
# which verifies that pg_vault_tde works correctly when:
#   - The extension is installed in a non-default database (tde_schema_test)
#   - Tables are created in a non-public schema (private_tde)
#   - search_path contains only the custom schema
#   - Multiple schemas coexist in the same database
#
# Tests SCHEMA-1 through SCHEMA-20 are covered.
#
# Exit code: 0 on success, 2 on test failure.
#
# Usage:
#   bash ci/scripts/run-schema.sh
#   make ci-schema
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-schema-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "SCHEMA REGRESSION TESTS (20 tests — new DB + custom schema)"

build_pg_test_image

start_pg_container "$CONTAINER" "${PG_SCHEMA_PORT:-15440}"

# Verify extension is loadable in the default database first
log_info "Verifying pg_vault_tde extension in default DB ..."
container_psql "$CONTAINER" -c \
    "SELECT extname, extversion FROM pg_extension WHERE extname = 'pg_vault_tde';"

# Copy schema regression SQL into the container
log_info "Copying regression_test_schema.sql into container ..."
$RT cp "$REPO_ROOT/sql/regression_test_schema.sql" \
       "$CONTAINER:/tmp/regression_test_schema.sql"

# Run the schema regression tests
#
# regression_test_schema.sql creates a new database (tde_schema_test),
# connects to it (\c), runs 20 tests, then drops the database and
# reconnects to postgres.  The -d postgres start database is required
# so that \c tde_schema_test succeeds from within the script.
log_info "Running schema regression tests (SCHEMA-1 through SCHEMA-20) ..."
START=$(timer_start)
if container_psql "$CONTAINER" -d postgres -v ON_ERROR_STOP=1 \
        -f /tmp/regression_test_schema.sql; then
    ELAPSED=$(timer_elapsed "$START")
    log_ok "SCHEMA REGRESSION: ALL 20 TESTS PASSED ($(timer_fmt "$ELAPSED"))"
else
    ELAPSED=$(timer_elapsed "$START")
    log_error "SCHEMA REGRESSION: FAILED after $(timer_fmt "$ELAPSED")"
    $RT logs "$CONTAINER" --tail 80 2>/dev/null || true
    exit 2
fi

log_ok "SCHEMA REGRESSION COMPLETE: SCHEMA-1 through SCHEMA-20 all passed"
exit 0
