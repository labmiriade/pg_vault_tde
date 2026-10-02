#!/usr/bin/env bash
# ci/scripts/run-asan.sh — Run the regression workload and the error-path
# suite with pg_vault_tde compiled under AddressSanitizer (PSQLE-181).
#
# The same two suites as run-ubsan.sh, in a stage of its own.  ASan's runtime
# is LD_PRELOADed into the stock server (see ci/containers/pg-asan.Containerfile
# for what it can and cannot see), and reports:
#
#   - reads and writes past malloc'd buffers — OpenSSL, libcurl, libc — past a
#     stack array or a global
#   - use after free and double free of the same
#
# A clean report means something only if ASan was there to report: the build
# checks that the module calls into ASan, and every suite first checks, from a
# backend, that the runtime is mapped.  A failed image build stops the stage
# rather than letting it run on an older image.
#
# Exit code: 0 clean, 12 on ASan reports, a failed build or workload.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# lib.sh sets -e; this script checks exit codes explicitly.
set +e

AS_IMAGE="${PG_ASAN_IMAGE:-pg-tde-asan}"
OUT_DIR="${ASAN_OUT_DIR:-$REPO_ROOT/tmp_asan}"
CONTAINERS=()

cleanup() { for c in "${CONTAINERS[@]}"; do $RT rm -f "$c" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT

log_stage "ASAN (memory errors)"

log_info "Building $AS_IMAGE (extension with -fsanitize=address) ..."
BUILD_LOG=$(mktemp)
$RT build \
    --build-arg PG_MAJOR="${PG_VERSION:-${PG_MAJOR:-18}}" \
    -f "$CI_DIR/containers/pg-asan.Containerfile" \
    -t "$AS_IMAGE:latest" \
    "$REPO_ROOT" > "$BUILD_LOG" 2>&1
BUILD_RC=$?
tail -3 "$BUILD_LOG"
if [ "$BUILD_RC" -ne 0 ]; then
    tail -30 "$BUILD_LOG"
    rm -f "$BUILD_LOG"
    log_error "ASAN: image build failed"
    exit 12
fi
rm -f "$BUILD_LOG"
log_ok "Image $AS_IMAGE built"

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/asan.* "$OUT_DIR/reports.txt"
RC=0

# Each suite gets its own container, as in run-ubsan.sh: they initialise the
# local wallet with different passphrases.
run_suite() {            # $1 = label, $2 = sql file, $3 = stop-on-error
    local label="$1" sqlfile="$2" strict="$3"
    local c="pg-tde-asan-${label}-$$"
    local mapped
    CONTAINERS+=("$c")

    $RT rm -f "$c" 2>/dev/null || true
    $RT run --rm -d --name "$c" -e POSTGRES_PASSWORD=postgres "$AS_IMAGE:latest" \
        postgres \
            -c "shared_preload_libraries=pg_vault_tde" \
            -c "pg_vault_tde.dev_mode=on" \
            -c "pg_vault_tde.kms_provider=local" \
            -c "pg_vault_tde.wallet_auto_open=off" \
            -c "log_min_messages=warning" >/dev/null
    wait_pg_ready "$c" >/dev/null 2>&1

    if ! container_psql "$c" -v ON_ERROR_STOP=1 -c \
            "CREATE EXTENSION IF NOT EXISTS pg_vault_tde;" >/dev/null 2>&1; then
        log_error "ASAN [$label]: CREATE EXTENSION failed"
        $RT logs "$c" --tail 30 2>/dev/null || true
        RC=1; return
    fi

    # The backend reads its own mappings: ASan's runtime and the module must
    # both be there, or a clean report would mean nothing.
    mapped=$(container_psql "$c" -tAc "
        SELECT count(*) FILTER (WHERE l ~ 'libasan') || ',' ||
               count(*) FILTER (WHERE l ~ 'pg_vault_tde')
        FROM regexp_split_to_table(pg_read_file('/proc/self/maps'), E'\\n') l" 2>/dev/null)
    case "$mapped" in
        0,*|*,0|"")
            log_error "ASAN [$label]: runtime or module not mapped in the backend ($mapped)"
            RC=1; return ;;
    esac

    $RT cp "$REPO_ROOT/$sqlfile" "$c:/tmp/suite.sql"
    log_info "Running $label ..."
    if [ "$strict" = "strict" ]; then
        if ! container_psql "$c" -v ON_ERROR_STOP=1 -f /tmp/suite.sql >/dev/null 2>&1; then
            log_error "ASAN [$label]: suite failed under instrumentation"
            container_psql "$c" -v ON_ERROR_STOP=1 -f /tmp/suite.sql 2>&1 | tail -20
            RC=1
        else
            log_ok "ASAN [$label]: suite passed"
        fi
    else
        container_psql "$c" -f /tmp/suite.sql >/dev/null 2>&1
        log_ok "ASAN [$label]: workload finished"
    fi

    # ASAN_OPTIONS=log_path writes one file per pid; reports can also reach
    # stderr, which for a backend means the server log.
    $RT cp "$c:/tmp/asan" "$OUT_DIR/" 2>/dev/null || true
    $RT logs "$c" 2>&1 | grep -A30 "ERROR: AddressSanitizer" >> "$OUT_DIR/reports.txt" 2>/dev/null
    $RT rm -f "$c" >/dev/null 2>&1 || true
}

run_suite workload  sql/valgrind_workload.sql          loose
run_suite errorpath sql/regression_test_errorpath.sql  strict

# ── Collect ──────────────────────────────────────────────────────────────
find "$OUT_DIR" -name 'asan.*' -exec mv -t "$OUT_DIR" {} + 2>/dev/null || true
REPORTS="$OUT_DIR/reports.txt"
cat "$OUT_DIR"/asan.* >> "$REPORTS" 2>/dev/null
touch "$REPORTS"

N=$(grep -c "ERROR: AddressSanitizer" "$REPORTS" 2>/dev/null || true); N=${N:-0}

echo ""
log_info "── ASan summary ─────────────────────────────────────────────"
printf "    %-34s %s\n" "memory errors" "$N"
if [ "$N" -gt 0 ]; then
    grep -E "ERROR: AddressSanitizer|^ *#[0-3] " "$REPORTS" | sed 's/^/      /' | head -40
fi
echo ""

if [ "$N" -gt 0 ]; then
    log_error "ASAN: $N memory error report(s)"
    log_error "Full reports: ${REPORTS#"$REPO_ROOT"/}"
    exit 12
fi

[ "$RC" -ne 0 ] && { log_error "ASAN: workload failed under instrumentation"; exit 12; }

log_ok "ASAN: no memory error reported"
exit 0
