#!/usr/bin/env bash
# ci/scripts/run-ubsan.sh — Run the regression + error-path suites with
# pg_vault_tde compiled under UndefinedBehaviorSanitizer.
#
# The cheapest of the deep-checking stages: UBSan instruments only our objects,
# so the server is the ordinary packaged binary and no PostgreSQL source build
# is involved.  It sees a different bug class from valgrind — not memory
# ownership, but operations the C standard leaves undefined and that a compiler
# is free to miscompile:
#
#   - signed integer overflow in length/offset arithmetic
#   - shift counts >= the width of the type (wire-format packing)
#   - misaligned loads (on-disk tuple headers, TOAST pointers)
#   - pointer arithmetic that leaves the underlying object
#   - passing NULL where a function is declared nonnull (memcpy of a
#     zero-length payload, e.g. an all-NULL tuple)
#
# Exit code: 0 clean, 11 on UBSan reports or workload failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# lib.sh sets -e; this script checks exit codes explicitly.
set +e

UB_IMAGE="${PG_UBSAN_IMAGE:-pg-tde-ubsan}"
OUT_DIR="${UBSAN_OUT_DIR:-$REPO_ROOT/tmp_ubsan}"
CONTAINERS=()

cleanup() { for c in "${CONTAINERS[@]}"; do $RT rm -f "$c" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT

log_stage "UBSAN (undefined behaviour)"

log_info "Building $UB_IMAGE (extension with -fsanitize=undefined) ..."
$RT build \
    --build-arg PG_MAJOR="${PG_VERSION:-${PG_MAJOR:-18}}" \
    -f "$CI_DIR/containers/pg-ubsan.Containerfile" \
    -t "$UB_IMAGE:latest" \
    "$REPO_ROOT" 2>&1 | tail -3
# With set +e a failed build would go unnoticed, and the stage run on the
# previous image.
[ "${PIPESTATUS[0]}" -eq 0 ] || { log_error "UBSAN: image build failed"; exit 11; }
log_ok "Image $UB_IMAGE built"

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/ubsan.* "$OUT_DIR/reports.txt"
RC=0

# Each suite gets its own container.  They initialise the local wallet with
# different passphrases, and wallet_init() refuses to overwrite an existing
# wallet file — sharing one container makes the second suite fail on setup
# rather than on anything UBSan found.
run_suite() {            # $1 = label, $2 = sql file, $3 = stop-on-error
    local label="$1" sqlfile="$2" strict="$3"
    local c="pg-tde-ubsan-${label}-$$"
    CONTAINERS+=("$c")

    $RT rm -f "$c" 2>/dev/null || true
    $RT run --rm -d --name "$c" -e POSTGRES_PASSWORD=postgres "$UB_IMAGE:latest" \
        postgres \
            -c "shared_preload_libraries=pg_vault_tde" \
            -c "pg_vault_tde.dev_mode=on" \
            -c "pg_vault_tde.kms_provider=local" \
            -c "pg_vault_tde.wallet_auto_open=off" \
            -c "log_min_messages=warning" >/dev/null
    wait_pg_ready "$c" >/dev/null 2>&1

    if ! container_psql "$c" -v ON_ERROR_STOP=1 -c \
            "CREATE EXTENSION IF NOT EXISTS pg_vault_tde;" >/dev/null 2>&1; then
        log_error "UBSAN [$label]: CREATE EXTENSION failed (is libubsan1 present?)"
        $RT logs "$c" --tail 30 2>/dev/null || true
        RC=1; return
    fi

    $RT cp "$REPO_ROOT/$sqlfile" "$c:/tmp/suite.sql"
    log_info "Running $label ..."
    if [ "$strict" = "strict" ]; then
        if ! container_psql "$c" -v ON_ERROR_STOP=1 -f /tmp/suite.sql >/dev/null 2>&1; then
            log_error "UBSAN [$label]: suite failed under instrumentation"
            container_psql "$c" -v ON_ERROR_STOP=1 -f /tmp/suite.sql 2>&1 | tail -20
            RC=1
        else
            log_ok "UBSAN [$label]: suite passed"
        fi
    else
        container_psql "$c" -f /tmp/suite.sql >/dev/null 2>&1
        log_ok "UBSAN [$label]: workload finished"
    fi

    # UBSAN_OPTIONS=log_path writes one file per pid; reports can also reach
    # stderr, which for a backend means the server log.
    $RT cp "$c:/tmp/ubsan" "$OUT_DIR/" 2>/dev/null || true
    $RT logs "$c" 2>&1 | grep -A6 "runtime error:" >> "$OUT_DIR/reports.txt" 2>/dev/null
    $RT rm -f "$c" >/dev/null 2>&1 || true
}

run_suite workload  sql/valgrind_workload.sql          loose
run_suite errorpath sql/regression_test_errorpath.sql  strict

# ── Collect ──────────────────────────────────────────────────────────────
# UBSAN_OPTIONS=log_path writes one file per pid; reports can also land on
# stderr, which for a backend means the server log.
find "$OUT_DIR" -name 'ubsan.*' -exec mv -t "$OUT_DIR" {} + 2>/dev/null || true
REPORTS="$OUT_DIR/reports.txt"
cat "$OUT_DIR"/ubsan.* >> "$REPORTS" 2>/dev/null
touch "$REPORTS"

# Only count reports naming our sources: an instrumented .so can still be
# blamed for a macro expanded from a PostgreSQL header.
N=$(grep -c "runtime error:" "$REPORTS" 2>/dev/null || true); N=${N:-0}
OURS=$(grep "runtime error:" "$REPORTS" 2>/dev/null | grep -c "pg_vault_tde" || true); OURS=${OURS:-0}

echo ""
log_info "── UBSan summary ────────────────────────────────────────────"
printf "    %-34s %s\n" "runtime errors (total)"        "$N"
printf "    %-34s %s\n" "naming a pg_vault_tde source"  "$OURS"
if [ "$N" -gt 0 ]; then
    grep "runtime error:" "$REPORTS" | sed 's/^/      /' | sort | uniq -c | sort -rn | head -20
fi
echo ""

if [ "$N" -gt 0 ]; then
    log_error "UBSAN: $N undefined-behaviour report(s)"
    log_error "Full reports: ${REPORTS#"$REPO_ROOT"/}"
    exit 11
fi

[ "$RC" -ne 0 ] && { log_error "UBSAN: workload failed under instrumentation"; exit 11; }

log_ok "UBSAN: no undefined behaviour reported"
exit 0
