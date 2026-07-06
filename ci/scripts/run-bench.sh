#!/usr/bin/env bash
# ci/scripts/run-bench.sh — Performance benchmark: encrypted_heap vs plain heap
#
# Self-contained benchmark that spins up a pg-tde-test container, opens the
# local wallet, and measures encrypted_heap vs plain heap across multiple
# operation types and row-width profiles.  Results are printed as formatted
# tables and written as JSON to /tmp/bench_results.json for CI artifacts.
#
# Three-way decomposition (per operation):
#   plain_heap   — stock heap AM (baseline)
#   passthrough  — encrypted_heap with pg_vault_tde.enabled = off
#                  (TAM dispatch + tuple copy, NO AES, NO 37-byte wire trailer)
#   encrypted    — encrypted_heap with AES-256-GCM + v4 wire format
# So:  passthrough − plain  ≈ TAM wrapper cost
#      encrypted   − passthrough ≈ AES-GCM + wire-size cost
#
# Row-width profiles (BENCH_PROFILES) expose the fixed 37-byte/tuple wire
# overhead: it dominates on tiny rows and amortises on wide rows.
#
# Methodology notes:
#   * Reads use EXPLAIN (ANALYZE, TIMING OFF) — server-side total execution
#     time WITHOUT per-tuple gettimeofday instrumentation, which otherwise
#     inflates absolute times and distorts the encrypted/plain ratio.
#   * Per-query GUCs (jit, parallelism, scan method) are issued INLINE in the
#     same psql -c session as the measured statement; a separate `psql -c "SET"`
#     would not survive into the next connection.
#   * INSERT is measured by client wall-clock (what an application observes).
#
# Environment variables:
#   BENCH_ROWS          — rows per INSERT (default: 200000)
#   BENCH_WARMUP        — warm-up rows before timing (default: 10000)
#   BENCH_ITERATIONS    — timing repetitions per measurement (default: 5)
#   BENCH_PROFILES      — space-separated row profiles (default: "tiny oltp wide")
#   BENCH_THRESHOLD_PCT — max acceptable avg overhead % before WARN (default: 100)
#   TDE_SKIP_PASSTHROUGH— set to 1 to skip pass-through baseline (default: 0)
#   PG_BENCH_PORT       — host port for the bench container (default: 15435)
#
# Exit codes:
#   0  — benchmark completed (avg overhead within threshold)
#   6  — failed to start container or psql error
#   7  — avg overhead exceeded BENCH_THRESHOLD_PCT (non-fatal in run-all.sh)
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

set -euo pipefail

# Force C locale: awk/printf must emit '.' as the decimal separator, otherwise
# a locale like it_IT produces "80,5" and corrupts the emitted JSON numbers.
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-bench-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "PERFORMANCE BENCHMARK"

ROWS="${BENCH_ROWS:-200000}"
WARMUP="${BENCH_WARMUP:-10000}"
ITERATIONS="${BENCH_ITERATIONS:-5}"
PROFILES="${BENCH_PROFILES:-tiny oltp wide}"
THRESHOLD="${BENCH_THRESHOLD_PCT:-100}"
SKIP_PASSTHROUGH="${TDE_SKIP_PASSTHROUGH:-0}"
BENCH_JSON="/tmp/bench_results.json"

# Payload expression per profile: the `data text` column for row `g`.
#   tiny ≈ 32 B  | oltp ≈ 256 B | wide ≈ 512 B
profile_payload() {
    case "$1" in
        tiny) echo "md5(g::text)" ;;
        oltp) echo "rpad(md5(g::text), 256, 'abc')" ;;
        wide) echo "rpad(md5(g::text), 512, 'abc')" ;;
        *)    echo "md5(g::text)" ;;   # unknown profile → tiny payload
    esac
}

build_pg_test_image

log_info "Starting benchmark container (rows=$ROWS, warmup=$WARMUP, iter=$ITERATIONS, profiles='$PROFILES') ..."

$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run --rm -d \
    --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    -p "${PG_BENCH_PORT:-15435}:5432" \
    "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
    postgres \
    -c "shared_preload_libraries=pg_vault_tde" \
    -c "pg_vault_tde.kms_provider=local" \
    -c "pg_vault_tde.wallet_passphrase_command=echo tde_bench_test" \
    -c "pg_vault_tde.dev_mode=on" \
    -c "log_min_messages=warning" \
    -c "pg_vault_tde.wallet_auto_open=off"

wait_pg_ready "$CONTAINER"

# Helper: run SQL inside the container as postgres user
run_sql() {
    $RT exec -u postgres "$CONTAINER" psql -qAt -U postgres "$@"
}

# Setup: extension + wallet
run_sql -c "CREATE EXTENSION IF NOT EXISTS pg_vault_tde;"
run_sql -c "SELECT pg_vault_tde_wallet_init('tde_bench_test');"

# Create bench tables (data column is reseeded per profile)
run_sql -c "
    DROP TABLE IF EXISTS bench_plain, bench_enc;
    CREATE TABLE bench_plain (id bigint PRIMARY KEY, data text NOT NULL);
    CREATE TABLE bench_enc   (id bigint PRIMARY KEY, data text NOT NULL)
        USING encrypted_heap;
"

log_info "Warming up with $WARMUP rows ..."
run_sql -c "
    INSERT INTO bench_plain SELECT g, md5(g::text) FROM generate_series(1,${WARMUP}) g;
    INSERT INTO bench_enc   SELECT g, md5(g::text) FROM generate_series(1,${WARMUP}) g;
    TRUNCATE bench_plain;
    TRUNCATE bench_enc;
" > /dev/null

# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------
# Deterministic, low-noise execution: no JIT, no parallel workers.  These are
# prepended INLINE so they apply to the measured statement in the same session.
GUC_BASE="SET jit=off; SET max_parallel_workers_per_gather=0;"

# avg_ms PRELUDE SQL — average server-side Execution Time (ms) over ITERATIONS.
# Uses TIMING OFF so per-tuple gettimeofday does not distort the result.
avg_ms() {
    local prelude="$1"
    local sql="$2"
    local total=0
    local i
    for (( i=0; i<ITERATIONS; i++ )); do
        local ms
        ms=$(run_sql -c "${GUC_BASE} ${prelude} EXPLAIN (ANALYZE, TIMING OFF, SUMMARY ON, FORMAT TEXT) ${sql}" \
            | grep -E "^Execution Time:" | awk '{print $3}')
        total=$(awk -v t="$total" -v m="$ms" 'BEGIN{printf "%.3f", t+m}')
    done
    awk -v t="$total" -v n="$ITERATIONS" 'BEGIN{printf "%.2f", t/n}'
}

# avg_insert_ms TABLE ROWS PAYLOAD — client wall-clock INSERT time (ms), averaged.
avg_insert_ms() {
    local tbl="$1"
    local rows="$2"
    local payload="$3"
    local total=0
    local i
    for (( i=0; i<ITERATIONS; i++ )); do
        run_sql -c "TRUNCATE ${tbl};" > /dev/null
        local start_us end_us
        start_us=$(date +%s%N)
        run_sql -c "INSERT INTO ${tbl} SELECT g, ${payload} FROM generate_series(1,${rows}) g;" \
            > /dev/null
        end_us=$(date +%s%N)
        local ms
        ms=$(awk -v s="$start_us" -v e="$end_us" 'BEGIN{printf "%.2f", (e-s)/1000000}')
        total=$(awk -v t="$total" -v m="$ms" 'BEGIN{printf "%.3f", t+m}')
    done
    awk -v t="$total" -v n="$ITERATIONS" 'BEGIN{printf "%.2f", t/n}'
}

# overhead_num PLAIN ENC — signed numeric overhead "%" (no sign char), or "null".
overhead_num() {
    awk -v p="$1" -v e="$2" \
        'BEGIN { if (p+0 > 0) printf "%.1f", (e-p)/p*100; else print "null" }'
}

# fmt_pct NUM — display "+X.X%" / "-X.X%" / "N/A" from a numeric (or "null").
fmt_pct() {
    awk -v v="$1" 'BEGIN {
        if (v == "null" || v == "") { print "N/A"; }
        else { printf "%+.1f%%\n", v+0; }
    }'
}

# ---------------------------------------------------------------------------
# Per-profile run: fills global *_p / *_e / *_pt result variables.
# ---------------------------------------------------------------------------
run_profile() {
    local prof="$1"
    local payload; payload="$(profile_payload "$prof")"

    log_info "=== Profile '$prof' (payload: ${payload}) ==="

    # --- INSERT (wall-clock) ---
    log_info "  INSERT ($ROWS rows) ..."
    ins_p=$(avg_insert_ms bench_plain "$ROWS" "$payload")
    ins_e=$(avg_insert_ms bench_enc   "$ROWS" "$payload")

    # Reseed both tables for the read/update benchmarks.
    run_sql -c "
        TRUNCATE bench_plain; TRUNCATE bench_enc;
        INSERT INTO bench_plain SELECT g, ${payload} FROM generate_series(1,${ROWS}) g;
        INSERT INTO bench_enc   SELECT g, ${payload} FROM generate_series(1,${ROWS}) g;
        ANALYZE bench_plain; ANALYZE bench_enc;
    " > /dev/null

    # --- SELECT seq scan (force seqscan in-session) ---
    log_info "  SELECT seq scan ..."
    local seq_prelude="SET enable_indexscan=off; SET enable_bitmapscan=off; SET enable_indexonlyscan=off;"
    seq_p=$(avg_ms "$seq_prelude" "SELECT count(*) FROM bench_plain")
    seq_e=$(avg_ms "$seq_prelude" "SELECT count(*) FROM bench_enc")

    # --- UPDATE (10% of rows) ---
    log_info "  UPDATE (10% rows) ..."
    upd_p=$(avg_ms "" "UPDATE bench_plain SET data = md5(data) WHERE id % 10 = 0")
    upd_e=$(avg_ms "" "UPDATE bench_enc   SET data = md5(data) WHERE id % 10 = 0")

    # --- INDEX SCAN (PK point lookup, force index in-session) ---
    log_info "  INDEX SCAN (pk lookup) ..."
    local rid=$(( RANDOM % ROWS + 1 ))
    local idx_prelude="SET enable_seqscan=off;"
    idx_p=$(avg_ms "$idx_prelude" "SELECT data FROM bench_plain WHERE id = ${rid}")
    idx_e=$(avg_ms "$idx_prelude" "SELECT data FROM bench_enc   WHERE id = ${rid}")

    # --- TABLESAMPLE SYSTEM (1%) ---
    log_info "  TABLESAMPLE 1% ..."
    smp_p=$(avg_ms "" "SELECT count(*) FROM bench_plain TABLESAMPLE SYSTEM (1)")
    smp_e=$(avg_ms "" "SELECT count(*) FROM bench_enc   TABLESAMPLE SYSTEM (1)")

    # --- Pass-through baseline (enabled=off): TAM cost without AES/wire ---
    ins_pt="null"; seq_pt="null"; upd_pt="null"
    if [[ "$SKIP_PASSTHROUGH" != "1" ]]; then
        log_info "  Pass-through baseline (enabled=off) ..."
        run_sql -c "ALTER SYSTEM SET pg_vault_tde.enabled = off;" > /dev/null
        $RT restart "$CONTAINER" > /dev/null 
        wait_pg_ready "$CONTAINER"

        ins_pt=$(avg_insert_ms bench_enc "$ROWS" "$payload")
        run_sql -c "
            TRUNCATE bench_enc;
            INSERT INTO bench_enc SELECT g, ${payload} FROM generate_series(1,${ROWS}) g;
            ANALYZE bench_enc;
        " > /dev/null
        seq_pt=$(avg_ms "$seq_prelude" "SELECT count(*) FROM bench_enc")
        upd_pt=$(avg_ms "" "UPDATE bench_enc SET data = md5(data) WHERE id % 10 = 0")

        run_sql -c "ALTER SYSTEM SET pg_vault_tde.enabled = on;" > /dev/null
        $RT restart "$CONTAINER" > /dev/null
        wait_pg_ready "$CONTAINER"
    fi
}

# ---------------------------------------------------------------------------
# Print one profile's result tables.
# ---------------------------------------------------------------------------
print_profile_tables() {
    local prof="$1"

    echo ""
    echo "--- Profile: ${prof} ---"
    printf "  %-24s  %-12s  %-14s  %-10s\n" \
        "Operation" "plain_heap" "encrypted" "overhead"
    printf "  %-24s  %-12s  %-14s  %-10s\n" \
        "────────────────────────" "────────────" "──────────────" "──────────"
    printf "  %-24s  %-12s  %-14s  %-10s\n" \
        "INSERT ${ROWS} rows" "${ins_p}ms" "${ins_e}ms" "$(fmt_pct "$(overhead_num "$ins_p" "$ins_e")")"
    printf "  %-24s  %-12s  %-14s  %-10s\n" \
        "SELECT seq scan" "${seq_p}ms" "${seq_e}ms" "$(fmt_pct "$(overhead_num "$seq_p" "$seq_e")")"
    printf "  %-24s  %-12s  %-14s  %-10s\n" \
        "UPDATE (10% rows)" "${upd_p}ms" "${upd_e}ms" "$(fmt_pct "$(overhead_num "$upd_p" "$upd_e")")"
    printf "  %-24s  %-12s  %-14s  %-10s\n" \
        "INDEX SCAN (pk)" "${idx_p}ms" "${idx_e}ms" "$(fmt_pct "$(overhead_num "$idx_p" "$idx_e")")"
    printf "  %-24s  %-12s  %-14s  %-10s\n" \
        "TABLESAMPLE 1%" "${smp_p}ms" "${smp_e}ms" "$(fmt_pct "$(overhead_num "$smp_p" "$smp_e")")"

    if [[ "$SKIP_PASSTHROUGH" != "1" ]]; then
        echo ""
        echo "    decomposition (TAM vs AES+wire):"
        printf "    %-22s  %-14s  %-14s\n" "Operation" "TAM (pt−plain)" "crypto (enc−pt)"
        printf "    %-22s  %-14s  %-14s\n" \
            "INSERT" "$(fmt_pct "$(overhead_num "$ins_p" "$ins_pt")")" "$(fmt_pct "$(overhead_num "$ins_pt" "$ins_e")")"
        printf "    %-22s  %-14s  %-14s\n" \
            "SELECT seq scan" "$(fmt_pct "$(overhead_num "$seq_p" "$seq_pt")")" "$(fmt_pct "$(overhead_num "$seq_pt" "$seq_e")")"
        printf "    %-22s  %-14s  %-14s\n" \
            "UPDATE" "$(fmt_pct "$(overhead_num "$upd_p" "$upd_pt")")" "$(fmt_pct "$(overhead_num "$upd_pt" "$upd_e")")"
    fi
}

# ---------------------------------------------------------------------------
# Emit one profile's JSON object (numbers only; "null" stays a JSON null).
# ---------------------------------------------------------------------------
profile_json() {
    local prof="$1"
    cat <<EOF
    {
      "profile": "${prof}",
      "insert":      { "plain_ms": ${ins_p}, "enc_ms": ${ins_e}, "passthrough_ms": ${ins_pt}, "overhead_pct": $(overhead_num "$ins_p" "$ins_e") },
      "seqscan":     { "plain_ms": ${seq_p}, "enc_ms": ${seq_e}, "passthrough_ms": ${seq_pt}, "overhead_pct": $(overhead_num "$seq_p" "$seq_e") },
      "update":      { "plain_ms": ${upd_p}, "enc_ms": ${upd_e}, "passthrough_ms": ${upd_pt}, "overhead_pct": $(overhead_num "$upd_p" "$upd_e") },
      "index_scan":  { "plain_ms": ${idx_p}, "enc_ms": ${idx_e}, "overhead_pct": $(overhead_num "$idx_p" "$idx_e") },
      "tablesample": { "plain_ms": ${smp_p}, "enc_ms": ${smp_e}, "overhead_pct": $(overhead_num "$smp_p" "$smp_e") }
    }
EOF
}

# ---------------------------------------------------------------------------
# Run all profiles, collect output + JSON, track global average overhead.
# ---------------------------------------------------------------------------
echo ""
echo "=== pg_vault_tde Performance Benchmark ==="
printf "  Rows: %s | Warmup: %s | Iterations: %d | Date: %s\n" \
    "$ROWS" "$WARMUP" "$ITERATIONS" "$(date '+%Y-%m-%d %H:%M')"

json_objects=""
ovh_accum=0          # running sum of INSERT/SEQSCAN/UPDATE overheads
ovh_count=0

for prof in $PROFILES; do
    run_profile "$prof"
    print_profile_tables "$prof"

    [[ -n "$json_objects" ]] && json_objects="${json_objects},"
    json_objects="${json_objects}
$(profile_json "$prof")"

    # Accumulate the three write/scan overheads for the headline average.
    read -r add cnt < <(awk \
        -v pi="$ins_p" -v ei="$ins_e" \
        -v ps="$seq_p" -v es="$seq_e" \
        -v pu="$upd_p" -v eu="$upd_e" \
        'BEGIN {
            t=0; n=0;
            if (pi+0>0){ t+=(ei-pi)/pi*100; n++ }
            if (ps+0>0){ t+=(es-ps)/ps*100; n++ }
            if (pu+0>0){ t+=(eu-pu)/pu*100; n++ }
            printf "%.4f %d\n", t, n
        }')
    ovh_accum=$(awk -v a="$ovh_accum" -v b="$add" 'BEGIN{printf "%.4f", a+b}')
    ovh_count=$(( ovh_count + cnt ))
done

avg_ovh=$(awk -v t="$ovh_accum" -v n="$ovh_count" \
    'BEGIN { if (n>0) printf "%.1f", t/n; else print "null" }')

echo ""
printf "  Average overhead across profiles (INSERT/SELECT/UPDATE): %s\n" "$(fmt_pct "$avg_ovh")"
echo "  Note: v4 wire format adds 37 bytes/tuple (IV 12 + TAG 16 + VERSION 1 + GEN 8)."
echo "  The 'crypto (enc−pt)' column isolates AES-GCM + wire-size cost from TAM dispatch."
echo ""

# ---------------------------------------------------------------------------
# Write JSON results for artifact collection
# ---------------------------------------------------------------------------
cat > "$BENCH_JSON" <<ENDJSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rows": $ROWS,
  "warmup": $WARMUP,
  "iterations": $ITERATIONS,
  "profiles_run": "$PROFILES",
  "skip_passthrough": $([[ "$SKIP_PASSTHROUGH" == "1" ]] && echo true || echo false),
  "results": [${json_objects}
  ],
  "avg_overhead_pct": ${avg_ovh},
  "threshold_pct": $THRESHOLD
}
ENDJSON
log_info "Results written to $BENCH_JSON"

# ---------------------------------------------------------------------------
# Threshold check (non-fatal: exit 7 signals WARN in run-all.sh)
# ---------------------------------------------------------------------------
RC=0
if [[ "$avg_ovh" != "null" ]] && \
   awk -v avg="$avg_ovh" -v thr="$THRESHOLD" 'BEGIN { exit (avg+0 > thr+0) ? 0 : 1 }'; then
    log_warn "Average overhead $(fmt_pct "$avg_ovh") exceeds threshold ${THRESHOLD}% (non-fatal)"
    RC=7
else
    log_ok "Average overhead $(fmt_pct "$avg_ovh") is within ${THRESHOLD}% threshold"
fi

echo ""
echo "=== Benchmark complete ==="
exit $RC
