#!/usr/bin/env bash
# ci/scripts/run-bench.sh — Performance benchmark: encrypted_heap vs plain heap
#
# Self-contained benchmark that spins up a pg-tde-test container, injects
# the test DEK, and measures encrypted_heap vs plain heap across multiple
# operation types.  Results are printed as a formatted table and written as
# JSON to /tmp/bench_results.json for downstream CI artifact collection.
#
# Environment variables:
#   BENCH_ROWS          — rows to INSERT (default: 100000)
#   BENCH_WARMUP        — warm-up rows before timing (default: 10000)
#   BENCH_ITERATIONS    — number of timing repetitions (default: 3)
#   BENCH_THRESHOLD_PCT — max acceptable overhead % before WARN (default: 15)
#   TDE_SKIP_PASSTHROUGH— set to 1 to skip pass-through baseline (default: 0)
#   PG_BENCH_PORT       — host port for the bench container (default: 15435)
#
# Exit codes:
#   0  — benchmark completed (results within threshold or threshold check disabled)
#   6  — failed to start container or psql error
#   7  — overhead exceeded BENCH_THRESHOLD_PCT (non-fatal in run-all.sh)
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-bench-$$"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "PERFORMANCE BENCHMARK"

ROWS="${BENCH_ROWS:-1000000}"
WARMUP="${BENCH_WARMUP:-10000}"
ITERATIONS="${BENCH_ITERATIONS:-10}"
THRESHOLD="${BENCH_THRESHOLD_PCT:-400}"
SKIP_PASSTHROUGH="${TDE_SKIP_PASSTHROUGH:-0}"
DEK_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
BENCH_JSON="/tmp/bench_results.json"

build_pg_test_image

log_info "Starting benchmark container (rows=$ROWS, warmup=$WARMUP, iter=$ITERATIONS) ..."

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
    -c "log_min_messages=warning"

wait_pg_ready "$CONTAINER"

# Helper: run SQL inside the container as postgres user
run_sql() {
    $RT exec -u postgres "$CONTAINER" psql -qAt -U postgres "$@"
}

# Setup: extension + DEK
run_sql -c "CREATE EXTENSION IF NOT EXISTS pg_vault_tde;"
run_sql -c "SELECT pg_vault_tde_wallet_init('tde_bench_test');"

# Create bench tables
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
# Timing helpers (run inside container via EXPLAIN ANALYZE)
# ---------------------------------------------------------------------------

# avg_ms LABEL SQL — returns average Execution Time across ITERATIONS
avg_ms() {
    local label="$1"
    local sql="$2"
    local total=0
    local i
    for (( i=0; i<ITERATIONS; i++ )); do
        local ms
        ms=$(run_sql -c "EXPLAIN (ANALYZE, TIMING, FORMAT TEXT) ${sql}" \
            | grep -E "^Execution Time:" | awk '{print $3}')
        total=$(awk -v t="$total" -v m="$ms" 'BEGIN{printf "%.3f", t+m}')
    done
    awk -v t="$total" -v n="$ITERATIONS" 'BEGIN{printf "%.2f", t/n}'
}

# avg_insert_ms TABLE ROWS — measures INSERT with \timing-equivalent via wall clock
avg_insert_ms() {
    local tbl="$1"
    local rows="$2"
    local total=0
    local i
    for (( i=0; i<ITERATIONS; i++ )); do
        run_sql -c "TRUNCATE ${tbl};" > /dev/null
        local start_us end_us
        start_us=$(date +%s%N)
        run_sql -c "INSERT INTO ${tbl} SELECT g, md5(g::text) FROM generate_series(1,${rows}) g;" \
            > /dev/null
        end_us=$(date +%s%N)
        local ms
        ms=$(awk -v s="$start_us" -v e="$end_us" 'BEGIN{printf "%.2f", (e-s)/1000000}')
        total=$(awk -v t="$total" -v m="$ms" 'BEGIN{printf "%.3f", t+m}')
    done
    awk -v t="$total" -v n="$ITERATIONS" 'BEGIN{printf "%.2f", t/n}'
}

# overhead_pct PLAIN ENC — prints "+X.X%" or "N/A"
overhead_pct() {
    local plain="$1" enc="$2"
    awk -v p="$plain" -v e="$enc" '
        BEGIN {
            if (p+0 > 0) printf "+%.1f%%\n", (e-p)/p*100
            else          print "N/A"
        }
    '
}

# ---------------------------------------------------------------------------
# INSERT benchmark
# ---------------------------------------------------------------------------
log_info "Benchmarking INSERT ($ROWS rows) ..."
plain_insert=$(avg_insert_ms bench_plain "$ROWS")
enc_insert=$(avg_insert_ms bench_enc "$ROWS")

# Re-populate for read benchmarks (seed after INSERT bench)
run_sql -c "
    TRUNCATE bench_plain; TRUNCATE bench_enc;
    INSERT INTO bench_plain SELECT g, md5(g::text) FROM generate_series(1,${ROWS}) g;
    INSERT INTO bench_enc   SELECT g, md5(g::text) FROM generate_series(1,${ROWS}) g;
    ANALYZE bench_plain; ANALYZE bench_enc;
" > /dev/null

# ---------------------------------------------------------------------------
# SELECT sequential scan
# ---------------------------------------------------------------------------
log_info "Benchmarking SELECT seq scan ..."
run_sql -c "SET enable_indexscan = off; SET enable_bitmapscan = off;" > /dev/null || true
plain_seqscan=$(avg_ms "seqscan_plain" "SELECT count(*) FROM bench_plain")
enc_seqscan=$(avg_ms   "seqscan_enc"   "SELECT count(*) FROM bench_enc")

# ---------------------------------------------------------------------------
# UPDATE (10% of rows)
# ---------------------------------------------------------------------------
log_info "Benchmarking UPDATE (10% rows) ..."
plain_update=$(avg_ms "update_plain" \
    "UPDATE bench_plain SET data = md5(data) WHERE id % 10 = 0")
enc_update=$(avg_ms "update_enc" \
    "UPDATE bench_enc SET data = md5(data) WHERE id % 10 = 0")

# ---------------------------------------------------------------------------
# INDEX SCAN (single PK lookup)
# ---------------------------------------------------------------------------
log_info "Benchmarking INDEX SCAN ..."
RAND_ID=$(( RANDOM % ROWS + 1 ))
plain_idx=$(avg_ms "idx_plain" \
    "SELECT data FROM bench_plain WHERE id = ${RAND_ID}")
enc_idx=$(avg_ms "idx_enc" \
    "SELECT data FROM bench_enc WHERE id = ${RAND_ID}")

# ---------------------------------------------------------------------------
# TABLESAMPLE SYSTEM (1%)
# ---------------------------------------------------------------------------
log_info "Benchmarking TABLESAMPLE SYSTEM 1% ..."
plain_sample=$(avg_ms "sample_plain" \
    "SELECT count(*) FROM bench_plain TABLESAMPLE SYSTEM (1)")
enc_sample=$(avg_ms "sample_enc" \
    "SELECT count(*) FROM bench_enc TABLESAMPLE SYSTEM (1)")

# ---------------------------------------------------------------------------
# Pass-through baseline (GUC pg_vault_tde.enabled = off)
# Isolates pure TAM wrapper overhead from actual AES-256-GCM crypto cost.
# ---------------------------------------------------------------------------
pt_insert="N/A"
pt_seqscan="N/A"
pt_update="N/A"

if [[ "$SKIP_PASSTHROUGH" != "1" ]]; then
    log_info "Benchmarking pass-through baseline (enabled=off) ..."
    run_sql -c "ALTER SYSTEM SET pg_vault_tde.enabled = off;" > /dev/null
    run_sql -c "SELECT pg_reload_conf();" > /dev/null
    sleep 0.5

    pt_insert=$(avg_insert_ms bench_enc "$ROWS")
    run_sql -c "
        TRUNCATE bench_enc;
        INSERT INTO bench_enc SELECT g, md5(g::text) FROM generate_series(1,${ROWS}) g;
        ANALYZE bench_enc;
    " > /dev/null
    pt_seqscan=$(avg_ms "seqscan_pt" "SELECT count(*) FROM bench_enc")
    pt_update=$(avg_ms  "update_pt"  \
        "UPDATE bench_enc SET data = md5(data) WHERE id % 10 = 0")

    run_sql -c "ALTER SYSTEM SET pg_vault_tde.enabled = on;" > /dev/null
    run_sql -c "SELECT pg_reload_conf();" > /dev/null
fi

# ---------------------------------------------------------------------------
# Compute overhead percentages
# ---------------------------------------------------------------------------
ovh_insert=$(overhead_pct "$plain_insert"   "$enc_insert")
ovh_seqscan=$(overhead_pct "$plain_seqscan" "$enc_seqscan")
ovh_update=$(overhead_pct  "$plain_update"  "$enc_update")
ovh_idx=$(overhead_pct     "$plain_idx"     "$enc_idx")
ovh_sample=$(overhead_pct  "$plain_sample"  "$enc_sample")

avg_ovh=$(awk \
    -v pi="$plain_insert"   -v ei="$enc_insert" \
    -v ps="$plain_seqscan"  -v es="$enc_seqscan" \
    -v pu="$plain_update"   -v eu="$enc_update" \
    'BEGIN {
        total = 0; n = 0
        if (pi+0 > 0) { total += (ei-pi)/pi*100; n++ }
        if (ps+0 > 0) { total += (es-ps)/ps*100; n++ }
        if (pu+0 > 0) { total += (eu-pu)/pu*100; n++ }
        if (n > 0) printf "+%.1f\n", total/n
        else       print "N/A"
    }')

# ---------------------------------------------------------------------------
# Print summary table
# ---------------------------------------------------------------------------
echo ""
echo "=== pg_vault_tde Performance Benchmark ==="
echo ""
printf "  Rows: %-8s | Warmup: %-8s | Iterations: %d | Date: %s\n" \
    "$ROWS" "$WARMUP" "$ITERATIONS" "$(date '+%Y-%m-%d %H:%M')"
echo ""
printf "  %-28s  %-14s  %-16s  %-10s\n" \
    "Operation" "plain_heap" "encrypted_heap" "overhead"
printf "  %-28s  %-14s  %-16s  %-10s\n" \
    "────────────────────────────" "──────────────" "────────────────" "────────"
printf "  %-28s  %-14s  %-16s  %-10s\n" \
    "INSERT ${ROWS} rows" "${plain_insert}ms" "${enc_insert}ms" "$ovh_insert"
printf "  %-28s  %-14s  %-16s  %-10s\n" \
    "SELECT seq scan" "${plain_seqscan}ms" "${enc_seqscan}ms" "$ovh_seqscan"
printf "  %-28s  %-14s  %-16s  %-10s\n" \
    "UPDATE (10% rows)" "${plain_update}ms" "${enc_update}ms" "$ovh_update"
printf "  %-28s  %-14s  %-16s  %-10s\n" \
    "INDEX SCAN (pk lookup)" "${plain_idx}ms" "${enc_idx}ms" "$ovh_idx"
printf "  %-28s  %-14s  %-16s  %-10s\n" \
    "TABLESAMPLE 1%" "${plain_sample}ms" "${enc_sample}ms" "$ovh_sample"
echo ""
printf "  Average crypto overhead (INSERT/SELECT/UPDATE): +%s%%\n" "$avg_ovh"
echo "  Note: AES-256-GCM adds 28 bytes/tuple overhead + GCM tag authentication"
echo ""

if [[ "$SKIP_PASSTHROUGH" != "1" ]]; then
    echo "  --- Pass-through baseline (pg_vault_tde.enabled = off) ---"
    echo "  (Isolates pure TAM wrapper cost from AES-256-GCM encryption cost)"
    echo ""
    printf "  %-28s  %-14s  %-16s  %-10s\n" \
        "Operation" "plain_heap" "passthrough" "TAM overhead"
    printf "  %-28s  %-14s  %-16s  %-10s\n" \
        "────────────────────────────" "──────────────" "────────────────" "────────"
    printf "  %-28s  %-14s  %-16s  %-10s\n" \
        "INSERT ${ROWS} rows" "${plain_insert}ms" "${pt_insert}ms" \
        "$(overhead_pct "$plain_insert" "$pt_insert")"
    printf "  %-28s  %-14s  %-16s  %-10s\n" \
        "SELECT seq scan" "${plain_seqscan}ms" "${pt_seqscan}ms" \
        "$(overhead_pct "$plain_seqscan" "$pt_seqscan")"
    printf "  %-28s  %-14s  %-16s  %-10s\n" \
        "UPDATE (10% rows)" "${plain_update}ms" "${pt_update}ms" \
        "$(overhead_pct "$plain_update" "$pt_update")"
    echo ""
fi

# ---------------------------------------------------------------------------
# Write JSON results for artifact collection
# ---------------------------------------------------------------------------
cat > "$BENCH_JSON" <<ENDJSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rows": $ROWS,
  "warmup": $WARMUP,
  "iterations": $ITERATIONS,
  "results": {
    "insert": {
      "plain_ms": $plain_insert,
      "enc_ms":   $enc_insert,
      "overhead": "$ovh_insert"
    },
    "seqscan": {
      "plain_ms": $plain_seqscan,
      "enc_ms":   $enc_seqscan,
      "overhead": "$ovh_seqscan"
    },
    "update": {
      "plain_ms": $plain_update,
      "enc_ms":   $enc_update,
      "overhead": "$ovh_update"
    },
    "index_scan": {
      "plain_ms": $plain_idx,
      "enc_ms":   $enc_idx,
      "overhead": "$ovh_idx"
    },
    "tablesample": {
      "plain_ms": $plain_sample,
      "enc_ms":   $enc_sample,
      "overhead": "$ovh_sample"
    }
  },
  "avg_crypto_overhead_pct": $avg_ovh,
  "threshold_pct": $THRESHOLD
}
ENDJSON
log_info "Results written to $BENCH_JSON"

# ---------------------------------------------------------------------------
# Threshold check (non-fatal: exit 7 signals WARN in run-all.sh)
# ---------------------------------------------------------------------------
RC=0
if awk -v avg="$avg_ovh" -v thr="$THRESHOLD" \
       'BEGIN { exit (avg+0 > thr+0) ? 0 : 1 }'; then
    log_warn "Average overhead ${avg_ovh}% exceeds threshold ${THRESHOLD}% (non-fatal)"
    RC=7
else
    log_ok "Average overhead ${avg_ovh}% is within ${THRESHOLD}% threshold"
fi

echo ""
echo "=== Benchmark complete ==="
exit $RC
