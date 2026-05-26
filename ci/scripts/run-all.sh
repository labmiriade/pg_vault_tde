#!/usr/bin/env bash
# ci/scripts/run-all.sh — Master orchestrator for the local CI pipeline
#
# Runs all test stages in sequence:
#   1. regress     — 80-test SQL regression suite (52 v1.4 + 20 v1.5 + 8 v1.6)
#   2. checksums   — Page checksum compatibility
#   3. tap         — Perl TAP tests (extension load, backup hooks)
#   4. isolation   — Concurrency/MVCC isolation specs
#   5. vault       — Vault mock integration (via Compose)
#   6. openbao     — OpenBao 3-node Raft integration (AppRole, KEK, BGW)
#   7. wallet      — Local wallet full regression (kms_provider=local, tests 74-80)
#   8. schema      — Multi-database and multi-schema isolation (SCHEMA-1..20)
#   9. bench       — Performance benchmark (informational, non-blocking)
#
# Usage:
#   bash ci/scripts/run-all.sh                    # run all stages
#   bash ci/scripts/run-all.sh --skip-bench       # skip benchmark
#   bash ci/scripts/run-all.sh --skip-openbao     # skip OpenBao stage
#   bash ci/scripts/run-all.sh --skip-wallet      # skip local wallet stage
#   bash ci/scripts/run-all.sh --skip-schema      # skip schema isolation stage
#   bash ci/scripts/run-all.sh --only regress tap # run specific stages
#
# Exit code: 0 if all stages pass, otherwise the first non-zero exit code.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
SKIP_BENCH=0
SKIP_OPENBAO=0
SKIP_WALLET=0
SKIP_SCHEMA=0
SKIP_INSTALL_TEST=0
ONLY_STAGES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-bench)
            SKIP_BENCH=1
            shift
            ;;
        --skip-openbao)
            SKIP_OPENBAO=1
            shift
            ;;
        --skip-wallet)
            SKIP_WALLET=1
            shift
            ;;
        --skip-schema)
            SKIP_SCHEMA=1
            shift
            ;;
        --skip-install-test)
            SKIP_INSTALL_TEST=1
            shift
            ;;
        --only)
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                ONLY_STAGES+=("$1")
                shift
            done
            ;;
        --help|-h)
            echo "Usage: $0 [--skip-bench] [--skip-openbao] [--skip-wallet] [--skip-install-test] [--only stage1 stage2 ...]"
            echo ""
            echo "Stages: regress checksums tap isolation vault openbao wallet schema install-test bench"
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Stage definitions
# ---------------------------------------------------------------------------
ALL_STAGES=(regress checksums tap isolation vault openbao wallet schema install-test bench)

should_run() {
    local stage="$1"
    if [[ ${#ONLY_STAGES[@]} -gt 0 ]]; then
        for s in "${ONLY_STAGES[@]}"; do
            [[  "$s" == "$stage" ]] && return 0
        done
        return 1
    fi
    if [[ "$stage" == "bench" && "$SKIP_BENCH" == "1" ]]; then
        return 1
    fi
    if [[ "$stage" == "openbao" && "$SKIP_OPENBAO" == "1" ]]; then
        return 1
    fi
    if [[ "$stage" == "wallet" && "$SKIP_WALLET" == "1" ]]; then
        return 1
    fi
    if [[ "$stage" == "schema" && "$SKIP_SCHEMA" == "1" ]]; then
        return 1
    fi
    if [[ "$stage" == "install-test" && "$SKIP_INSTALL_TEST" == "1" ]]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Pre-flight: build the pg-test image once (shared by all stages)
# ---------------------------------------------------------------------------
log_stage "pg_vault_tde — LOCAL CI PIPELINE"

log_info "Container runtime: $RT"
log_info "Compose command:   $COMPOSE_CMD"
log_info "Repository root:   $REPO_ROOT"
echo ""

PIPELINE_START=$(timer_start)

# Build image once upfront — individual scripts will skip if already available
build_pg_test_image

# ---------------------------------------------------------------------------
# Run stages
# ---------------------------------------------------------------------------
declare -A RESULTS
OVERALL_RC=0

for stage in "${ALL_STAGES[@]}"; do
    if ! should_run "$stage"; then
        RESULTS[$stage]="SKIPPED"
        continue
    fi

    STAGE_START=$(timer_start)

    if bash "$SCRIPT_DIR/run-${stage}.sh"; then
        STAGE_ELAPSED=$(timer_elapsed "$STAGE_START")
        RESULTS[$stage]="PASSED ($(timer_fmt "$STAGE_ELAPSED"))"
    else
        RC=$?
        STAGE_ELAPSED=$(timer_elapsed "$STAGE_START")
        if [[ "$stage" == "bench" || "$stage" == "openbao" ]]; then
            # Benchmark and OpenBao failures are non-fatal in CI
            # (OpenBao requires podman network access to pull docker.io/openbao)
            RESULTS[$stage]="WARN ($(timer_fmt "$STAGE_ELAPSED"))"
        else
            RESULTS[$stage]="FAILED ($(timer_fmt "$STAGE_ELAPSED"))"
            if [[ $OVERALL_RC -eq 0 ]]; then
                OVERALL_RC=$RC
            fi
        fi
    fi
done

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
PIPELINE_ELAPSED=$(timer_elapsed "$PIPELINE_START")

echo ""
log_stage "PIPELINE SUMMARY"
echo ""
printf "  %-14s  %-30s\n" "Stage" "Result"
printf "  %-14s  %-30s\n" "──────────────" "──────────────────────────────"

for stage in "${ALL_STAGES[@]}"; do
    result="${RESULTS[$stage]:-NOT RUN}"
    case "$result" in
        PASSED*)  color="$GREEN" ;;
        FAILED*)  color="$RED" ;;
        WARN*)    color="$YELLOW" ;;
        SKIPPED*) color="$CYAN" ;;
        *)        color="$NC" ;;
    esac
    printf "  %-14s  ${color}%-30s${NC}\n" "$stage" "$result"
done

echo ""
printf "  Total time: %s\n" "$(timer_fmt "$PIPELINE_ELAPSED")"
printf "  Runtime:    %s\n" "$RT"
printf "  Date:       %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
echo ""

if [[ $OVERALL_RC -eq 0 ]]; then
    log_ok "ALL STAGES PASSED"
else
    log_error "PIPELINE FAILED (exit code: $OVERALL_RC)"
fi

exit $OVERALL_RC
