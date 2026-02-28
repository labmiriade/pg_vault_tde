#!/usr/bin/env bash
# bench_tde.sh — Compatibility stub
#
# The benchmark has moved to ci/scripts/run-bench.sh and is now integrated
# into the CI pipeline as the "bench" stage.
#
# This script delegates to ci/scripts/run-bench.sh so that any existing
# invocations of bench_tde.sh continue to work.
#
# Usage (legacy):
#   bash bench_tde.sh [env overrides]
#
# Recommended:
#   bash ci/scripts/run-bench.sh
#   # or via the full pipeline:
#   bash ci/scripts/run-all.sh --only bench
#
# Environment variables are forwarded unchanged (BENCH_ROWS, BENCH_WARMUP,
# BENCH_ITERATIONS, BENCH_THRESHOLD_PCT, TDE_SKIP_PASSTHROUGH, etc.).
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[bench_tde.sh] Delegating to ci/scripts/run-bench.sh ..."
exec bash "$SCRIPT_DIR/ci/scripts/run-bench.sh" "$@"
