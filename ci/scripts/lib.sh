#!/usr/bin/env bash
# ci/scripts/lib.sh — Shared utilities for the local CI pipeline
#
# Sourced by all stage scripts. Provides:
#   - Container runtime detection (podman vs docker)
#   - Compose command detection (podman-compose vs docker-compose vs docker compose)
#   - Colored output helpers
#   - PG readiness wait loop
#   - Cleanup trap wiring
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

set -euo pipefail

# ---------------------------------------------------------------------------
# Directory resolution — always relative to repo root
# ---------------------------------------------------------------------------
CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CI_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Load .env defaults (can be overridden by shell environment)
# ---------------------------------------------------------------------------
if [[ -f "$CI_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$CI_DIR/.env"
    set +a
fi

# ---------------------------------------------------------------------------
# Container runtime detection
# ---------------------------------------------------------------------------
detect_runtime() {
    if [[ -n "${CONTAINER_RT:-}" ]]; then
        echo "$CONTAINER_RT"
        return
    fi
    if command -v podman &>/dev/null; then
        echo "podman"
    elif command -v docker &>/dev/null; then
        echo "docker"
    else
        echo "ERROR: Neither podman nor docker found in PATH" >&2
        exit 1
    fi
}

detect_compose() {
    local rt="$1"
    if [[ "$rt" == "podman" ]]; then
        if command -v podman-compose &>/dev/null; then
            echo "podman-compose"
        elif podman compose version &>/dev/null 2>&1; then
            echo "podman compose"
        else
            echo "ERROR: Neither podman-compose nor 'podman compose' plugin found" >&2
            exit 1
        fi
    else
        if docker compose version &>/dev/null 2>&1; then
            echo "docker compose"
        elif command -v docker-compose &>/dev/null; then
            echo "docker-compose"
        else
            echo "ERROR: Neither 'docker compose' nor docker-compose found" >&2
            exit 1
        fi
    fi
}

RT=$(detect_runtime)
COMPOSE_CMD=$(detect_compose "$RT")

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

log_info()  { echo -e "${CYAN}[ci]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[ci]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[ci]${NC} $*"; }
log_error() { echo -e "${RED}[ci]${NC} $*"; }
log_stage() { echo -e "\n${BOLD}═══════════════════════════════════════════════════${NC}"; \
              echo -e "${BOLD}  $*${NC}"; \
              echo -e "${BOLD}═══════════════════════════════════════════════════${NC}\n"; }

# ---------------------------------------------------------------------------
# Timer helpers
# ---------------------------------------------------------------------------
timer_start() { date +%s; }
timer_elapsed() {
    local start="$1"
    local end
    end=$(date +%s)
    echo $(( end - start ))
}
timer_fmt() {
    local secs="$1"
    printf "%dm%02ds" $(( secs / 60 )) $(( secs % 60 ))
}

# ---------------------------------------------------------------------------
# Wait for a container's PG to be ready
# ---------------------------------------------------------------------------
wait_pg_ready() {
    local container="$1"
    local timeout="${2:-${PG_STARTUP_TIMEOUT:-30}}"
    log_info "Waiting for PostgreSQL ($container) ..."
    for i in $(seq 1 "$timeout"); do
        if $RT exec "$container" pg_isready -U postgres -q 2>/dev/null; then
            log_ok "PostgreSQL ($container) is ready (${i}s)"
            return 0
        fi
        sleep 1
    done
    log_error "PostgreSQL ($container) failed to start within ${timeout}s"
    $RT logs "$container" --tail 20 2>/dev/null || true
    return 1
}

# ---------------------------------------------------------------------------
# Build the pg-test image (no-op if already up to date)
# ---------------------------------------------------------------------------
build_pg_test_image() {
    local image="${PG_TEST_IMAGE:-pg-tde-test}"
    log_info "Building $image image ..."
    $RT build \
        -f "$CI_DIR/containers/pg-test.Containerfile" \
        -t "$image:latest" \
        "$REPO_ROOT" 2>&1 | tail -5
    log_ok "Image $image built successfully"
}

# ---------------------------------------------------------------------------
# Start a standalone pg-test container (no compose, no vault)
# ---------------------------------------------------------------------------
start_pg_container() {
    local name="$1"
    local port="${2:-15432}"
    local extra_args=("${@:3}")

    $RT rm -f "$name" 2>/dev/null || true
    $RT run --rm -d \
        --name "$name" \
        -e POSTGRES_PASSWORD=postgres \
        -p "${port}:5432" \
        "${extra_args[@]}" \
        "${PG_TEST_IMAGE:-pg-tde-test}:latest" \
        postgres \
        -c "shared_preload_libraries=pg_vault_tde" \
        -c "pg_vault_tde.dev_mode=on" \
        -c "log_min_messages=warning" \

    wait_pg_ready "$name"
}

# ---------------------------------------------------------------------------
# Run psql inside a container
# ---------------------------------------------------------------------------
container_psql() {
    local container="$1"
    shift
    $RT exec -u postgres "$container" psql -U postgres "$@"
}

# ---------------------------------------------------------------------------
# Cleanup: stop and remove a container
# ---------------------------------------------------------------------------
stop_container() {
    local name="$1"
    log_info "Stopping container $name ..."
    $RT stop "$name" 2>/dev/null || true
    $RT rm -f "$name" 2>/dev/null || true
}
