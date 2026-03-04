#!/bin/bash
# packaging/build_in_container.sh — Build pg_vault_tde packages inside a container
#
# Builds .deb (Ubuntu 22.04 + PGDG) or .rpm (Rocky Linux 9 + PGDG) packages
# without requiring any local build toolchain.  Output packages land in ./dist/.
#
# Requires: podman or docker
#
# Usage:
#   bash packaging/build_in_container.sh [OPTIONS]
#
# Options:
#   --format deb|rpm      Package format  (default: deb)
#   --pg-version 17|18    PostgreSQL major version  (default: 18)
#   --all                 Build all combinations: deb+rpm × pg17+pg18
#   --output-dir DIR      Where to copy finished packages  (default: ./dist)
#   --no-cache            Pass --no-cache to the container runtime
#   -h, --help            Show this help
#
# Examples:
#   bash packaging/build_in_container.sh
#       → ./dist/postgresql-18-pg-vault-tde_1.6-1_amd64.deb
#
#   bash packaging/build_in_container.sh --format rpm --pg-version 17
#       → ./dist/postgresql17-pg_vault_tde-1.6-1.el9.x86_64.rpm
#
#   bash packaging/build_in_container.sh --all
#       → dist/ with all four packages
#
# Copyright (c) 2026 Miriade Srl — PostgreSQL License

set -euo pipefail
cd "$(dirname "$0")/.."   # project root

VERSION="1.6"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
FORMAT="deb"
PG_MAJOR="18"
BUILD_ALL=0
OUTPUT_DIR="./dist"
NO_CACHE=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)
            FORMAT="${2,,}"   # lowercase
            shift 2
            ;;
        --pg-version)
            PG_MAJOR="$2"
            shift 2
            ;;
        --all)
            BUILD_ALL=1
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument '$1'"
            echo "Run '$0 --help' for usage."
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------
if [[ "$FORMAT" != "deb" && "$FORMAT" != "rpm" ]]; then
    echo "ERROR: --format must be 'deb' or 'rpm', got '$FORMAT'"
    exit 1
fi
if [[ "$PG_MAJOR" != "17" && "$PG_MAJOR" != "18" ]]; then
    echo "ERROR: --pg-version must be 17 or 18, got '$PG_MAJOR'"
    exit 1
fi

# ---------------------------------------------------------------------------
# Detect container runtime
# ---------------------------------------------------------------------------
RUNTIME=""
for cmd in podman docker; do
    if command -v "$cmd" &>/dev/null; then
        RUNTIME="$cmd"
        break
    fi
done
if [[ -z "$RUNTIME" ]]; then
    echo "ERROR: Neither 'podman' nor 'docker' found. Install one and retry."
    exit 1
fi
echo "Container runtime: $RUNTIME"

# ---------------------------------------------------------------------------
# Ensure output directory exists
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"

# ---------------------------------------------------------------------------
# Build functions
# ---------------------------------------------------------------------------

build_deb() {
    local pg="$1"
    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  DEB build  |  PG${pg}  |  Ubuntu 22.04 / PGDG"
    echo "════════════════════════════════════════════════════════"

    $RUNTIME run --rm $NO_CACHE \
        -v "$(pwd)":/src:ro \
        -v "$OUTPUT_DIR":/dist \
        docker.io/library/ubuntu:22.04 bash -c "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── PGDG apt repository ───────────────────────────────────────────────────
apt-get update  -qq
apt-get install -y -q curl ca-certificates gnupg lsb-release
install -d /usr/share/postgresql-common/pgdg
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
     -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo \"deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \\
     https://apt.postgresql.org/pub/repos/apt \$(lsb_release -cs)-pgdg main\" \
     > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq

# ── Build dependencies ────────────────────────────────────────────────────
apt-get install -y -q \\
    debhelper devscripts dpkg-dev build-essential \\
    postgresql-server-dev-${pg} libssl-dev libcurl4-openssl-dev pkg-config

# ── Build ─────────────────────────────────────────────────────────────────
cp -r /src /build && cd /build
export PG_MAJOR=${pg}
bash packaging/build_deb.sh --no-sign --pg-version ${pg}

# ── Copy output ───────────────────────────────────────────────────────────
pkg=\$(ls /build/../postgresql-${pg}-pg-vault-tde_*.deb 2>/dev/null | head -1)
if [[ -z \"\$pkg\" ]]; then
    echo 'ERROR: .deb not found after build'
    exit 1
fi
cp \"\$pkg\" /dist/
echo \"Copied: \$(basename \$pkg) → /dist/\"
"
    echo "  ✓ DEB PG${pg} complete"
}


build_rpm() {
    local pg="$1"
    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  RPM build  |  PG${pg}  |  Rocky Linux 9 / PGDG"
    echo "════════════════════════════════════════════════════════"

    $RUNTIME run --rm $NO_CACHE \
        -v "$(pwd)":/src:ro \
        -v "$OUTPUT_DIR":/dist \
        docker.io/library/rockylinux:9 bash -c "
set -euo pipefail

# ── PGDG + EPEL + CRB repositories ───────────────────────────────────────
dnf install -y -q epel-release
dnf config-manager --set-enabled crb
dnf install -y -q https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -y module disable postgresql 2>/dev/null || true

# ── Build dependencies ────────────────────────────────────────────────────
dnf install -y -q \\
    perl-IPC-Run postgresql${pg}-devel \\
    openssl-devel libcurl-devel pkgconfig \\
    gcc make rsync rpm-build

# ── Build ─────────────────────────────────────────────────────────────────
export PATH=\"/usr/pgsql-${pg}/bin:\$PATH\"
cp -r /src /build && cd /build
bash packaging/build_rpm.sh --pg-version ${pg}

# ── Copy output ───────────────────────────────────────────────────────────
pkg=\$(find ~/rpmbuild/RPMS -name \"postgresql${pg}-pg_vault_tde-*.rpm\" \\
           ! -name '*debuginfo*' ! -name '*debugsource*' | head -1)
if [[ -z \"\$pkg\" ]]; then
    echo 'ERROR: .rpm not found after build'
    exit 1
fi
cp \"\$pkg\" /dist/
echo \"Copied: \$(basename \$pkg) → /dist/\"
"
    echo "  ✓ RPM PG${pg} complete"
}

# ---------------------------------------------------------------------------
# Run builds
# ---------------------------------------------------------------------------
if [[ "$BUILD_ALL" -eq 1 ]]; then
    build_deb 17
    build_deb 18
    build_rpm 17
    build_rpm 18
elif [[ "$FORMAT" == "deb" ]]; then
    build_deb "$PG_MAJOR"
else
    build_rpm "$PG_MAJOR"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Packages in ${OUTPUT_DIR}/"
echo "════════════════════════════════════════════════════════"
ls -lh "$OUTPUT_DIR"/*.deb "$OUTPUT_DIR"/*.rpm 2>/dev/null \
    | awk '{printf "  %-50s %s\n", $NF, $5}' || true
echo ""
echo "Install:"
echo "  DEB: dpkg -i <package>.deb"
echo "  RPM: dnf install <package>.rpm"
