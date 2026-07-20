#!/bin/bash
# packaging/build_deb.sh  — Build a Debian/Ubuntu .deb package for pg_vault_tde
#
# Prerequisites on the build host (Debian/Ubuntu):
#   apt-get install -y debhelper devscripts build-essential \
#       postgresql-server-dev-17 libssl-dev libcurl4-openssl-dev pkg-config
#   # or postgresql-server-dev-18 for PG18
#
# Usage:
#   bash packaging/build_deb.sh [--no-sign]
#     Build the package for PG18.
#
#   bash packaging/build_deb.sh --pg-version 17 [--no-sign]
#     Build for PostgreSQL 17.
#
# There is a single package. Hardware-accelerated AES (AES-NI, VAES, ARM
# Crypto Extensions, SVE2) is provided automatically at runtime by OpenSSL's
# EVP layer — no CPU-specific build variant is needed or offered. See
# wiki/Performance-and-Tuning.md.
#
# Output: ../postgresql-PG-pg-vault-tde_1.7-1_<arch>.deb
#
# Copyright (c) 2026 Miriade Srl — PostgreSQL License

set -e
cd "$(dirname "$0")/.."   # move to project root

VERSION="1.7"
PKG_VERSION="1.7-1"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
NO_SIGN=""
PG_MAJOR="18"  # default; override with --pg-version

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pg-version)
            PG_MAJOR="$2"
            shift 2
            ;;
        --no-sign)
            NO_SIGN="yes"
            shift
            ;;
        *)
            echo "ERROR: Unknown argument '$1'"
            echo "Usage: $0 [--pg-version 17|18] [--no-sign]"
            exit 1
            ;;
    esac
done

TDE_OPTIMIZE="standard"
DEB_NAME="postgresql-${PG_MAJOR}-pg-vault-tde_${PKG_VERSION}_${ARCH}.deb"

echo "========================================================"
echo "  Building DEB package: $DEB_NAME"
echo "  PG_MAJOR=${PG_MAJOR}  TDE_OPTIMIZE=${TDE_OPTIMIZE}"
echo "========================================================"

# ---------------------------------------------------------------------------
# Verify build dependencies
# ---------------------------------------------------------------------------
for dep in pg_config dpkg-buildpackage dh; do
    if ! command -v "$dep" &>/dev/null; then
        echo "ERROR: '$dep' not found. Install:"
        echo "  apt-get install debhelper devscripts build-essential \\"
        echo "      postgresql-server-dev-${PG_MAJOR} libssl-dev libcurl4-openssl-dev pkg-config"
        exit 1
    fi
done

# Verify that pg_config matches the requested PG major version
PG_DETECTED=$(pg_config --version | grep -oP '\d+' | head -1)
if [ "$PG_DETECTED" != "$PG_MAJOR" ]; then
    echo "WARNING: pg_config reports PostgreSQL $PG_DETECTED but --pg-version ${PG_MAJOR} was requested"
    echo "         Set PG_CONFIG=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config if you have multiple versions installed"
fi

# ---------------------------------------------------------------------------
# Copy Debian packaging metadata into place
# ---------------------------------------------------------------------------
cp -r packaging/debian ./debian

# Generate debian/control from the template, substituting the PG major version.
# debian/control.in uses 'PGMAJOR' as a placeholder throughout.
if [ -f debian/control.in ]; then
    sed "s/PGMAJOR/${PG_MAJOR}/g" debian/control.in > debian/control
else
    echo "ERROR: packaging/debian/control.in not found"
    exit 1
fi

# Remove debian/compat: we declare compat via debhelper-compat in Build-Depends.
# Having both causes a debhelper error; the Build-Depends method is the modern approach.
rm -f debian/compat

# Ensure rules is executable
chmod +x debian/rules

# Export make variables so debian/rules can pick them up
export TDE_OPTIMIZE PG_MAJOR

# ---------------------------------------------------------------------------
# Build the package
# ---------------------------------------------------------------------------
if [ "$NO_SIGN" = "yes" ]; then
    dpkg-buildpackage -us -uc -b
else
    dpkg-buildpackage -b
fi

# Cleanup residual
rm -rf ./debian

echo ""
echo "Package built: ../${DEB_NAME}"
echo ""
echo "Install with:"
echo "  dpkg -i ../${DEB_NAME}"
echo "  # or: apt-get install -f ../${DEB_NAME}"
echo ""
echo "Then configure postgresql.conf:"
echo "  shared_preload_libraries = 'pg_vault_tde'"
echo "  # Restart PostgreSQL and run: CREATE EXTENSION pg_vault_tde;"
