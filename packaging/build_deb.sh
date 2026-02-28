#!/bin/bash
# packaging/build_deb.sh  — Build a Debian/Ubuntu .deb package for pg_vault_tde
#
# Prerequisites on the build host (Debian/Ubuntu):
#   apt-get install -y debhelper devscripts build-essential \
#       postgresql-server-dev-18 libssl-dev libcurl4-openssl-dev pkg-config
#
# Usage:
#   bash packaging/build_deb.sh [--no-sign]
#     Build the generic (portable) package.
#
#   bash packaging/build_deb.sh --arch-variant aesni [--no-sign]
#     Build with TDE_TARGET_ARCH=x86_64-aesni TDE_OPTIMIZE=max.
#     Package name: postgresql-18-pg-vault-tde-aesni
#
#   bash packaging/build_deb.sh --arch-variant armce [--no-sign]
#     Build with TDE_TARGET_ARCH=aarch64-ce TDE_OPTIMIZE=max.
#     Package name: postgresql-18-pg-vault-tde-armce
#
# Output: ../postgresql-18-pg-vault-tde[_variant]_1.0-1_<arch>.deb
#
# Copyright (c) 2026 Miriade Srl — PostgreSQL License

set -e
cd "$(dirname "$0")/.."   # move to project root

VERSION="1.0"
PKG_VERSION="1.0-1"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
ARCH_VARIANT=""
NO_SIGN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch-variant)
            ARCH_VARIANT="$2"
            shift 2
            ;;
        --no-sign)
            NO_SIGN="yes"
            shift
            ;;
        *)
            echo "ERROR: Unknown argument '$1'"
            echo "Usage: $0 [--arch-variant aesni|armce] [--no-sign]"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve variant-specific settings
# ---------------------------------------------------------------------------
case "$ARCH_VARIANT" in
    aesni)
        TDE_TARGET_ARCH="x86_64-aesni"
        TDE_OPTIMIZE="max"
        PKG_SUFFIX="-aesni"
        CONTROL_EXTRA="packaging/debian/control.aesni"
        ;;
    armce)
        TDE_TARGET_ARCH="aarch64-ce"
        TDE_OPTIMIZE="max"
        PKG_SUFFIX="-armce"
        CONTROL_EXTRA="packaging/debian/control.arm"
        ;;
    "")
        TDE_TARGET_ARCH="generic"
        TDE_OPTIMIZE="standard"
        PKG_SUFFIX=""
        CONTROL_EXTRA=""
        ;;
    *)
        echo "ERROR: Unknown --arch-variant '$ARCH_VARIANT'. Supported: aesni, armce"
        exit 1
        ;;
esac

DEB_NAME="postgresql-18-pg-vault-tde${PKG_SUFFIX}_${PKG_VERSION}_${ARCH}.deb"

echo "========================================================"
echo "  Building DEB package: $DEB_NAME"
echo "  TDE_TARGET_ARCH=${TDE_TARGET_ARCH}  TDE_OPTIMIZE=${TDE_OPTIMIZE}"
echo "========================================================"

# ---------------------------------------------------------------------------
# Verify build dependencies
# ---------------------------------------------------------------------------
for dep in pg_config dpkg-buildpackage debhelper; do
    if ! command -v "$dep" &>/dev/null; then
        echo "ERROR: '$dep' not found. Install: apt-get install debhelper postgresql-server-dev-18"
        exit 1
    fi
done

PG_VERSION=$(pg_config --version | grep -oP '\d+' | head -1)
if [ "$PG_VERSION" != "18" ]; then
    echo "WARNING: pg_config reports PostgreSQL $PG_VERSION, expected 18"
fi

# ---------------------------------------------------------------------------
# Copy Debian packaging metadata into place
# ---------------------------------------------------------------------------
cp -r packaging/debian ./debian

# For variant builds, append the supplemental control stanza so dpkg-buildpackage
# knows about the extra binary package.
if [ -n "$CONTROL_EXTRA" ] && [ -f "$CONTROL_EXTRA" ]; then
    echo "" >> debian/control
    cat "$CONTROL_EXTRA" >> debian/control
fi

# Ensure rules is executable
chmod +x debian/rules

# Export make variables so debian/rules can pick them up
export TDE_TARGET_ARCH TDE_OPTIMIZE

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
