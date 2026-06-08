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
#     Build the generic (portable) package for PG18.
#
#   bash packaging/build_deb.sh --pg-version 17 [--no-sign]
#     Build for PostgreSQL 17.
#
#   bash packaging/build_deb.sh --arch-variant aesni [--no-sign]
#     Build with TDE_TARGET_ARCH=x86_64-aesni TDE_OPTIMIZE=max.
#     Package name: postgresql-PG-pg-vault-tde-aesni
#
#   bash packaging/build_deb.sh --arch-variant armce [--no-sign]
#     Build with TDE_TARGET_ARCH=aarch64-ce TDE_OPTIMIZE=max.
#     Package name: postgresql-PG-pg-vault-tde-armce
#
#   bash packaging/build_deb.sh --arch-variant vaes [--no-sign]
#     Build with TDE_TARGET_ARCH=x86_64-vaes TDE_OPTIMIZE=max.
#     Package name: postgresql-PG-pg-vault-tde-vaes
#
# Output: ../postgresql-PG-pg-vault-tde[_variant]_1.7-1_<arch>.deb
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
ARCH_VARIANT=""
NO_SIGN=""
PG_MAJOR="18"  # default; override with --pg-version

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pg-version)
            PG_MAJOR="$2"
            shift 2
            ;;
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
            echo "Usage: $0 [--pg-version 17|18] [--arch-variant aesni|armce|vaes] [--no-sign]"
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
    vaes)
        TDE_TARGET_ARCH="x86_64-vaes"
        TDE_OPTIMIZE="max"
        PKG_SUFFIX="-vaes"
        CONTROL_EXTRA="packaging/debian/control.vaes"
        ;;
    "")
        TDE_TARGET_ARCH="generic"
        TDE_OPTIMIZE="standard"
        PKG_SUFFIX=""
        CONTROL_EXTRA=""
        ;;
    *)
        echo "ERROR: Unknown --arch-variant '$ARCH_VARIANT'. Supported: aesni, armce, vaes"
        exit 1
        ;;
esac

DEB_NAME="postgresql-${PG_MAJOR}-pg-vault-tde${PKG_SUFFIX}_${PKG_VERSION}_${ARCH}.deb"

echo "========================================================"
echo "  Building DEB package: $DEB_NAME"
echo "  PG_MAJOR=${PG_MAJOR}  TDE_TARGET_ARCH=${TDE_TARGET_ARCH}  TDE_OPTIMIZE=${TDE_OPTIMIZE}"
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

# For variant builds, append the supplemental control stanza so dpkg-buildpackage
# knows about the extra binary package.
if [ -n "$CONTROL_EXTRA" ] && [ -f "$CONTROL_EXTRA" ]; then
    echo "" >> debian/control
    # Also substitute PGMAJOR in the variant stanza
    sed "s/PGMAJOR/${PG_MAJOR}/g; s/postgresql-18/postgresql-${PG_MAJOR}/g" "$CONTROL_EXTRA" >> debian/control
fi

# Ensure rules is executable
chmod +x debian/rules

# Export make variables so debian/rules can pick them up
export TDE_TARGET_ARCH TDE_OPTIMIZE PG_MAJOR

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
