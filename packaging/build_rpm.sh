#!/bin/bash
# packaging/build_rpm.sh  — Build an RPM package for pg_vault_tde
#
# Prerequisites on the build host (RHEL/Rocky/Fedora):
#   dnf install -y rpm-build postgresql18-devel openssl-devel libcurl-devel \
#                  pkgconfig gcc make
#
# Usage: bash packaging/build_rpm.sh
#
# Output: ~/rpmbuild/RPMS/x86_64/postgresql18-pg_vault_tde-1.0-1.*.rpm
#
# Copyright (c) 2026 Miriade Srl — PostgreSQL License

set -e
cd "$(dirname "$0")/.."  # move to project root

VERSION="1.0"
RELEASE="1"
SPEC="packaging/rpm/pg_vault_tde.spec"
TARBALL="pg_vault_tde-${VERSION}.tar.gz"

echo "========================================================"
echo "  Building RPM package: postgresql18-pg_vault_tde-${VERSION}-${RELEASE}"
echo "========================================================"

# Verify build dependencies
for dep in rpmbuild pg_config; do
    if ! command -v "$dep" &>/dev/null; then
        echo "ERROR: '$dep' not found."
        echo "Install: dnf install rpm-build postgresql18-devel"
        exit 1
    fi
done

PG_VERSION=$(pg_config --version | grep -oP '\d+' | head -1)
if [ "$PG_VERSION" != "18" ]; then
    echo "WARNING: pg_config reports PostgreSQL $PG_VERSION, expected 18"
fi

# Set up rpmbuild tree
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball from current directory (exclude .git, packaging/build artifacts)
echo "Creating source tarball..."
TMPDIR=$(mktemp -d)
mkdir -p "$TMPDIR/pg_vault_tde-${VERSION}"
rsync -a --exclude='.git' --exclude='*.o' --exclude='*.so' --exclude='*.bc' \
         --exclude='packaging' --exclude='tmp_pgext' \
         . "$TMPDIR/pg_vault_tde-${VERSION}/"
tar -czf ~/rpmbuild/SOURCES/"$TARBALL" \
    -C "$TMPDIR" "pg_vault_tde-${VERSION}"
rm -rf "$TMPDIR"
echo "  -> ~/rpmbuild/SOURCES/$TARBALL"

# Copy spec file
cp "$SPEC" ~/rpmbuild/SPECS/pg_vault_tde.spec

# Build RPM
echo "Building RPM..."
rpmbuild -ba \
    --define "pgmajorversion 18" \
    ~/rpmbuild/SPECS/pg_vault_tde.spec

echo ""
echo "RPM build complete. Packages in ~/rpmbuild/RPMS/"
ls -la ~/rpmbuild/RPMS/*/postgresql18-pg_vault_tde* 2>/dev/null || true

echo ""
echo "Install with:"
echo "  dnf install ~/rpmbuild/RPMS/x86_64/postgresql18-pg_vault_tde-${VERSION}-${RELEASE}.*.rpm"
echo ""
echo "Then configure postgresql.conf:"
echo "  shared_preload_libraries = 'pg_vault_tde'"
echo "  # Restart PostgreSQL and run: CREATE EXTENSION pg_vault_tde;"
