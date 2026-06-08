#!/bin/bash
# packaging/build_in_container.sh — Build pg_vault_tde packages inside a container
#
# Builds .deb (Ubuntu/Debian + PGDG) or .rpm (Rocky Linux/AlmaLinux + PGDG) packages
# without requiring any local build toolchain.  Output packages land in ./dist/.
#
# Requires: podman or docker
#
# Usage:
#   bash packaging/build_in_container.sh [OPTIONS]
#
# Options:
#   --format deb|rpm          Package format  (default: deb)
#   --pg-version 17|18        PostgreSQL major version  (default: 18)
#   --os-version VERSION      OS base image for the build container:
#                               DEB:  ubuntu:22.04 (default), ubuntu:24.04,
#                                     debian:12, debian:11
#                               RPM:  rockylinux:9 (default), rockylinux:8,
#                                     almalinux:9, almalinux:8
#   --arch-variant VARIANT    Hardware acceleration variant:
#                               generic (default) — portable, no special flags
#                               aesni   — Intel/AMD AES-NI + PCLMUL (Core 2010+, Bulldozer+)
#                               vaes    — AMD VAES + AVX2 (Zen 4+, Intel Ice Lake+)
#                               armce   — ARM Crypto Extensions (ARMv8-A, Graviton 2/3)
#                               sve2    — ARM SVE2 (ARMv9-A, Neoverse V2, Grace)
#   --all                     Build all combinations: deb+rpm × pg17+pg18
#                             (uses default OS versions, generic arch variant)
#   --output-dir DIR          Where to copy finished packages  (default: ./dist)
#   --no-cache                Pass --no-cache to the container runtime
#   -h, --help                Show this help
#
# Examples:
#   bash packaging/build_in_container.sh
#       → ./dist/postgresql-18-pg-vault-tde_1.7-1_amd64.deb
#
#   bash packaging/build_in_container.sh --format rpm --pg-version 17
#       → ./dist/postgresql17-pg_vault_tde-1.7-1.el9.x86_64.rpm
#
#   bash packaging/build_in_container.sh --os-version ubuntu:24.04
#       → DEB PG18 built on Ubuntu 24.04 Noble
#
#   bash packaging/build_in_container.sh --format rpm --os-version rockylinux:8 --pg-version 17
#       → RPM PG17 built on Rocky Linux 8 (EL8)
#
#   bash packaging/build_in_container.sh --arch-variant aesni
#       → ./dist/postgresql-18-pg-vault-tde-aesni_1.7-1_amd64.deb
#
#   bash packaging/build_in_container.sh --format rpm --arch-variant vaes --os-version almalinux:9
#       → RPM AES-VAES on AlmaLinux 9
#
#   bash packaging/build_in_container.sh --all
#       → dist/ with all four generic packages (deb+rpm × pg17+pg18)
#
# Copyright (c) 2026 Miriade Srl — PostgreSQL License

set -euo pipefail
cd "$(dirname "$0")/.."   # project root

VERSION="1.7"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
FORMAT="deb"
PG_MAJOR="18"
BUILD_ALL=0
OUTPUT_DIR="./dist"
PULL_FLAG=""             # set to --pull=always by --no-cache
ARCH_VARIANT=""          # empty = generic
OS_VERSION_ARG=""        # empty = use format-specific default

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
        --os-version)
            OS_VERSION_ARG="$2"
            shift 2
            ;;
        --arch-variant)
            ARCH_VARIANT="${2,,}"   # lowercase
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
            # --no-cache is a 'build' flag; for 'run' the equivalent is
            # --pull=always which forces a fresh pull of the base OS image
            # from the registry, preventing a stale cached image from
            # delivering an outdated build toolchain or compiled binary.
            PULL_FLAG="--pull=always"
            shift
            ;;
        -h|--help)
            sed -n '2,58p' "$0" | sed 's/^# \?//'
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
# Validate --format
# ---------------------------------------------------------------------------
if [[ "$FORMAT" != "deb" && "$FORMAT" != "rpm" ]]; then
    echo "ERROR: --format must be 'deb' or 'rpm', got '$FORMAT'"
    exit 1
fi

# ---------------------------------------------------------------------------
# Validate --pg-version
# ---------------------------------------------------------------------------
if [[ "$PG_MAJOR" != "17" && "$PG_MAJOR" != "18" ]]; then
    echo "ERROR: --pg-version must be 17 or 18, got '$PG_MAJOR'"
    exit 1
fi

# ---------------------------------------------------------------------------
# OS version validation and defaults
# ---------------------------------------------------------------------------
VALID_DEB_OS=("ubuntu:22.04" "ubuntu:24.04" "debian:12" "debian:11")
VALID_RPM_OS=("rockylinux:9" "rockylinux:8" "almalinux:9" "almalinux:8")

# Set format defaults
DEB_OS_IMAGE="ubuntu:22.04"
RPM_OS_IMAGE="rockylinux:9"

if [[ -n "$OS_VERSION_ARG" ]]; then
    case "$FORMAT" in
        deb)
            valid=0
            for v in "${VALID_DEB_OS[@]}"; do
                [[ "$OS_VERSION_ARG" == "$v" ]] && valid=1 && break
            done
            if [[ "$valid" -eq 0 ]]; then
                echo "ERROR: --os-version '$OS_VERSION_ARG' is not valid for --format deb."
                echo "       Valid values: ${VALID_DEB_OS[*]}"
                exit 1
            fi
            DEB_OS_IMAGE="$OS_VERSION_ARG"
            ;;
        rpm)
            valid=0
            for v in "${VALID_RPM_OS[@]}"; do
                [[ "$OS_VERSION_ARG" == "$v" ]] && valid=1 && break
            done
            if [[ "$valid" -eq 0 ]]; then
                echo "ERROR: --os-version '$OS_VERSION_ARG' is not valid for --format rpm."
                echo "       Valid values: ${VALID_RPM_OS[*]}"
                exit 1
            fi
            RPM_OS_IMAGE="$OS_VERSION_ARG"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# Validate and resolve --arch-variant
# ---------------------------------------------------------------------------
VALID_ARCH_VARIANTS=("" "generic" "aesni" "vaes" "armce" "sve2")
valid=0
for v in "${VALID_ARCH_VARIANTS[@]}"; do
    [[ "$ARCH_VARIANT" == "$v" ]] && valid=1 && break
done
if [[ "$valid" -eq 0 ]]; then
    echo "ERROR: --arch-variant '$ARCH_VARIANT' is not valid."
    echo "       Valid values: generic, aesni, vaes, armce, sve2"
    exit 1
fi

#
# Map variant → compiler flags string passed to build_deb.sh / build_rpm.sh
# via the --arch-variant argument (mirrored from the upstream spec/rules).
#
case "$ARCH_VARIANT" in
    ""|generic)
        PKG_VARIANT_FLAG=""           # no --arch-variant flag → generic build
        ARCH_LABEL="generic"
        ;;
    aesni)
        PKG_VARIANT_FLAG="--arch-variant aesni"
        ARCH_LABEL="aesni"
        ;;
    vaes)
        PKG_VARIANT_FLAG="--arch-variant vaes"
        ARCH_LABEL="vaes"
        ;;
    armce)
        PKG_VARIANT_FLAG="--arch-variant armce"
        ARCH_LABEL="armce"
        ;;
    sve2)
        PKG_VARIANT_FLAG="--arch-variant sve2"
        ARCH_LABEL="sve2"
        ;;
esac

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
echo "Container runtime : $RUNTIME"
echo "Pull flag         : ${PULL_FLAG:-'(use local cache)'}"

# ---------------------------------------------------------------------------
# Ensure output directory exists
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"

# ---------------------------------------------------------------------------
# Helper: derive the EL version number from an RPM OS image name.
# Used to construct the correct PGDG repo URL (EL-8 vs EL-9).
# ---------------------------------------------------------------------------
_el_version_from_image() {
    local img="$1"
    case "$img" in
        rockylinux:9|almalinux:9) echo "9" ;;
        rockylinux:8|almalinux:8) echo "8" ;;
        *) echo "9" ;;
    esac
}

# ---------------------------------------------------------------------------
# Build functions
# ---------------------------------------------------------------------------

build_deb() {
    local pg="$1"
    local os_image="$2"
    local arch_label="$3"
    local pkg_variant_flag="$4"

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  DEB build  |  PG${pg}  |  ${os_image}  |  arch=${arch_label}"
    echo "════════════════════════════════════════════════════════"

    # $PULL_FLAG is intentionally unquoted: either empty or "--pull=always".
    # Quoting an empty string would pass a literal "" argument to the runtime.
    # shellcheck disable=SC2086
    $RUNTIME run --rm $PULL_FLAG \
        -v "$(pwd)":/src:ro \
        -v "$OUTPUT_DIR":/dist \
        "docker.io/library/${os_image}" bash -c "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── Verify the buffer pin fix is present in the mounted source ────────────
# The bug was ExecClearTuple(slot) called inside pg_vault_tde_decode_slot(),
# releasing the buffer pin prematurely (O(rows) hits instead of O(pages)).
# A legitimate ExecClearTuple(slot) also exists in tde_index_build_range_scan
# so we must scope the check to decode_slot's function body only.
if awk '/^pg_vault_tde_decode_slot/,/^}/' /src/src/tam/pg_vault_tde_tam.c \
       | grep -q 'ExecClearTuple(slot)'; then
    echo 'BUILD ERROR: ExecClearTuple(slot) found inside pg_vault_tde_decode_slot'
    echo '             Buffer pin fix is MISSING. Check the source tree.'
    exit 1
fi
echo '── Source OK: buffer pin fix confirmed in decode_slot ──'
md5sum /src/src/tam/pg_vault_tde_tam.c

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
bash packaging/build_deb.sh --no-sign --pg-version ${pg} ${pkg_variant_flag}

# ── Copy output ───────────────────────────────────────────────────────────
pkg=\$(ls /build/../postgresql-${pg}-pg-vault-tde*.deb 2>/dev/null | head -1)
if [[ -z \"\$pkg\" ]]; then
    echo 'ERROR: .deb not found after build'
    exit 1
fi
cp \"\$pkg\" /dist/
echo \"Copied: \$(basename \$pkg) → /dist/\"
md5sum /dist/\$(basename \$pkg)
"
    echo "  ✓ DEB PG${pg} (${os_image}, arch=${arch_label}) complete"
    echo ""
    echo "  To install and activate:"
    echo "    sudo dpkg -i ${OUTPUT_DIR}/postgresql-${pg}-pg-vault-tde*.deb"
    echo "    sudo systemctl restart postgresql"
}


build_rpm() {
    local pg="$1"
    local os_image="$2"
    local arch_label="$3"
    # arch-variant for RPM: separate spec files per variant; not wired through
    # build_rpm.sh flags yet — the EL spec names carry the variant suffix.

    local el_ver
    el_ver="$(_el_version_from_image "$os_image")"

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  RPM build  |  PG${pg}  |  ${os_image} (EL${el_ver})  |  arch=${arch_label}"
    echo "════════════════════════════════════════════════════════"

    # shellcheck disable=SC2086
    $RUNTIME run --rm $PULL_FLAG \
        -v "$(pwd)":/src:ro \
        -v "$OUTPUT_DIR":/dist \
        "docker.io/library/${os_image}" bash -c "
set -euo pipefail

# ── Verify the buffer pin fix is present in the mounted source ────────────
if awk '/^pg_vault_tde_decode_slot/,/^}/' /src/src/tam/pg_vault_tde_tam.c \
       | grep -q 'ExecClearTuple(slot)'; then
    echo 'BUILD ERROR: ExecClearTuple(slot) found inside pg_vault_tde_decode_slot'
    echo '             Buffer pin fix is MISSING. Check the source tree.'
    exit 1
fi
echo '── Source OK: buffer pin fix confirmed in decode_slot ──'
md5sum /src/src/tam/pg_vault_tde_tam.c

# ── PGDG + EPEL + CRB repositories ───────────────────────────────────────
dnf install -y -q epel-release
dnf config-manager --set-enabled crb 2>/dev/null || \
    dnf config-manager --enable crb 2>/dev/null || true
dnf install -y -q https://download.postgresql.org/pub/repos/yum/reporpms/EL-${el_ver}-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -y module disable postgresql 2>/dev/null || true

# ── Build dependencies ────────────────────────────────────────────────────
dnf install -y -q \\
    perl-IPC-Run postgresql${pg}-devel \\
    openssl-devel libcurl-devel pkgconfig \\
    gcc make rsync rpm-build

# ── Build ─────────────────────────────────────────────────────────────────
export PATH=\"/usr/pgsql-${pg}/bin:\$PATH\"
cp -r /src /build && cd /build
bash packaging/build_rpm.sh --pg-version ${pg} ${PKG_VARIANT_FLAG}

# ── Copy output ───────────────────────────────────────────────────────────
pkg=\$(find ~/rpmbuild/RPMS -name \"postgresql${pg}-pg_vault_tde*.rpm\" \\
           ! -name '*debuginfo*' ! -name '*debugsource*' | head -1)
if [[ -z \"\$pkg\" ]]; then
    echo 'ERROR: .rpm not found after build'
    exit 1
fi
cp \"\$pkg\" /dist/
echo \"Copied: \$(basename \$pkg) → /dist/\"
md5sum /dist/\$(basename \$pkg)
"
    echo "  ✓ RPM PG${pg} (${os_image}, arch=${arch_label}) complete"
    echo ""
    echo "  To install and activate:"
    echo "    sudo dnf install ${OUTPUT_DIR}/postgresql${pg}-pg_vault_tde*.rpm"
    echo "    sudo systemctl restart postgresql"
}

# ---------------------------------------------------------------------------
# Run builds
# ---------------------------------------------------------------------------
if [[ "$BUILD_ALL" -eq 1 ]]; then
    # --all targets all PG × format combinations with the default OS images
    # and the generic (portable) arch variant.
    build_deb 17 "$DEB_OS_IMAGE" "generic" ""
    build_deb 18 "$DEB_OS_IMAGE" "generic" ""
    build_rpm 17 "$RPM_OS_IMAGE" "generic" ""
    build_rpm 18 "$RPM_OS_IMAGE" "generic" ""
elif [[ "$FORMAT" == "deb" ]]; then
    build_deb "$PG_MAJOR" "$DEB_OS_IMAGE" "$ARCH_LABEL" "$PKG_VARIANT_FLAG"
else
    build_rpm "$PG_MAJOR" "$RPM_OS_IMAGE" "$ARCH_LABEL"
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
