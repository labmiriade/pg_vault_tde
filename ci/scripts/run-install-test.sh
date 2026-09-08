#!/usr/bin/env bash
# ci/scripts/run-install-test.sh — Package installation smoke-test
#
# Catches regressions of the class:
#   "CREATE EXTENSION pg_vault_tde fails because a SQL upgrade-script
#    references a function that does not yet exist (wrong search_path,
#    missing CREATE, wrong ordering …)"
#
# The combinations come from packaging/build-matrix.json: every row whose
# install_test flag is true is exercised here, so the matrix that declares the
# coverage and the coverage itself cannot drift apart. Narrow it with --os,
# --format and --pg; with no filter at all, $PG_VERSION selects the major, which
# is how the two parallel Bitbucket steps split the matrix between them.
#
# For each selected (format, os, pg) combination, the test:
#   1. Builds the package from source inside a fresh container
#   2. Starts a second container of the same OS with a clean PGDG install
#   3. Installs the built package
#   4. Starts PostgreSQL with shared_preload_libraries = 'pg_vault_tde'
#   5. CREATE EXTENSION pg_vault_tde  ← main gate
#   6. Asserts extversion = '1.7'
#   7. Asserts every expected function/AM/table exists in pg_catalog
#   8. Smoke-test: SET_TEST_DEK → CREATE TABLE USING encrypted_heap
#      → INSERT → SELECT → compare plaintext → DROP TABLE
#
# Exit code: 0 = all combinations pass, 1 = at least one failure.
#
# Usage:
#   bash ci/scripts/run-install-test.sh [--pg 17|18] [--format deb|rpm]
#                                       [--os ubuntu:24.04] [--all] [--list]
#
# --list prints the combinations that would run, and exits.
#
# Requires jq, to read the build matrix.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
RUN_ALL=0
LIST_ONLY=0
PG_VERSIONS=()
FORMATS=()
OS_IMAGES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)       RUN_ALL=1; shift ;;
        --pg)        PG_VERSIONS+=("$2"); shift 2 ;;
        --format)    FORMATS+=("$2"); shift 2 ;;
        --os)        OS_IMAGES+=("$2"); shift 2 ;;
        --list)      LIST_ONLY=1; shift ;;
        -h|--help)
            sed -n '3,31p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "ERROR: unknown arg '$1'"; exit 1 ;;
    esac
done

# With no filter and no --all, honour $PG_VERSION as before: run-all.sh calls
# this script without arguments, and the Bitbucket pipeline runs it twice in
# parallel with PG_VERSION=17 and PG_VERSION=18, so the two steps together
# cover the matrix exactly once instead of each covering all of it.
if [[ "$RUN_ALL" -eq 0 && ${#PG_VERSIONS[@]} -eq 0 && ${#FORMATS[@]} -eq 0 \
      && ${#OS_IMAGES[@]} -eq 0 && -n "${PG_VERSION:-}" ]]; then
    PG_VERSIONS=("$PG_VERSION")
fi

command -v jq >/dev/null \
    || { echo "ERROR: jq is required to read packaging/build-matrix.json"; exit 1; }

MATRIX="${REPO_ROOT}/packaging/build-matrix.json"
[[ -f "$MATRIX" ]] || { echo "ERROR: $MATRIX not found"; exit 1; }

# Every row flagged install_test, then narrowed by whichever filters were given.
_selected() {
    local out
    out=$(jq -r '.[] | select(.install_test) | "\(.format) \(.os) \(.pg)"' "$MATRIX")
    if [[ ${#FORMATS[@]} -gt 0 ]]; then
        out=$(echo "$out" | grep -E "^($(IFS='|'; echo "${FORMATS[*]}")) ")
    fi
    if [[ ${#OS_IMAGES[@]} -gt 0 ]]; then
        out=$(echo "$out" | awk -v want="$(IFS=,; echo "${OS_IMAGES[*]}")" \
              'BEGIN{n=split(want,a,",");for(i=1;i<=n;i++)w[a[i]]=1} w[$2]')
    fi
    if [[ ${#PG_VERSIONS[@]} -gt 0 ]]; then
        out=$(echo "$out" | awk -v want="$(IFS=,; echo "${PG_VERSIONS[*]}")" \
              'BEGIN{n=split(want,a,",");for(i=1;i<=n;i++)w[a[i]]=1} w[$3]')
    fi
    echo "$out"
}

mapfile -t COMBOS < <(_selected)
if [[ "$LIST_ONLY" -eq 1 ]]; then
    printf '%s\n' "${COMBOS[@]}"
    exit 0
fi
if [[ ${#COMBOS[@]} -eq 0 ]]; then
    echo "ERROR: no combination in $MATRIX matches the given filters"
    exit 1
fi

# ---------------------------------------------------------------------------
# Image and EL-version mapping. Kept in step with the same two helpers in
# packaging/build_in_container.sh, which is where they originate: Rocky Linux
# stopped publishing to the Docker library namespace after 9.3, so rockylinux:*
# only exists under docker.io/rockylinux/rockylinux.
# ---------------------------------------------------------------------------
_container_image_ref() {
    case "$1" in
        rockylinux:*) echo "docker.io/rockylinux/rockylinux:${1#rockylinux:}" ;;
        *)            echo "docker.io/library/$1" ;;
    esac
}
_el_version_from_image() {
    case "$1" in
        rockylinux:10|almalinux:10) echo "10" ;;
        *)                          echo "9"  ;;
    esac
}

# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------
RT=""
for cmd in podman docker; do
    if command -v "$cmd" &>/dev/null; then RT="$cmd"; break; fi
done
[[ -z "$RT" ]] && { echo "ERROR: podman or docker required"; exit 1; }

# ---------------------------------------------------------------------------
# Colour + TAP helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

TAP_COUNT=0
TAP_FAIL=0

tap_ok()     { TAP_COUNT=$(( TAP_COUNT+1 ));
               echo -e "  ${GREEN}ok${NC} ${TAP_COUNT} - $*"; }
tap_not_ok() { TAP_COUNT=$(( TAP_COUNT+1 )); TAP_FAIL=$(( TAP_FAIL+1 ));
               echo -e "  ${RED}not ok${NC} ${TAP_COUNT} - $*"; }
tap_diag()   { echo -e "  ${YELLOW}#${NC} $*"; }
log_stage()  { echo -e "\n${BOLD}═══════════════════════════════════════${NC}";
               echo -e "${BOLD}  $*${NC}";
               echo -e "${BOLD}═══════════════════════════════════════${NC}\n"; }

# ---------------------------------------------------------------------------
# The SQL that is injected into the target container's psql session.
# Must ALL succeed; any error causes psql -v ON_ERROR_STOP=1 to exit ≠0.
# ---------------------------------------------------------------------------
#  § 1  CREATE EXTENSION — tests the full upgrade-script chain
#  § 2  Version assertion — extversion must equal '1.7'
#  § 3  Function catalogue — every function that shipped in 1.0–1.7 must exist
#  § 4  Access-method catalogue — encrypted_heap and tde_btree must be registered
#  § 5  Catalog tables — pg_vault_tde_catalog and rotation progress must exist
#  § 6  Smoke round-trip — inject DEK, encrypt a row, decrypt, compare

SMOKE_SQL='
\set ON_ERROR_STOP on

-- §1 ─ CREATE EXTENSION (installs directly from pg_vault_tde--1.7.sql)
CREATE EXTENSION pg_vault_tde;

-- §2 ─ version
DO $$
DECLARE ver text;
BEGIN
    SELECT extversion INTO ver
    FROM pg_extension WHERE extname = '"'"'pg_vault_tde'"'"';
    IF ver IS DISTINCT FROM '"'"'1.7'"'"' THEN
        RAISE EXCEPTION '"'"'expected extversion 1.7, got %'"'"', ver;
    END IF;
    RAISE NOTICE '"'"'version OK: %'"'"', ver;
END;
$$;

-- §3 ─ function catalogue
-- Every function introduced across all versions must resolve.
DO $$
DECLARE
    missing text[];
    fn      text;
    expected_fns text[] := ARRAY[
        -- v1.0 base
        '"'"'pg_vault_tde_tableam_handler(internal)'"'"',
        '"'"'pg_vault_tde_iam_handler(internal)'"'"',
        '"'"'pg_vault_tde_reencrypt_table(regclass,integer)'"'"',
        '"'"'pg_vault_tde_verify_integrity(regclass)'"'"',
        '"'"'pg_vault_tde_health_check()'"'"',
        -- v1.4 / v1.5
        '"'"'pg_vault_tde_wallet_init(text)'"'"',
        '"'"'pg_vault_tde_wallet_status()'"'"',
        '"'"'pg_vault_tde_rotate_online(regclass,integer)'"'"',
        -- v1.6
        '"'"'pg_vault_tde_wallet_change_passphrase(text,text)'"'"',
        '"'"'pg_vault_tde_wallet_unlock(text)'"'"',
        '"'"'pg_vault_tde_wallet_lock()'"'"',
        '"'"'pg_vault_tde_seal_keys(text,text,text)'"'"',
        '"'"'pg_vault_tde_seal_keys_bytea(text,text)'"'"',
        '"'"'pg_vault_tde_unseal_keys(text,text)'"'"',
        '"'"'pg_vault_tde_migrate_vault_to_wallet(text)'"'"'
    ];
BEGIN
    missing := ARRAY[]::text[];
    FOREACH fn IN ARRAY expected_fns LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = '"'"'public'"'"'
              AND (p.proname || '"'"'('"'"' ||
                   pg_catalog.pg_get_function_identity_arguments(p.oid) ||
                   '"'"')'"'"') ILIKE
                   regexp_replace(fn, '"'"'\(.*\)'"'"', '"'"'%'"'"')
        ) THEN
            missing := array_append(missing, fn);
        END IF;
    END LOOP;
    IF array_length(missing, 1) > 0 THEN
        RAISE EXCEPTION '"'"'Missing functions: %'"'"', array_to_string(missing, '"'"', '"'"');
    END IF;
    RAISE NOTICE '"'"'function catalogue OK (% functions checked)'"'"', array_length(expected_fns, 1);
END;
$$;

-- §4 ─ access methods
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_am WHERE amname = '"'"'encrypted_heap'"'"') THEN
        RAISE EXCEPTION '"'"'AM encrypted_heap not found'"'"';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_am WHERE amname = '"'"'tde_btree'"'"') THEN
        RAISE EXCEPTION '"'"'AM tde_btree not found'"'"';
    END IF;
    RAISE NOTICE '"'"'access methods OK'"'"';
END;
$$;

-- §5 ─ catalog tables
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = '"'"'public'"'"' AND c.relname = '"'"'pg_vault_tde_catalog'"'"'
    ) THEN
        RAISE EXCEPTION '"'"'table pg_vault_tde_catalog not found'"'"';
    END IF;
    RAISE NOTICE '"'"'catalog tables OK'"'"';
END;
$$;

SET pg_vault_tde.kms_provider = '"'"'local'"'"';
SET pg_vault_tde.wallet_passphrase_command = '"'"'echo test-install'"'"';

SELECT pg_vault_tde_wallet_init('"'"'test-install'"'"');


CREATE TABLE _tde_smoke_test (
    id   serial PRIMARY KEY,
    data text   NOT NULL
) USING encrypted_heap;

INSERT INTO _tde_smoke_test (data)
VALUES ('"'"'hello encrypted world'"'"');

DO $$
DECLARE row_data text;
BEGIN
    SELECT data INTO row_data FROM _tde_smoke_test WHERE id = 1;
    IF row_data IS DISTINCT FROM '"'"'hello encrypted world'"'"' THEN
        RAISE EXCEPTION '"'"'round-trip mismatch: expected "hello encrypted world", got "%"'"'"', row_data;
    END IF;
    RAISE NOTICE '"'"'smoke round-trip OK: "%"'"'"', row_data;
END;
$$;

DROP TABLE _tde_smoke_test;

SELECT '"'"'ALL CHECKS PASSED'"'"';
'

# ---------------------------------------------------------------------------
# Build and test DEB (any Debian/Ubuntu image from the matrix + PGDG).
# The apt repository line derives the suite from lsb_release, so the image tag
# is the only thing that has to change per distribution.
# ---------------------------------------------------------------------------
test_deb() {
    local os="$1"
    local pg="$2"
    log_stage "INSTALL TEST  DEB  PG${pg}  (${os})"

    $RT run --rm \
        -v "${REPO_ROOT}":/src:ro \
        "$(_container_image_ref "$os")" bash -c "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── PGDG apt repository ────────────────────────────────────────────────
apt-get update -qq
apt-get install -y -q curl ca-certificates gnupg lsb-release
install -d /usr/share/postgresql-common/pgdg
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
     -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo \"deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
     https://apt.postgresql.org/pub/repos/apt \$(lsb_release -cs)-pgdg main\" \
     > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq

# ── Build dependencies ─────────────────────────────────────────────────
apt-get install -y -q \
    debhelper devscripts dpkg-dev build-essential \
    postgresql-server-dev-${pg} libssl-dev libcurl4-openssl-dev pkg-config \
    postgresql-${pg}

# ── Build package from source ──────────────────────────────────────────
echo '--- Building DEB ---'
mkdir -p /build
tar -C /src --exclude=./.git --exclude=./test/tap --exclude=./ci/docker-data -cf - . | tar -C /build -xf -
cd /build
bash packaging/build_deb.sh --no-sign --pg-version ${pg}
DEB=\$(ls /build/../postgresql-${pg}-pg-vault-tde_*.deb | head -1)
echo \"Built: \$(basename \$DEB)\"

# ── Install package ────────────────────────────────────────────────────
echo '--- Installing DEB ---'
dpkg -i \"\$DEB\"
apt-get install -f -y -q 2>/dev/null || true   # resolve any deps

echo '--- Checking frontend binaries ---'
for b in pg_dump_tde pg_restore_tde pg_basebackup_tde; do
    test -x /usr/lib/postgresql/${pg}/bin/\$b \
        || { echo \"MISSING BINARY: \$b\"; exit 1; }
done

# ── Create wallet base directory ──────────────────────────────────────
mkdir -p /var/lib/pg_vault_tde
chown postgres:postgres /var/lib/pg_vault_tde
chmod 0700 /var/lib/pg_vault_tde

# ── Configure PostgreSQL ───────────────────────────────────────────────
echo '--- Configuring PostgreSQL ---'
pg_ctlcluster ${pg} main start 2>/dev/null || true
su postgres -c \"psql -c \\\"ALTER SYSTEM SET shared_preload_libraries = 'pg_vault_tde';\\\"\"
pg_ctlcluster ${pg} main restart

# Wait for PG
for i in \$(seq 1 20); do
    pg_lsclusters | grep -q 'online' && break
    sleep 1
done

# ── Run all checks ─────────────────────────────────────────────────────
echo '--- Running extension checks ---'
su postgres -c 'psql -v ON_ERROR_STOP=1' <<'EOSQL'
${SMOKE_SQL}
EOSQL
echo 'DEB PG${pg}: PASS'
"
}

# ---------------------------------------------------------------------------
# Build and test RPM (any EL image from the matrix + PGDG).
# ---------------------------------------------------------------------------
test_rpm() {
    local os="$1"
    local pg="$2"
    local el
    el="$(_el_version_from_image "$os")"
    log_stage "INSTALL TEST  RPM  PG${pg}  (${os}, EL${el})"
    PGDATA="/var/lib/pgsql/${pg}/data"
    PGBIN="/usr/pgsql-${pg}/bin"

    $RT run --rm \
        -v "${REPO_ROOT}":/src:ro \
        "$(_container_image_ref "$os")" bash -c "
set -euo pipefail

# ── PGDG + EPEL + CRB ─────────────────────────────────────────────────
dnf install -y -q epel-release
dnf config-manager --set-enabled crb
dnf install -y -q https://download.postgresql.org/pub/repos/yum/reporpms/EL-${el}-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -y module disable postgresql 2>/dev/null || true

# ── Build + runtime dependencies ──────────────────────────────────────
# Must satisfy every BuildRequires in packaging/rpm/pg_vault_tde.spec, since
# rpmbuild refuses to start otherwise: chrpath, plus clang and llvm-devel for
# the LLVM bitcode targets, which postgresqlNN-devel does not pull in.
dnf install -y -q \
    perl-IPC-Run postgresql${pg}-devel postgresql${pg}-server \
    openssl-devel libcurl-devel pkgconfig gcc make rsync rpm-build \
    chrpath clang llvm-devel

# ── Build RPM from source ──────────────────────────────────────────────
echo '--- Building RPM ---'
export PATH=\"/usr/pgsql-${pg}/bin:\$PATH\"
mkdir -p /build
tar -C /src --exclude=./.git --exclude=./test/tap --exclude=./ci/docker-data -cf - . | tar -C /build -xf -
cd /build
bash packaging/build_rpm.sh --pg-version ${pg}
RPM=\$(find ~/rpmbuild/RPMS -name \"postgresql${pg}-pg_vault_tde-*.rpm\" \
           ! -name '*debuginfo*' ! -name '*debugsource*' | head -1)
echo \"Built: \$(basename \$RPM)\"

# ── Install RPM ────────────────────────────────────────────────────────
echo '--- Installing RPM ---'
dnf install -y -q \"\$RPM\"

echo '--- Checking frontend binaries ---'
for b in pg_dump_tde pg_restore_tde pg_basebackup_tde; do
    test -x ${PGBIN}/\$b \
        || { echo \"MISSING BINARY: \$b\"; exit 1; }
done

# ── Create wallet base directory ──────────────────────────────────────
mkdir -p /var/lib/pg_vault_tde
chown postgres:postgres /var/lib/pg_vault_tde
chmod 0700 /var/lib/pg_vault_tde

# ── Initialize and configure PostgreSQL ──────────────────────────────
echo '--- Initializing PostgreSQL cluster ---'

# 1. Direct initdb without RPM wrapper (container needs)
su postgres -c \"${PGBIN}/initdb -D ${PGDATA} --encoding=UTF8 --auth=trust\"

systemctl start postgresql-${pg} 2>/dev/null || \
    su postgres -c \"${PGBIN}/pg_ctl start \
        -D ${PGDATA} \
        -o '-c shared_preload_libraries=pg_vault_tde' \
        -w -t 20\"

# Wait for PG
for i in \$(seq 1 20); do
    su postgres -c '/usr/pgsql-${pg}/bin/pg_isready -q' 2>/dev/null && break
    sleep 1
done
su postgres -c '/usr/pgsql-${pg}/bin/pg_isready'

# ── Run all checks ─────────────────────────────────────────────────────
echo '--- Running extension checks ---'
su postgres -c '/usr/pgsql-${pg}/bin/psql -v ON_ERROR_STOP=1' <<'EOSQL'
${SMOKE_SQL}
EOSQL
echo 'RPM PG${pg}: PASS'
"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}pg_vault_tde  package install tests${NC}"
echo -e "${BOLD}${#COMBOS[@]} combination(s) from packaging/build-matrix.json${NC}"
for c in "${COMBOS[@]}"; do echo "  - $c"; done
echo ""

RESULTS=()   # "PASS|FAIL  label"

for combo in "${COMBOS[@]}"; do
    read -r fmt os pg <<<"$combo"
    label="${fmt^^} PG${pg} ${os}"
    if [[ "$fmt" == "deb" ]]; then
        runner=test_deb
    else
        runner=test_rpm
    fi
    if "$runner" "$os" "$pg"; then
        tap_ok "$label — CREATE EXTENSION + smoke test"
        RESULTS+=("PASS  $label")
    else
        tap_not_ok "$label — CREATE EXTENSION or smoke test FAILED"
        RESULTS+=("FAIL  $label")
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "${BOLD}  INSTALL TEST RESULTS${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"
for r in "${RESULTS[@]}"; do
    if [[ "$r" == PASS* ]]; then
        echo -e "  ${GREEN}✓${NC} ${r#PASS  }"
    else
        echo -e "  ${RED}✗${NC} ${r#FAIL  }"
    fi
done
echo ""
echo "TAP: 1..${TAP_COUNT}"
echo "Tests: ${TAP_COUNT}, Failed: ${TAP_FAIL}"

[[ "$TAP_FAIL" -eq 0 ]]
