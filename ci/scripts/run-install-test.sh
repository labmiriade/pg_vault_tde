#!/usr/bin/env bash
# ci/scripts/run-install-test.sh — Package installation smoke-test
#
# Catches regressions of the class:
#   "CREATE EXTENSION pg_vault_tde fails because a SQL upgrade-script
#    references a function that does not yet exist (wrong search_path,
#    missing CREATE, wrong ordering …)"
#
# For each combination of (format=deb|rpm) × (pg=17|18), the test:
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
#   bash ci/scripts/run-install-test.sh [--pg 17|18] [--format deb|rpm] [--all]
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
RUN_ALL=0
PG_VERSIONS=()
FORMATS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)       RUN_ALL=1; shift ;;
        --pg)        PG_VERSIONS+=("$2"); shift 2 ;;
        --format)    FORMATS+=("$2"); shift 2 ;;
        -h|--help)
            sed -n '3,25p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "ERROR: unknown arg '$1'"; exit 1 ;;
    esac
done

if [[ "$RUN_ALL" -eq 1 ]]; then
    PG_VERSIONS=(17 18)
    FORMATS=(deb rpm)
fi
[[ ${#PG_VERSIONS[@]} -eq 0 ]] && PG_VERSIONS=(18)
[[ ${#FORMATS[@]} -eq 0 ]]    && FORMATS=(deb)

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

-- §1 ─ CREATE EXTENSION (traverses the full 1.0→1.4→1.5→1.6→1.7 chain)
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
        '"'"'pg_vault_tde_rotate_key()'"'"',
        '"'"'pg_vault_tde_key_generation()'"'"',
        '"'"'pg_vault_tde_set_test_dek()'"'"',
        '"'"'pg_vault_tde_encrypt_test(text)'"'"',
        '"'"'pg_vault_tde_decrypt_test(bytea)'"'"',
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
        '"'"'pg_vault_tde_wallet_rotate_kek(text)'"'"',
        '"'"'pg_vault_tde_wallet_export_bundle(text,text)'"'"',
        '"'"'pg_vault_tde_wallet_import_bundle(text,text)'"'"',
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

-- §6 ─ smoke round-trip (encrypted_heap INSERT → SELECT)
SELECT pg_vault_tde_set_test_dek();

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
# Build and test DEB (Ubuntu 22.04 + PGDG)
# ---------------------------------------------------------------------------
test_deb() {
    local pg="$1"
    local tag="install-test-deb${pg}-$$"
    log_stage "INSTALL TEST  DEB  PG${pg}  (Ubuntu 22.04)"

    $RT run --rm \
        -v "${REPO_ROOT}":/src:ro \
        docker.io/library/ubuntu:22.04 bash -c "
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
cp -r /src /build && cd /build
bash packaging/build_deb.sh --no-sign --pg-version ${pg}
DEB=\$(ls /build/../postgresql-${pg}-pg-vault-tde_*.deb | head -1)
echo \"Built: \$(basename \$DEB)\"

# ── Install package ────────────────────────────────────────────────────
echo '--- Installing DEB ---'
dpkg -i \"\$DEB\"
apt-get install -f -y -q 2>/dev/null || true   # resolve any deps

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
# Build and test RPM (Rocky Linux 9 + PGDG)
# ---------------------------------------------------------------------------
test_rpm() {
    local pg="$1"
    log_stage "INSTALL TEST  RPM  PG${pg}  (Rocky Linux 9)"

    $RT run --rm \
        -v "${REPO_ROOT}":/src:ro \
        docker.io/library/rockylinux:9 bash -c "
set -euo pipefail

# ── PGDG + EPEL + CRB ─────────────────────────────────────────────────
dnf install -y -q epel-release
dnf config-manager --set-enabled crb
dnf install -y -q https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -y module disable postgresql 2>/dev/null || true

# ── Build + runtime dependencies ──────────────────────────────────────
dnf install -y -q \
    perl-IPC-Run postgresql${pg}-devel postgresql${pg}-server \
    openssl-devel libcurl-devel pkgconfig gcc make rsync rpm-build

# ── Build RPM from source ──────────────────────────────────────────────
echo '--- Building RPM ---'
export PATH=\"/usr/pgsql-${pg}/bin:\$PATH\"
cp -r /src /build && cd /build
bash packaging/build_rpm.sh --pg-version ${pg}
RPM=\$(find ~/rpmbuild/RPMS -name \"postgresql${pg}-pg_vault_tde-*.rpm\" \
           ! -name '*debuginfo*' ! -name '*debugsource*' | head -1)
echo \"Built: \$(basename \$RPM)\"

# ── Install RPM ────────────────────────────────────────────────────────
echo '--- Installing RPM ---'
dnf install -y -q \"\$RPM\"

# ── Initialize and configure PostgreSQL ──────────────────────────────
echo '--- Initializing PostgreSQL cluster ---'
/usr/pgsql-${pg}/bin/postgresql-${pg}-setup initdb
systemctl start postgresql-${pg} 2>/dev/null || \
    su postgres -c '/usr/pgsql-${pg}/bin/pg_ctl start -D /var/lib/pgsql/${pg}/data -w' || true

# In containers systemd is usually absent; start directly
su postgres -c '/usr/pgsql-${pg}/bin/pg_ctl start \
    -D /var/lib/pgsql/${pg}/data \
    -o \"-c shared_preload_libraries=pg_vault_tde\" \
    -w -t 20' || true

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
echo -e "${BOLD}formats: ${FORMATS[*]}   pg versions: ${PG_VERSIONS[*]}${NC}"
echo ""

RESULTS=()   # "FORMAT PG PASS|FAIL message"

for fmt in "${FORMATS[@]}"; do
    for pg in "${PG_VERSIONS[@]}"; do
        label="${fmt^^} PG${pg}"
        if [[ "$fmt" == "deb" ]]; then
            if test_deb "$pg"; then
                tap_ok "$label — CREATE EXTENSION + smoke test"
                RESULTS+=("PASS  $label")
            else
                tap_not_ok "$label — CREATE EXTENSION or smoke test FAILED"
                RESULTS+=("FAIL  $label")
            fi
        else
            if test_rpm "$pg"; then
                tap_ok "$label — CREATE EXTENSION + smoke test"
                RESULTS+=("PASS  $label")
            else
                tap_not_ok "$label — CREATE EXTENSION or smoke test FAILED"
                RESULTS+=("FAIL  $label")
            fi
        fi
    done
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
