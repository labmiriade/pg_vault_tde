#!/usr/bin/env bash
# ci/scripts/run-valgrind.sh — Run the TDE workload with the postmaster under
# Valgrind memcheck.
#
# Until this stage existed, .valgrind.supp was dead weight: no Make target and
# no CI stage ever invoked it, so memory-safety verification of the AES-GCM and
# DEK-handling code was something a developer had to know to run by hand.
#
# WHAT THIS CAN AND CANNOT SEE
#
# The PostgreSQL server here is the stock Debian package, which is NOT built
# with -DUSE_VALGRIND or --enable-cassert.  Without those, memcheck cannot see
# inside palloc: PostgreSQL carves chunks out of large malloc'd blocks, so a
# use-after-pfree looks like an ordinary access to still-valid malloc'd memory.
# That is why the error-path regression suite (make ci-errorpath) exists
# alongside this stage rather than being replaced by it.
#
# What memcheck DOES catch here, all of it real:
#   - invalid free()/double free of malloc'd state (libcurl handles, OpenSSL
#     contexts) — the vault_transit_request PG_CATCH path
#   - invalid read/write outside any malloc'd block — buffer arithmetic bugs in
#     tde_gcm_encrypt/decrypt, wire-format header handling
#   - use of uninitialised bytes — IV/tag/DEK buffers
#   - definite leaks of malloc'd allocations (palloc arenas are suppressed)
#
# Reports are filtered to stacks that mention pg_vault_tde: the stock server
# produces a steady background of its own memcheck noise, and this stage is
# about our code.
#
# To go deeper, build PostgreSQL with --enable-cassert -DUSE_VALGRIND and point
# PG_VALGRIND_IMAGE at it; the filtering below still applies.
#
# Exit code: 0 clean, 10 on memcheck findings or workload failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-valgrind-$$"
VG_IMAGE="${PG_VALGRIND_IMAGE:-pg-tde-valgrind}"
PGDATA_DIR=/var/lib/postgresql/data
OUT_DIR="${VALGRIND_OUT_DIR:-$REPO_ROOT/tmp_valgrind}"

cleanup() { stop_container "$CONTAINER"; }
trap cleanup EXIT

log_stage "VALGRIND MEMCHECK"

# ── Images ───────────────────────────────────────────────────────────────
build_pg_test_image

log_info "Building $VG_IMAGE (pg-tde-test + valgrind) ..."
$RT build \
    --build-arg BASE_IMAGE="${PG_TEST_IMAGE:-pg-tde-test}" \
    -f "$CI_DIR/containers/pg-valgrind.Containerfile" \
    -t "$VG_IMAGE:latest" \
    "$REPO_ROOT" 2>&1 | tail -3
log_ok "Image $VG_IMAGE built"

# ── Container with an idle PID 1 ─────────────────────────────────────────
# The stock entrypoint would start the postmaster for us, but we need it
# launched *under* valgrind, so we take over the lifecycle: idle PID 1, then
# initdb and postgres by hand.
log_info "Starting $CONTAINER (idle) ..."
$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run -d --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=postgres \
    --entrypoint sleep \
    "$VG_IMAGE:latest" infinity >/dev/null

cx() { $RT exec -u postgres "$CONTAINER" "$@"; }

log_info "initdb ..."
if ! cx bash -c "initdb -D $PGDATA_DIR -U postgres --auth=trust" >/dev/null 2>&1; then
    log_error "VALGRIND: initdb failed"
    $RT exec -u postgres "$CONTAINER" bash -c "initdb -D $PGDATA_DIR -U postgres --auth=trust" 2>&1 | tail -20
    exit 10
fi

cx bash -c "cat >> $PGDATA_DIR/postgresql.conf <<'CONF'
shared_preload_libraries = 'pg_vault_tde'
pg_vault_tde.dev_mode = on
pg_vault_tde.kms_provider = 'local'
pg_vault_tde.wallet_auto_open = off
log_min_messages = warning
# Memcheck serialises everything; keep the server small so startup is not
# dominated by zeroing shared buffers.
shared_buffers = 32MB
max_connections = 10
fsync = off
CONF"

# ── Postmaster under memcheck ────────────────────────────────────────────
log_info "Starting postmaster under valgrind memcheck (slow: 10-50x) ..."
$RT exec -u postgres -d "$CONTAINER" bash -c "
    valgrind \
        --tool=memcheck \
        --trace-children=yes \
        --child-silent-after-fork=no \
        --leak-check=full \
        --show-leak-kinds=definite,indirect \
        --errors-for-leak-kinds=definite,indirect \
        --track-origins=yes \
        --read-var-info=yes \
        --num-callers=30 \
        --error-limit=no \
        --suppressions=/etc/pg_vault_tde/valgrind.supp \
        --log-file=/tmp/valgrind/vg.%p.log \
        postgres -D $PGDATA_DIR -k /tmp
"

# initdb+startup under memcheck is slow; allow well past the normal timeout.
log_info "Waiting for the instrumented server (up to 300s) ..."
READY=0
for _ in $(seq 1 150); do
    if cx pg_isready -h /tmp -U postgres >/dev/null 2>&1; then READY=1; break; fi
    sleep 2
done
if [ "$READY" != "1" ]; then
    log_error "VALGRIND: server did not become ready"
    cx bash -c 'tail -40 /tmp/valgrind/vg.*.log' 2>/dev/null || true
    exit 10
fi
log_ok "Instrumented server ready"

# ── Workload ─────────────────────────────────────────────────────────────
$RT cp "$REPO_ROOT/sql/valgrind_workload.sql" "$CONTAINER:/tmp/valgrind_workload.sql"

log_info "Running workload ..."
START=$(timer_start)
cx psql -h /tmp -U postgres -v ON_ERROR_STOP=1 -c \
    "CREATE EXTENSION IF NOT EXISTS pg_vault_tde;" >/dev/null 2>&1
WORKLOAD_RC=0
if ! cx psql -h /tmp -U postgres -f /tmp/valgrind_workload.sql; then
    WORKLOAD_RC=1
    log_error "VALGRIND: workload itself failed"
fi
log_info "Workload finished in $(timer_fmt "$(timer_elapsed "$START")")"

# Clean shutdown so every backend flushes its memcheck report, including the
# leak summary — killing the container would discard exactly what we came for.
log_info "Stopping server cleanly to flush memcheck reports ..."
cx pg_ctl -D "$PGDATA_DIR" -m fast -w -t 120 stop >/dev/null 2>&1
sleep 5

# ── Collect and triage ───────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/vg.*.log
$RT cp "$CONTAINER:/tmp/valgrind" "$OUT_DIR/" 2>/dev/null || true
find "$OUT_DIR" -name 'vg.*.log' -exec mv -t "$OUT_DIR" {} + 2>/dev/null || true
rmdir "$OUT_DIR/valgrind" 2>/dev/null || true

# valgrind writes some logs 0600 under the container's uid.  The packaging
# build copies the working tree from inside a container that cannot then read
# them, which fails the tarball rather than merely bloating it (the excludes in
# run-install-test.sh and build_rpm.sh cover that too -- belt and braces, since
# anyone reading these reports by hand hits the same wall).
chmod -R u+rwX "$OUT_DIR" 2>/dev/null || true

LOGS=$(find "$OUT_DIR" -name 'vg.*.log' | wc -l)
log_info "Collected $LOGS memcheck logs into ${OUT_DIR#"$REPO_ROOT"/}/"

if [ "$LOGS" -eq 0 ]; then
    log_error "VALGRIND: no memcheck logs produced — the run did not happen"
    exit 10
fi

# An "error block" is the header line plus its stack.  Keep only blocks whose
# stack names our module: everything else belongs to the stock server.
OURS="$OUT_DIR/pg_vault_tde-findings.txt"
awk '
    /^==[0-9]+== [A-Z]/ { blk = $0 "\n"; inblk = 1; ours = 0; next }
    inblk && /^==[0-9]+== *$/ { if (ours) printf "%s\n", blk; inblk = 0; next }
    inblk { blk = blk $0 "\n"; if ($0 ~ /pg_vault_tde/) ours = 1 }
' "$OUT_DIR"/vg.*.log > "$OURS" 2>/dev/null

FINDINGS=$(grep -c '^==[0-9]*== [A-Z]' "$OURS" 2>/dev/null || true); FINDINGS=${FINDINGS:-0}

echo ""
log_info "── memcheck summary ─────────────────────────────────────────"
for kind in "Invalid free" "Invalid read" "Invalid write" "Mismatched free" \
            "Conditional jump" "Uninitialised value" "definitely lost"; do
    n=$(grep -c "$kind" "$OURS" 2>/dev/null || true); n=${n:-0}
    printf "    %-24s %s\n" "$kind" "$n"
done
echo ""

if [ "$FINDINGS" -gt 0 ]; then
    log_error "VALGRIND: $FINDINGS memcheck finding(s) implicating pg_vault_tde"
    head -60 "$OURS"
    log_error "Full reports: ${OURS#"$REPO_ROOT"/}"
    exit 10
fi

[ "$WORKLOAD_RC" -ne 0 ] && exit 10

log_ok "VALGRIND: no memcheck findings implicating pg_vault_tde"
exit 0
