#!/usr/bin/env bash
# ci/scripts/run-scan-build.sh — Clang static analyzer over the extension.
#
# Compile-only, so it is the fastest of the deep-checking stages and the only
# one that needs no running server.
#
# THE PGXS WRINKLE
#
# scan-build normally intercepts a build by exporting CC=ccc-analyzer.  That
# does not work here: PGXS pulls CC from the server's Makefile.global, and a
# Makefile assignment beats an environment variable.  The wrapper therefore has
# to be passed on the make command line (`make CC=<ccc-analyzer>`), where it
# does win.  Without that the stage silently analyses nothing and reports a
# clean run — which is worse than failing.  The path check below is what stops
# that from happening quietly.
#
# Exit code: 0 clean, 12 on analyzer findings or setup failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

CONTAINER="pg-tde-analyze-$$"
AN_IMAGE="${PG_ANALYZE_IMAGE:-pg-tde-analyze}"
OUT_DIR="${SCAN_OUT_DIR:-$REPO_ROOT/tmp_scanbuild}"

cleanup() { $RT rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

log_stage "CLANG STATIC ANALYZER (scan-build)"

log_info "Building $AN_IMAGE ..."
$RT build \
    --build-arg PG_MAJOR="${PG_VERSION:-${PG_MAJOR:-18}}" \
    -f "$CI_DIR/containers/pg-analyze.Containerfile" \
    -t "$AN_IMAGE:latest" \
    "$REPO_ROOT" 2>&1 | tail -3
log_ok "Image $AN_IMAGE built"

$RT rm -f "$CONTAINER" 2>/dev/null || true
$RT run -d --name "$CONTAINER" --entrypoint sleep "$AN_IMAGE:latest" infinity >/dev/null

log_info "Locating the ccc-analyzer wrapper ..."
CCC=$($RT exec "$CONTAINER" bash -c \
    'find /usr/libexec /usr/share/clang /usr/lib/llvm-* -name ccc-analyzer -type f 2>/dev/null | head -1')
if [ -z "$CCC" ]; then
    log_error "SCAN-BUILD: ccc-analyzer not found — the analyzer would not run"
    exit 12
fi
log_ok "ccc-analyzer: $CCC"

log_info "Analysing ..."
START=$(timer_start)
set +e
$RT exec "$CONTAINER" bash -c "
    cd /build && make clean >/dev/null 2>&1
    scan-build -o /tmp/scan \
        --status-bugs \
        --keep-cc \
        -enable-checker security.insecureAPI \
        -enable-checker alpha.security.ArrayBoundV2 \
        -enable-checker alpha.core.CastSize \
        make CC='$CCC' 2>&1 | tail -60
"
SB_RC=$?
set -e
log_info "Analysis finished in $(timer_fmt "$(timer_elapsed "$START")")"

# --status-bugs makes scan-build exit non-zero when it reports anything, so the
# exit code alone cannot distinguish "found bugs" from "build broke".  Count
# the reports to tell them apart.
BUGS=$($RT exec "$CONTAINER" bash -c \
    'find /tmp/scan -name "report-*.html" 2>/dev/null | wc -l' 2>/dev/null || echo 0)

mkdir -p "$OUT_DIR"
rm -rf "${OUT_DIR:?}"/*
$RT cp "$CONTAINER:/tmp/scan" "$OUT_DIR/" 2>/dev/null || true

# Sanity: if nothing was compiled, the clean result is meaningless.
ANALYSED=$($RT exec "$CONTAINER" bash -c 'ls /build/src/*.o /build/src/*/*.o 2>/dev/null | wc -l' 2>/dev/null || echo 0)
if [ "$ANALYSED" -eq 0 ]; then
    log_error "SCAN-BUILD: no objects were produced — the build did not run"
    exit 12
fi
log_info "Objects analysed: $ANALYSED"

echo ""
log_info "── analyzer summary ─────────────────────────────────────────"
printf "    %-28s %s\n" "reports" "$BUGS"
if [ "$BUGS" -gt 0 ]; then
    $RT exec "$CONTAINER" bash -c \
        'grep -ho "<!-- BUGDESC .* -->" /tmp/scan/*/report-*.html 2>/dev/null' \
        | sed 's/<!-- BUGDESC //; s/ -->//' | sort | uniq -c | sort -rn | sed 's/^/    /'
fi
echo ""

if [ "$BUGS" -gt 0 ]; then
    log_error "SCAN-BUILD: $BUGS analyzer finding(s)"
    log_error "HTML reports: ${OUT_DIR#"$REPO_ROOT"/}/  (open index.html)"
    exit 12
fi

if [ "$SB_RC" -ne 0 ]; then
    log_error "SCAN-BUILD: the instrumented build itself failed (rc=$SB_RC)"
    exit 12
fi

log_ok "SCAN-BUILD: no analyzer findings"
exit 0
