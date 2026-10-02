#!/usr/bin/env bash
# ci/scripts/run-security-report.sh — the automated evidence of a security
# review (PSQLE-182)
#
# Runs the stages a review cites (doc/SECURITY-REVIEW.md › Workflow) and writes
# doc/security/evidence/v<VERSION>.md: the commit they ran on, the tools and
# their versions, and each stage's result and counts.  Counts come from the
# stages' own summaries, so two runs on one commit write the same numbers; the
# raw logs stay in tmp_security/<stage>.log.
#
# Run it on the release commit, with a clean tree: the report says which
# commit it saw and whether anything outside doc/security/ was modified.
# The SBOM and its vulnerability scan (run-sbom.sh) are those of the source
# bundle, as the release publishes them (PSQLE-180), and informational.
# CodeQL runs on GitHub: with GITHUB_TOKEN set the report counts its open
# alerts, otherwise it links them.
#
# Exit code: 0 when every stage passed, otherwise the first failing stage's.
# The report is written either way.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
set +e

VERSION=$(cat "$REPO_ROOT/VERSION")
PG_MAJOR="${PG_VERSION:-${PG_MAJOR:-18}}"
REPORT="$REPO_ROOT/doc/security/evidence/v$VERSION.md"
LOG_DIR="$REPO_ROOT/tmp_security"
GH_REPO="labmiriade/pg_vault_tde"
STAGES=(pins semgrep sbom errorpath scan-build ubsan asan valgrind cassert)

log_stage "SECURITY REPORT (pg_vault_tde $VERSION)"
mkdir -p "$LOG_DIR" "$(dirname "$REPORT")"
rm -rf "$LOG_DIR"/*.log "$LOG_DIR/sbom"

declare -A RESULT COUNTS VERDICT
RC=0

# The label/count lines of a stage's "── ... summary ──" block.
summary_counts() {
    sed -nE '/summary ─/,/^\s*$/ s/^    (.*[^ ]) +([0-9]+)$/\1 \2/p' "$1" | paste -sd';' | sed 's/;/; /g'
}

stage_counts() {        # $1 = stage, $2 = log without colours
    local log="$2"
    case "$1" in
        pins)
            echo "unpinned references $(grep '^pins: ' "$log" | grep -vc '^pins: every')" ;;
        semgrep)
            echo "$(grep -oE 'Rule tests: [0-9]+/[0-9]+' "$log" | tail -1); $(grep -oE 'Ran [0-9]+ rules on [0-9]+ files: [0-9]+ findings?' "$log" | tail -1); nosemgrep in src/ $(grep -rc 'nosemgrep' "$REPO_ROOT/src" | awk -F: '{n += $2} END {print n + 0}')" ;;
        errorpath)
            grep -oE 'ALL [0-9]+ TESTS PASSED' "$log" | tail -1 | awk '{print $2 " tests passed"}' ;;
        cassert)
            echo "$(grep -oE '[a-z0-9_]+\.sql: [0-9]+ passed' "$log" | awk '{n++; t += $2} END {if (n) print n " SQL files, " t " tests passed"}'); TAP $(grep -oE 'Files=[0-9]+, Tests=[0-9]+' "$log" | tail -1)" ;;
        *)
            summary_counts "$log" ;;
    esac
}

for s in "${STAGES[@]}"; do
    log_info "Running $s (log: tmp_security/$s.log) ..."
    bash "$SCRIPT_DIR/run-$s.sh" > "$LOG_DIR/$s.raw" 2>&1
    src=$?
    sed 's/\x1b\[[0-9;]*m//g' "$LOG_DIR/$s.raw" > "$LOG_DIR/$s.log"
    rm -f "$LOG_DIR/$s.raw"
    COUNTS[$s]=$(stage_counts "$s" "$LOG_DIR/$s.log")
    # The stage's last verdict line, without its timing.
    VERDICT[$s]=$(grep -E '^(\[ci\] )?(pins|[A-Z][A-Z -]+):' "$LOG_DIR/$s.log" | tail -1 \
        | sed -E 's/^\[ci\] //; s/^pins: //; s/ *\([0-9]+m[0-9]+s\)//g')
    if [ "$src" -eq 0 ]; then
        RESULT[$s]=PASS; log_ok "$s: ${VERDICT[$s]}"
    else
        RESULT[$s]="FAIL ($src)"; log_error "$s: exit $src — ${VERDICT[$s]}"
        [ "$RC" -eq 0 ] && RC=$src
    fi
done

# ── Tool versions, read from the images the stages just built ───────────
in_image() { $RT run --rm --entrypoint sh -e LD_PRELOAD= "$1" -c "$2" 2>/dev/null | head -1; }
image_of() { sed -nE "s/^$1=\"\\\$\\{$1:-(.*)\\}\"\$/\\1/p" "$SCRIPT_DIR/$2"; }
SEMGREP_IMAGE=$(image_of SEMGREP_IMAGE run-semgrep.sh)
SBOM_JSON="$LOG_DIR/sbom/pg_vault_tde-$VERSION.spdx.json"
SCAN_JSON="$LOG_DIR/sbom/pg_vault_tde-$VERSION.grype.json"
declare -A TOOL=(
    [pins]="ci/scripts/run-pins.sh"
    [semgrep]="semgrep $(in_image "$SEMGREP_IMAGE" 'semgrep --version') (\`$SEMGREP_IMAGE\`), rules in \`ci/semgrep/\`"
    [sbom]="$(jq -r '.creationInfo.creators[] | select(startswith("Tool:")) | sub("Tool: "; "")' "$SBOM_JSON" 2>/dev/null) (\`$(image_of SYFT_IMAGE run-sbom.sh)\`), grype-$(jq -r '.descriptor.version' "$SCAN_JSON" 2>/dev/null) (\`$(image_of GRYPE_IMAGE run-sbom.sh)\`), database built $(jq -r '.descriptor.db.status.built' "$SCAN_JSON" 2>/dev/null)"
    [errorpath]="$(in_image pg-tde-test 'postgres --version'), local wallet"
    [scan-build]="$(in_image pg-tde-analyze 'clang --version')"
    [ubsan]="$(in_image pg-tde-ubsan 'gcc --version'), -fsanitize=undefined"
    [asan]="$(in_image pg-tde-asan 'gcc --version'), -fsanitize=address, runtime preloaded"
    [valgrind]="$(in_image pg-tde-valgrind 'valgrind --version') memcheck"
    [cassert]="$(in_image pg-tde-cassert 'pg_config --version') from source, --enable-cassert, -DUSE_VALGRIND"
)
PG_BASE=$($RT image inspect --format '{{index .RepoDigests 0}}' "postgres:$PG_MAJOR" 2>/dev/null)

# The shared libraries the module and the client tools need (DT_NEEDED), by
# soname: the ABI they were built against.  Which release of it runs is the
# system's, so none is named.  Read from the UBSan image, the one with
# binutils; its build differs by the sanitizer runtime, left out here with the
# C library.
needed() {              # $1 = files, expanded in the image
    $RT run --rm --entrypoint sh pg-tde-ubsan -c "for f in $1; do objdump -p \"\$f\"; done" 2>/dev/null \
        | awk '/NEEDED/ {print $2}' \
        | grep -vE '^(libubsan|libasan|libc|libm|libdl|libpthread|librt|ld-linux)[.-]' \
        | sed -E 's/^(libcrypto|libssl)\.so\.([0-9]+)$/OpenSSL \2 (`&`)/; t; s/^(lib[a-z0-9_]+)\.so\.[0-9]+$/\1 (`&`)/' \
        | LC_ALL=C sort -u | paste -sd, | sed 's/,/, /g'
}
MODULE_LIBS=$(needed '$(pg_config --pkglibdir)/pg_vault_tde.so')
TOOLS_LIBS=$(needed '$(pg_config --bindir)/*_tde')

# ── What was tested ──────────────────────────────────────────────────────
COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "${BITBUCKET_COMMIT:-unknown}")
DESCRIBE=$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null)
DIRTY=$(git -C "$REPO_ROOT" status --porcelain -- . ':(exclude)doc/security' 2>/dev/null | wc -l)
if [ "$DIRTY" -eq 0 ]; then TREE="clean"; else TREE="**$DIRTY file(s) modified or untracked outside \`doc/security/\`**: not the commit above"; fi

CODEQL_URL="https://github.com/$GH_REPO/security/code-scanning"
if [ -n "${GITHUB_TOKEN:-}" ] && N=$(curl -fsS -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$GH_REPO/code-scanning/alerts?state=open&per_page=100" | jq length); then
    [ "$N" -ge 100 ] && N="100 or more"
    CODEQL="$N open alert(s) on GitHub's default branch at the time of the report — [list]($CODEQL_URL)"
else
    CODEQL="not queried (no GITHUB_TOKEN) — [open alerts]($CODEQL_URL)"
fi

FAILED=""
for s in "${STAGES[@]}"; do [ "${RESULT[$s]}" = PASS ] || FAILED+=" $s"; done

{
    echo "# Security evidence — pg_vault_tde $VERSION"
    echo
    echo "Written by \`make ci-security-report\` (\`ci/scripts/run-security-report.sh\`), for the"
    echo "review of this release ([doc/SECURITY-REVIEW.md](../../SECURITY-REVIEW.md#workflow))."
    echo "Raw logs: \`tmp_security/<stage>.log\` of the run, the artifacts of the Bitbucket"
    echo "custom pipeline \`security-report\`."
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| Commit | \`$COMMIT\` (\`$DESCRIBE\`) |"
    echo "| Working tree | $TREE |"
    echo "| Date | $(date -u '+%Y-%m-%d %H:%M UTC') |"
    echo "| Runtime | $($RT --version | head -1) |"
    echo "| PostgreSQL | $PG_MAJOR (\`${PG_BASE:-postgres:$PG_MAJOR}\`) |"
    echo "| Runtime libraries | From the system, not in the SBOM. Module: ${MODULE_LIBS:-unknown}. Client tools: ${TOOLS_LIBS:-unknown}. PKCS#11: the module \`pkcs11_library\` names, loaded at run time |"
    if [ -z "$FAILED" ]; then
        echo "| Result | **PASS** — every stage passed |"
    else
        echo "| Result | **FAIL** —$FAILED |"
    fi
    echo
    echo "## Stages"
    echo
    echo "| Stage | Result | Counts | Tool |"
    echo "|---|---|---|---|"
    for s in "${STAGES[@]}"; do
        echo "| \`$s\` | ${RESULT[$s]} | ${COUNTS[$s]:-${VERDICT[$s]}} | ${TOOL[$s]} |"
    done
    echo
    echo "The SBOM and its scan, in \`tmp_security/sbom/\`, are of the bundle \`make dist\` archives,"
    echo "the one the release publishes with its signed \`SHA256SUMS\` (PSQLE-180). The runtime"
    echo "libraries above are not in it: the release carries no copy of them, and their fixes"
    echo "come with the system's updates. Vulnerability counts depend on the grype database of"
    echo "the day, and never fail the report."
    echo
    echo "## Suppressed findings"
    echo
    echo "Each line a Semgrep rule would report and that was judged right in context;"
    echo "the review checks every one."
    echo
    (cd "$REPO_ROOT" && grep -rn 'nosemgrep' src) | sed -E 's|^([^:]+:[0-9]+):\s*(.*)$|- `\1`: `\2`|'
    echo
    echo "## Not run here"
    echo
    echo "- CodeQL (\`security-extended\`, \`.github/workflows/codeql.yml\`): $CODEQL."
    echo "- The functional battery: \`make ci-all\`, or the Bitbucket custom pipeline \`test-all\`."
} > "$REPORT"

log_info "Report: ${REPORT#"$REPO_ROOT"/}"
if [ "$RC" -ne 0 ]; then
    log_error "SECURITY REPORT: failed stage(s):$FAILED"
    exit "$RC"
fi
log_ok "SECURITY REPORT: every stage passed"
exit 0
