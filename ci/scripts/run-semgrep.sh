#!/usr/bin/env bash
# ci/scripts/run-semgrep.sh — the project's own Semgrep rules (PSQLE-181)
#
# Each rule in ci/semgrep/ encodes a mistake this code base has made or must
# not make — superuser() inside SECURITY DEFINER, a write to rd_tableam, a
# non-constant-time MAC compare, a secret freed without being cleansed or put
# into a message, a random source that is not pg_strong_random(), a client
# call outside the extension's schema — and sits next to a test file whose
# "ruleid:" and "ok:" lines say where it must and must not fire.
#
# First every rule is checked against its test file (semgrep --test), then all
# of them run on src/.  Any finding fails the stage: a line that is right in
# context carries a "nosemgrep: <rule>" comment saying why.  Offline: the
# rules are local, and --metrics=off.
#
# Exit code: 0 clean, 14 on a failed rule test or a finding.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
set +e

SEMGREP_IMAGE="${SEMGREP_IMAGE:-docker.io/semgrep/semgrep:1.178.0@sha256:32e459968daabe7ab86968184a29109b9564aa00392401156f9788452b42786b}"

semgrep() { $RT run --rm -v "$REPO_ROOT":/src:ro -w /src "$SEMGREP_IMAGE" semgrep "$@"; }

log_stage "SEMGREP (project rules)"
START=$(timer_start)

log_info "Checking each rule against its test file ..."
OUT=$(semgrep --test --metrics=off ci/semgrep 2>&1)
if ! grep -qE '[0-9]+/[0-9]+: .*All tests passed' <<<"$OUT"; then
    grep -vE '^\s*$|Scanning|Scan Status|[─│┌└┐┘]' <<<"$OUT" | tail -30
    log_error "SEMGREP: a rule does not do what its test file says"
    exit 14
fi
log_ok "Rule tests: $(grep -oE '[0-9]+/[0-9]+: .*All tests passed' <<<"$OUT")"

log_info "Scanning src/ ..."
if ! semgrep scan --metrics=off --disable-version-check --no-git-ignore \
        --config ci/semgrep --error src; then
    log_error "SEMGREP: findings in src/ (fix them, or add a nosemgrep comment saying why)"
    exit 14
fi

log_ok "SEMGREP: no finding ($(timer_fmt "$(timer_elapsed "$START")"))"
exit 0
