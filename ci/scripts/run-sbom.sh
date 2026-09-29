#!/usr/bin/env bash
# ci/scripts/run-sbom.sh — SBOM of the source bundle and its vulnerability
# scan (PSQLE-182)
#
# The input and the tools of the release workflow (build-packages.yml): the
# bundle `make dist` archives — HEAD, filtered by .gitattributes — catalogued
# by syft into SPDX JSON, then the SBOM scanned by grype.  One container per
# tool, each pinned by digest.  The extension vendors no code and links
# OpenSSL, libcurl and libpq from the system, so the SBOM holds the bundle
# itself; the stage shows it stays that way.
#
# Informational, as on the release: vulnerabilities are counted, never a
# failure by themselves.  grype downloads its database on every run (~3 GB
# unpacked, about a minute) inside its container: no cache in the tree, where
# every image build would copy it, and nothing to mount on Bitbucket.
#
# Output: tmp_security/sbom/pg_vault_tde-<VERSION>.spdx.json and .grype.json.
# Exit code: 0 when both tools ran, 15 otherwise.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
set +e

SYFT_IMAGE="${SYFT_IMAGE:-docker.io/anchore/syft:v1.52.0@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02}"
GRYPE_IMAGE="${GRYPE_IMAGE:-docker.io/anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3}"

VERSION=$(cat "$REPO_ROOT/VERSION")
WORK="$REPO_ROOT/tmp_security/sbom"
SBOM="pg_vault_tde-$VERSION.spdx.json"
SCAN="pg_vault_tde-$VERSION.grype.json"

log_stage "SBOM (source bundle) and vulnerability scan"

rm -rf "$WORK"
mkdir -p "$WORK/bundle"
# Bitbucket's dockerd remaps user namespaces: mode bits cross the remap,
# ownership does not.
chmod 0777 "$WORK"
if ! git -C "$REPO_ROOT" archive --prefix="pg_vault_tde-$VERSION/" HEAD | tar -x -C "$WORK/bundle"; then
    log_error "SBOM: git archive of HEAD failed"
    exit 15
fi

log_info "syft: cataloguing the bundle ..."
if ! $RT run --rm -v "$WORK":/work "$SYFT_IMAGE" scan dir:/work/bundle -q \
        --source-name pg_vault_tde --source-version "$VERSION" \
        -o "spdx-json=/work/$SBOM"; then
    log_error "SBOM: syft failed"
    exit 15
fi
rm -rf "$WORK/bundle"

log_info "grype: scanning the SBOM (downloads its database) ..."
if ! $RT run --rm -v "$WORK":/work "$GRYPE_IMAGE" "sbom:/work/$SBOM" -q \
        -o json --file "/work/$SCAN"; then
    log_error "SBOM: grype failed"
    exit 15
fi

PKGS=$(jq '.packages | length' "$WORK/$SBOM")
ALL=$(jq '.matches | length' "$WORK/$SCAN")
HIGH=$(jq '[.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")] | length' "$WORK/$SCAN")

echo ""
log_info "── SBOM summary ─────────────────────────────────────────────"
printf "    %-34s %s\n" "packages" "$PKGS"
printf "    %-34s %s\n" "vulnerabilities" "$ALL"
printf "    %-34s %s\n" "of which critical or high" "$HIGH"
echo ""

log_ok "SBOM: $PKGS package(s), $ALL vulnerability match(es); grype database built $(jq -r '.descriptor.db.status.built' "$WORK/$SCAN")"
exit 0
