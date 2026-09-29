#!/usr/bin/env bash
# ci/scripts/run-pins.sh — what CI and the release pipeline fetch is pinned
#
# A tag can be moved and an image tag re-pushed: whoever controls it then runs
# code in our pipelines, and in the release job, with its secrets.  So
# (PSQLE-180):
#
#   1. every GitHub Action is referenced by a full commit SHA, with the
#      version it corresponds to in a comment:  uses: org/repo@<40 hex>  # vX.Y.Z
#   2. every container image from a registry is pinned by digest
#      (name:version@sha256:...), except the families below that float on
#      purpose, and the images built from this repository;
#   3. every binary downloaded from a GitHub release is checked against a
#      SHA-256 written in the same file.
#
# Floating on purpose — each tracks its own security and minor releases, and
# that is the point: the PostgreSQL images are how CI met the 17.11 change to
# logical decoding the week it shipped.  None of them reaches a release
# artifact that PGDG ships; the release packages are built on distribution
# images the same way.
#   postgres:<major>          the server under test, every minor
#   debian:<release>[-slim]   the base of the cassert and vault-mock images
#   ubuntu:<release>          the Bitbucket build container
#   golang:<ver>-<release>    builds the Vault mock, a test tool
#
# Exit code: 0 when everything is pinned, 1 otherwise (each offence printed).
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

fail=0
offend() { echo "pins: $*"; fail=1; }

# ── 1. GitHub Actions ──────────────────────────────────────────────────────
while IFS= read -r line; do
    file=${line%%:*}; rest=${line#*:}; lineno=${rest%%:*}; text=${rest#*:}
    ref=$(sed -E 's/.*uses:[[:space:]]*([^[:space:]#]+).*/\1/' <<<"$text")
    case "$ref" in
        ./*|docker://*) continue ;;                 # local action, image
    esac
    if ! [[ "$ref" =~ @[0-9a-f]{40}$ ]]; then
        offend "$file:$lineno: action not pinned by commit SHA: $ref"
    elif ! [[ "$text" =~ \#[[:space:]]*v[0-9]+(\.[0-9]+)*[[:space:]]*$ ]]; then
        offend "$file:$lineno: pinned action lacks its version comment (# vX.Y.Z): $ref"
    fi
done < <(grep -nE '^[[:space:]]*-?[[:space:]]*uses:' .github/workflows/*.yml)

# ── 2. Container images ────────────────────────────────────────────────────
floating='^(docker\.io/)?(library/)?(postgres:[0-9]+|debian:[a-z]+(-slim)?|ubuntu:[0-9]+\.[0-9]+|golang:[0-9.]+-[a-z]+)$'

check_image() {       # $1 = where, $2 = image reference
    local where="$1" img="$2"
    case "$img" in
        *'${'*'}'*)                                   # a variable: check its default
            if [[ "$img" =~ \$\{[A-Z_]+:-([^}]+)\} ]]; then
                img="${BASH_REMATCH[1]}${img#*\}}"
            else
                return 0                              # built or chosen by the caller
            fi ;;
    esac
    [[ "$img" == *@sha256:* ]] && return 0
    [[ "$img" =~ $floating ]] && return 0
    [[ "$img" != */* && "$img" != *.*:* && ! "$img" =~ ^[a-z]+:[0-9] ]] && return 0  # built here
    offend "$where: image not pinned by digest: $img"
}

while IFS= read -r line; do
    where=${line%%:*}:$(cut -d: -f2 <<<"$line")
    img=$(sed -E 's/^[^:]+:[0-9]+:[[:space:]]*FROM[[:space:]]+([^[:space:]]+).*/\1/' <<<"$line")
    check_image "$where" "$img"
done < <(grep -nE '^[[:space:]]*FROM[[:space:]]' Containerfile ci/containers/*.Containerfile)

while IFS= read -r line; do
    where=${line%%:*}:$(cut -d: -f2 <<<"$line")
    img=$(sed -E 's/^[^:]+:[0-9]+:[[:space:]]*image:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/' <<<"$line")
    check_image "$where" "$img"
done < <(grep -nE '^[[:space:]]*image:[[:space:]]' ci/*.yml bitbucket-pipelines.yml)

# Images the CI scripts run by name.  A tag computed at run time (${...}) is the
# install test choosing a distribution, which floats with it on purpose.
while IFS= read -r line; do
    where=${line%%:*}:$(cut -d: -f2 <<<"$line")
    for img in $(grep -oE 'docker\.io/[a-z0-9._/-]+:[A-Za-z0-9._${#:-]+(@sha256:[0-9a-f]{64})?' <<<"${line#*:*:}"); do
        [[ "$img" == *'${'* ]] && continue
        check_image "$where" "$img"
    done
done < <(grep -nE 'docker\.io/' ci/scripts/*.sh | grep -v '^[^:]*:[0-9]*:[[:space:]]*#')

# ── 3. Downloaded binaries ─────────────────────────────────────────────────
for f in bitbucket-pipelines.yml .github/workflows/*.yml ci/containers/*.Containerfile; do
    downloads=$(grep -c 'releases/download/' "$f")
    checks=$(grep -cE 'sha256sum (-c|--check)' "$f")
    if [ "$downloads" -gt 0 ] && [ "$checks" -lt "$downloads" ]; then
        offend "$f: $downloads download(s) from a release, $checks checksum check(s)"
    fi
done

[ "$fail" -eq 0 ] && echo "pins: every action, image and download is pinned"
exit "$fail"
