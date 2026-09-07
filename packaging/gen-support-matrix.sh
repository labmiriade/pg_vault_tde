#!/usr/bin/env bash
# packaging/gen-support-matrix.sh — regenerate the support matrix in
# doc/pg_vault_tde.md from packaging/build-matrix.json, its single source of truth.
#
# Idempotent: run it, commit the result together with the JSON change.
# Nothing in CI enforces this by design — see packaging/BUILD_MATRIX.md.
#
# Requires: jq
set -euo pipefail

cd "$(dirname "$0")/.."

MATRIX=packaging/build-matrix.json
DOC=doc/pg_vault_tde.md
BEGIN='<!-- BEGIN GENERATED: support matrix (packaging/gen-support-matrix.sh) -->'
END='<!-- END GENERATED: support matrix -->'

command -v jq >/dev/null || { echo "gen-support-matrix: jq is required" >&2; exit 1; }

# Fail loudly on a row missing a flag: jq would silently render it as "not
# verified", quietly downgrading a combination nobody meant to downgrade.
jq -e 'type == "array" and length > 0 and
       all(.[]; has("format") and has("os") and has("pg")
                and (has("functional_test") and (.functional_test | type == "boolean"))
                and (has("install_test")    and (.install_test    | type == "boolean")))' \
   "$MATRIX" >/dev/null \
  || { echo "gen-support-matrix: $MATRIX has a row missing format/os/pg or a boolean verification flag" >&2; exit 1; }

table=$(jq -r '
  def mark(b): if b then "yes" else "no" end;
  "| Format | OS | PG | Functional suite | Package install |",
  "|---|---|---|---|---|",
  (.[] | "| \(.format) | `\(.os)` | \(.pg) | \(mark(.functional_test)) | \(mark(.install_test)) |")
' "$MATRIX")

grep -qF "$BEGIN" "$DOC" || { echo "gen-support-matrix: begin marker not found in $DOC" >&2; exit 1; }
grep -qF "$END"   "$DOC" || { echo "gen-support-matrix: end marker not found in $DOC" >&2; exit 1; }

awk -v b="$BEGIN" -v e="$END" -v repl="$table" '
  index($0, b) { print; print ""; print repl; print ""; skip = 1; next }
  index($0, e) { skip = 0 }
  !skip
' "$DOC" > "$DOC.tmp"

mv "$DOC.tmp" "$DOC"
echo "gen-support-matrix: $DOC updated from $MATRIX ($(jq length "$MATRIX") rows)"
