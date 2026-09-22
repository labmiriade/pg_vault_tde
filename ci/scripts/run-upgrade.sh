#!/usr/bin/env bash
# ci/scripts/run-upgrade.sh — Read data written by the PREVIOUS RELEASE
#
# Every other suite in this repo reads only data it wrote in the same run.
# Writer and reader therefore move together: a change to the on-disk format,
# or to anything the AAD is derived from, leaves the whole suite green while
# data already on disk becomes unreadable.  That is not hypothetical — it has
# shipped twice:
#
#   * 1.7.1 rebound the AEAD AAD to the effective relid.  Out-of-line TOAST
#     written by <= 1.7.0 stopped decrypting.  VACUUM FULL could not repair it,
#     because VACUUM FULL rewrites tuples by DECRYPTING them first; the release
#     notes carry a dump-with-the-old-binary procedure instead.
#   * PSQLE-165 (v5 tuple layout).  v4 rows stay readable, but keep a data area
#     the core cannot walk, so UPDATE on them still dies until they are
#     rewritten.  Here VACUUM FULL is the remedy.
#
# Which of those two worlds a change lands in is exactly what this stage
# reports, and it cannot be known without reading bytes written by an earlier
# build.  The baseline is the most recent v* TAG, not the previous commit: the
# question is what someone running the released version will experience, and a
# commit halfway through a format change is not a state anyone has installed.
#
# Declared expectations live in ci/upgrade-compat.expected.
#
# Exit code: 0 on success, 2 on failure, 0 + a loud warning when skipped.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

PG_MAJOR="${PG_VERSION:-${PG_MAJOR:-18}}"
CONTAINER="pg-tde-upgrade-$$"
DATA_VOL="pg-tde-upgrade-data-$$"
WALLET_VOL="pg-tde-upgrade-wallet-$$"
WORKTREE="$(mktemp -d -t pg-tde-baseline-XXXXXX)"
EXPECTED_FILE="$CI_DIR/upgrade-compat.expected"
PASSPHRASE="tde_regression_pass_2026"

cleanup() {
    stop_container "$CONTAINER"
    $RT volume rm -f "$DATA_VOL" "$WALLET_VOL" 2>/dev/null || true
    git -C "$REPO_ROOT" worktree remove --force "$WORKTREE" 2>/dev/null || true
    rm -rf "$WORKTREE" 2>/dev/null || true
}
trap cleanup EXIT

log_stage "UPGRADE COMPATIBILITY (data written by the previous release)"

# ── Baseline tag ─────────────────────────────────────────────────────────
BASELINE="$(git -C "$REPO_ROOT" describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)"
if [[ -z "$BASELINE" ]]; then
    log_warn "UPGRADE: no v* tag reachable from HEAD — nothing to upgrade FROM."
    log_warn "         In CI this usually means a shallow clone: fetch tags to enable this stage."
    exit 0
fi
log_info "Baseline release: $BASELINE (current tree: $(cat "$REPO_ROOT/VERSION"))"

# ── Declared expectations ────────────────────────────────────────────────
if [[ ! -f "$EXPECTED_FILE" ]]; then
    log_error "UPGRADE: $EXPECTED_FILE is missing"
    exit 2
fi
EXP_READABLE="$(grep -E '^readable_after_upgrade=' "$EXPECTED_FILE" | cut -d= -f2)"
EXP_UPDATE="$(grep -E '^update_in_place_before_vacuum=' "$EXPECTED_FILE" | cut -d= -f2)"
log_info "Declared: readable_after_upgrade=$EXP_READABLE update_in_place_before_vacuum=$EXP_UPDATE"

# ── Images: baseline (from the tag's own tree) and current ───────────────
BASELINE_IMAGE="pg-tde-baseline:${BASELINE}-pg${PG_MAJOR}"
if $RT image inspect "$BASELINE_IMAGE" >/dev/null 2>&1 && [[ -z "${UPGRADE_REBUILD_BASELINE:-}" ]]; then
    log_ok "Baseline image $BASELINE_IMAGE already built (set UPGRADE_REBUILD_BASELINE=1 to force)"
else
    log_info "Checking out $BASELINE and building $BASELINE_IMAGE ..."
    # A worktree, not `git archive`: .gitattributes marks /ci export-ignore, so
    # an archive of the tag would not even contain the Containerfile.
    rm -rf "$WORKTREE"
    git -C "$REPO_ROOT" worktree add --detach "$WORKTREE" "$BASELINE" >/dev/null 2>&1 || {
        log_error "UPGRADE: could not create a worktree at $BASELINE"; exit 2; }
    $RT build --build-arg PG_MAJOR="$PG_MAJOR" \
        -f "$WORKTREE/ci/containers/pg-test.Containerfile" \
        -t "$BASELINE_IMAGE" "$WORKTREE" 2>&1 | tail -3
    log_ok "Baseline image built"
fi

build_pg_test_image

$RT volume rm -f "$DATA_VOL" "$WALLET_VOL" 2>/dev/null || true
$RT volume create "$DATA_VOL"   >/dev/null
$RT volume create "$WALLET_VOL" >/dev/null

# The postgres image changed where the data volume belongs in 18: mounting it
# at /var/lib/postgresql/data is refused ("unused mount/volume") because the
# cluster now lives in a major-version subdirectory of /var/lib/postgresql, so
# that pg_upgrade --link can cross it. 17 and earlier still want .../data.
if [[ "$PG_MAJOR" -ge 18 ]]; then
    DATA_MOUNT="/var/lib/postgresql"
else
    DATA_MOUNT="/var/lib/postgresql/data"
fi

start_upgrade_container() {
    local image="$1"
    $RT rm -f "$CONTAINER" 2>/dev/null || true
    $RT run --rm -d --name "$CONTAINER" \
        -e POSTGRES_PASSWORD=postgres \
        -v "$DATA_VOL:$DATA_MOUNT" \
        -v "$WALLET_VOL:/var/lib/pg_vault_tde" \
        "$image" \
        postgres \
            -c "shared_preload_libraries=pg_vault_tde" \
            -c "pg_vault_tde.dev_mode=on" \
            -c "pg_vault_tde.kms_provider=local" \
            -c "pg_vault_tde.wallet_auto_open=off" \
            -c "pg_vault_tde.wallet_dev_mode_passphrase=$PASSPHRASE" \
            -c "log_min_messages=warning" >/dev/null
    wait_pg_ready "$CONTAINER" 60
}

# One fingerprint over every fixture table: if any byte of any row changes,
# this changes.  Deliberately excludes nothing — VACUUM FULL must preserve it.
read -r -d '' FINGERPRINT <<'SQL' || true
SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (
    SELECT 'p:' || id || ':' || payload                     AS x FROM up_plain
    UNION ALL
    SELECT 'k:' || key || ':' || pad || ':' || payload      AS x FROM up_late_key
    UNION ALL
    SELECT 't:' || id || ':' || length(big) || ':' || md5(big) AS x FROM up_toast
    UNION ALL
    SELECT 'n:' || coalesce(a::text,'-') || ':' || coalesce(b,'-')
                || ':' || coalesce(c::text,'-')             AS x FROM up_nulls
) s;
SQL

# ── Phase 1: write with the baseline build ───────────────────────────────
log_info "Phase 1 — writing the fixture with $BASELINE ..."
start_upgrade_container "$BASELINE_IMAGE" || { log_error "UPGRADE: baseline container did not start"; exit 2; }

FIXTURE_SQL="$(mktemp -t pg-tde-upgrade-fixture-XXXXXX.sql)"
cat > "$FIXTURE_SQL" <<SQL
SELECT pg_vault_tde_wallet_init('$PASSPHRASE');
CREATE EXTENSION IF NOT EXISTS pg_vault_tde;

-- the common shape: key first, offset cached, never walked
CREATE TABLE up_plain (id int4 PRIMARY KEY, payload text) USING encrypted_heap;
INSERT INTO up_plain SELECT g, repeat('p', 80) || g FROM generate_series(1, 200) g;

-- the PSQLE-165 shape: indexed attribute behind a variable-length one
CREATE TABLE up_late_key (pad text, payload text, key int4) USING encrypted_heap;
CREATE INDEX up_late_key_idx ON up_late_key USING tde_btree (key tde_int4_enc_ops);
INSERT INTO up_late_key SELECT repeat('a', 120), repeat('b', 120), g FROM generate_series(1, 200) g;

-- the 1.7.1 shape: genuinely out-of-line TOAST, high entropy so it stays there
CREATE TABLE up_toast (id int4, big text) USING encrypted_heap;
INSERT INTO up_toast SELECT g, string_agg(md5((g * 1000 + s)::text), '')
  FROM generate_series(1, 10) g, generate_series(1, 400) s GROUP BY g;

-- NULLs in the bitmap, which is the branch the attribute walk takes.
--
-- Deliberately NOT an all-NULL row: the baseline has to be able to read back
-- what it writes, and up to 1.7.1 it cannot. Such a row has no user data at
-- all, so its encrypted region is exactly the AEAD framing — a well-formed
-- encoding of a zero-length plaintext that tde_gcm_decrypt() rejected, which
-- makes the whole table unreadable by sequential scan from that INSERT on.
-- Fixed in 1.7.2; covered by regression test 155.
CREATE TABLE up_nulls (a int4, b text, c timestamptz) USING encrypted_heap;
INSERT INTO up_nulls VALUES (1, 'x', '2026-01-01 00:00:00+00'),
                            (2, NULL, NULL),
                            (NULL, 'y', NULL);

CHECKPOINT;
SQL
chmod 0644 "$FIXTURE_SQL"   # mktemp gives 0600; container_psql runs as postgres
$RT cp "$FIXTURE_SQL" "$CONTAINER:/tmp/fixture.sql"
rm -f "$FIXTURE_SQL"
container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -q -f /tmp/fixture.sql \
    || { log_error "UPGRADE: fixture write failed under $BASELINE"; exit 2; }

BEFORE="$(container_psql "$CONTAINER" -tAc "$FINGERPRINT" 2>/dev/null | tr -d '[:space:]' || true)"
if [[ -z "$BEFORE" ]]; then
    log_error "UPGRADE: could not fingerprint the fixture under the baseline build"
    exit 2
fi
log_ok "Fixture written and fingerprinted under $BASELINE ($BEFORE)"

stop_container "$CONTAINER"

# ── Phase 2: read the same files with the current build ──────────────────
log_info "Phase 2 — reading the same data directory with the working tree ..."
start_upgrade_container "${PG_TEST_IMAGE:-pg-tde-test}:latest" || {
    log_error "UPGRADE: the current build could not even start on the baseline data directory"
    exit 2; }

# Only if the SQL objects moved; a patch release keeps default_version.
container_psql "$CONTAINER" -q -c \
    "DO \$\$ BEGIN
         IF (SELECT extversion FROM pg_extension WHERE extname='pg_vault_tde')
            IS DISTINCT FROM (SELECT default_version FROM pg_available_extensions WHERE name='pg_vault_tde')
         THEN EXECUTE 'ALTER EXTENSION pg_vault_tde UPDATE'; END IF;
     END \$\$;" 2>/dev/null || true

# ── Gate A: the data must still read ─────────────────────────────────────
AFTER="$(container_psql "$CONTAINER" -tAc "$FINGERPRINT" 2>/dev/null | tr -d '[:space:]')"
if [[ "$AFTER" == "$BEFORE" ]]; then
    ACT_READABLE=yes
    log_ok "GATE A: every row written by $BASELINE still decrypts, byte for byte"
else
    ACT_READABLE=no
    log_error "GATE A: data written by $BASELINE does NOT read back under this build"
    log_error "        baseline=$BEFORE  current=${AFTER:-<error>}"
fi

if [[ "$ACT_READABLE" != "$EXP_READABLE" ]]; then
    log_error "UPGRADE: readable_after_upgrade is '$ACT_READABLE', ci/upgrade-compat.expected declares '$EXP_READABLE'."
    if [[ "$ACT_READABLE" == "no" ]]; then
        log_error "        This change breaks existing data. VACUUM FULL will NOT repair it —"
        log_error "        it rewrites tuples by decrypting them first. Either fix the change, or"
        log_error "        flip the declaration AND ship a dump-with-the-old-binary procedure."
    fi
    exit 2
fi
[[ "$ACT_READABLE" == "yes" ]] || exit 2

# ── Probe B: can old-format rows be UPDATEd as they are? ─────────────────
# Rolled back either way, so the fingerprint below is unaffected: on success by
# the ROLLBACK, on a crash by recovery.
log_info "Probe B — UPDATE on rows still in the baseline's on-disk format ..."
PROBE_ERR="$(container_psql "$CONTAINER" -q -c \
    "BEGIN; UPDATE up_late_key SET pad = pad || 'x'; ROLLBACK;" 2>&1 >/dev/null || true)"
if echo "$PROBE_ERR" | grep -q "connection to server was lost\|server closed the connection"; then
    ACT_UPDATE=no
    log_warn "Probe B: the backend died — old-format rows cannot be updated in place"
    wait_pg_ready "$CONTAINER" 60 || { log_error "UPGRADE: server did not recover"; exit 2; }
elif [[ -n "$PROBE_ERR" ]]; then
    ACT_UPDATE=no
    log_warn "Probe B: UPDATE refused — $(echo "$PROBE_ERR" | head -1)"
else
    ACT_UPDATE=yes
    log_ok "Probe B: old-format rows update in place"
fi

if [[ "$ACT_UPDATE" != "$EXP_UPDATE" ]]; then
    log_error "UPGRADE: update_in_place_before_vacuum is '$ACT_UPDATE', ci/upgrade-compat.expected declares '$EXP_UPDATE'."
    log_error "        Either fix the change, or flip the declaration AND say so in the release notes:"
    log_error "        users must run VACUUM FULL on encrypted tables before writing to them."
    exit 2
fi

# ── Gate C: the documented remedy has to work ────────────────────────────
log_info "Gate C — VACUUM FULL must migrate the rows without altering them ..."
container_psql "$CONTAINER" -v ON_ERROR_STOP=1 -q -c \
    "VACUUM FULL up_plain, up_late_key, up_toast, up_nulls;" \
    || { log_error "GATE C: VACUUM FULL failed on baseline data"; exit 2; }

MIGRATED="$(container_psql "$CONTAINER" -tAc "$FINGERPRINT" 2>/dev/null | tr -d '[:space:]')"
if [[ "$MIGRATED" != "$BEFORE" ]]; then
    log_error "GATE C: VACUUM FULL changed the data (fingerprint $MIGRATED, expected $BEFORE)"
    exit 2
fi
log_ok "GATE C: data unchanged across the rewrite"

POST_ERR="$(container_psql "$CONTAINER" -q -c \
    "BEGIN; UPDATE up_late_key SET pad = pad || 'x'; ROLLBACK;" 2>&1 >/dev/null || true)"
if [[ -n "$POST_ERR" ]]; then
    log_error "GATE C: UPDATE still fails after VACUUM FULL — the documented remedy does not work"
    log_error "        $(echo "$POST_ERR" | head -1)"
    exit 2
fi
log_ok "GATE C: rows update normally once rewritten"

log_ok "UPGRADE COMPATIBILITY: data written by $BASELINE reads under $(cat "$REPO_ROOT/VERSION"); behaviour matches ci/upgrade-compat.expected"
exit 0
