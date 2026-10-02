#!/usr/bin/env bash
# ci/scripts/run-soak.sh — Run the soak test, tap/43_soak.t (PSQLE-207)
#
# The soak test is skipped in every other run.  This runs it alone, in the
# same container as run-tap.sh:
#
#   SOAK_MINUTES  how long (default 30)
#   SOAK_ROUNDS   stop after this many rounds, whichever comes first
#   SOAK_SEED     replay a failed run with the seed it printed
#
# Exit code: 0 on success, 3 on failure.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

export PG_VAULT_TDE_SOAK=1
export SOAK_MINUTES="${SOAK_MINUTES:-30}"
export TAP_FILES=tap/43_soak.t
exec bash "$(dirname "${BASH_SOURCE[0]}")/run-tap.sh"
