# ci/containers/pg-valgrind.Containerfile
#
# The pg-tde-test image plus valgrind, for `make ci-valgrind`.
#
# Built FROM the already-built pg-tde-test image rather than repeating the
# extension build, so the binary under memcheck is byte-identical to the one
# every other CI stage exercises.  ci/scripts/run-valgrind.sh calls
# build_pg_test_image first to guarantee the base exists and is current.
ARG BASE_IMAGE=pg-tde-test
FROM ${BASE_IMAGE}:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends valgrind && \
    rm -rf /var/lib/apt/lists/*

# Somewhere for the per-process memcheck logs; the server runs as postgres.
RUN mkdir -p /tmp/valgrind && chown postgres:postgres /tmp/valgrind

# pg-test.Containerfile is multi-stage: /build exists only in the builder, so
# the suppression file is not in the runtime image.  Ship it here, where it is
# actually used.
COPY .valgrind.supp /etc/pg_vault_tde/valgrind.supp
