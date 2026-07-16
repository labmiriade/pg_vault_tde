# ci/containers/pg-test.Containerfile
#
# Multi-stage build:
#   Stage 1 (builder): Compile pg_vault_tde from source with zero-warning gate
#   Stage 2 (test):    Install extension + all test dependencies
#
# This image is used by ALL test stages (regress, tap, isolation, bench).
# It includes Perl TAP modules, isolation tester, and benchmark tools.
#
# Build context MUST be the project root:
#   podman build -f ci/containers/pg-test.Containerfile \
#                --build-arg PG_MAJOR=18 -t pg-tde-test .
#
# To test against PG 17:
#   podman build -f ci/containers/pg-test.Containerfile \
#                --build-arg PG_MAJOR=17 -t pg-tde-test:pg17 .

ARG PG_MAJOR=18
FROM postgres:${PG_MAJOR} AS builder

# Re-declare ARG after FROM (Docker/Podman scoping rule)
ARG PG_MAJOR=18

# Force GCC, disable LTO (incompatible with PG PGXS in some container configs)
ENV CC=gcc
ENV CFLAGS="-O2 -fno-lto"
ENV LDFLAGS="-fno-lto"

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        build-essential \
        postgresql-server-dev-${PG_MAJOR} \
        libssl-dev \
        libcurl4-openssl-dev \
        libpq-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build

# Clean stale .o/.bc files from host build (different gcc/LTO versions)
RUN make clean PG_CONFIG=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config 2>/dev/null || true

# Compile with zero-warning gate: grep for warnings and fail if any found
RUN make PG_CONFIG=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config 2>&1 | tee /tmp/build.log && \
    if grep -qE ': warning:' /tmp/build.log; then \
        echo "FATAL: Compilation produced warnings — zero-warning policy violated" >&2; \
        grep ': warning:' /tmp/build.log >&2; \
        exit 1; \
    fi && \
    make install PG_CONFIG=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config

# ── Test image ──────────────────────────────────────────────────────────
ARG PG_MAJOR=18
FROM postgres:${PG_MAJOR}

# Re-declare ARG after FROM
ARG PG_MAJOR=18

# Install runtime deps (OpenSSL, curl) + test tooling
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        libcurl4 \
        postgresql-${PG_MAJOR}-pgaudit \ 
        # TAP test dependencies
        perl \
        libipc-run-perl \
        libhttp-daemon-perl \
        libhttp-message-perl \
        # Debug tools (useful for failures)
        procps \
        less && \
    # Isolation tester (may not exist in all PG repos — install if available)
    apt-get install -y --no-install-recommends \
        postgresql-${PG_MAJOR}-pg-isolation-regress 2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled extension from builder stage
COPY --from=builder /usr/lib/postgresql/${PG_MAJOR}/lib/pg_vault_tde.so \
     /usr/lib/postgresql/${PG_MAJOR}/lib/
COPY --from=builder /usr/share/postgresql/${PG_MAJOR}/extension/pg_vault_tde* \
     /usr/share/postgresql/${PG_MAJOR}/extension/
# Copy the compiled pg_dump_tde, pg_restore_tde and pg_basebackup_tde from builder stage
COPY --from=builder /usr/lib/postgresql/${PG_MAJOR}/bin/pg_dump_tde \
     /usr/lib/postgresql/${PG_MAJOR}/bin/
COPY --from=builder /usr/lib/postgresql/${PG_MAJOR}/bin/pg_restore_tde \
     /usr/lib/postgresql/${PG_MAJOR}/bin/
COPY --from=builder /usr/lib/postgresql/${PG_MAJOR}/bin/pg_basebackup_tde \
     /usr/lib/postgresql/${PG_MAJOR}/bin/
# Copy PostgreSQL Perl test modules (PostgreSQL::Test::Cluster etc.) from builder
COPY --from=builder /usr/lib/postgresql/${PG_MAJOR}/lib/pgxs/src/test/perl/ \
     /usr/lib/postgresql/${PG_MAJOR}/lib/pgxs/src/test/perl/

ENV PERL5LIB=/usr/lib/postgresql/${PG_MAJOR}/lib/pgxs/src/test/perl

# Copy test assets into the image (for self-contained execution)
COPY sql/regression_test.sql  /test/regression_test.sql
COPY sql/pg_vault_tde_init.sql /docker-entrypoint-initdb.d/pg_vault_tde_init.sql
COPY tap/                     /test/tap/
COPY test/isolation/               /test/isolation/
COPY bench_tde.sh            /test/bench_tde.sh

# Ensure test files are readable and writable by the postgres user
# (PostgreSQL::Test::Utils writes log/ relative to cwd, which is /test)
RUN chmod -R a+r /test && \
    mkdir -p /test/log && \
    chown -R postgres:postgres /test

# Create wallet base directory outside PGDATA.
# In production this is done by the package installer (postinst / %pre scriptlet).
# Here we replicate that step for the container image.
RUN mkdir -p /var/lib/pg_vault_tde && \
    chown postgres:postgres /var/lib/pg_vault_tde && \
    chmod 0700 /var/lib/pg_vault_tde

EXPOSE 5432

# Default entrypoint from postgres:${PG_MAJOR} handles initdb + startup
