# ci/containers/pg-cassert.Containerfile
#
# PostgreSQL built from source with --enable-cassert and -DUSE_VALGRIND, plus
# pg_vault_tde built against it.  This is the image that can see the bug
# classes the stock Debian package hides.
#
# WHY IT HAS TO BE A SOURCE BUILD
#
# Neither PGDG nor Debian ship an assert-enabled server, and both flags are
# compile-time only:
#
#   --enable-cassert   turns on Assert() — the codebase is full of them
#                      (e.g. Assert(enc_len == user_len + TDE_V4_OVERHEAD) in
#                      tde_encrypt_heap_tuple) and none of them execute in any
#                      other CI stage — and switches on MEMORY_CONTEXT_CHECKING,
#                      which poisons freed chunks and detects a pfree() of an
#                      already-freed chunk.  That is the double-free class our
#                      PG_CATCH handlers can produce, and the one a release
#                      build swallows silently because the aborting transaction
#                      deletes the context moments later.
#
#   -DUSE_VALGRIND     compiles in the Valgrind client requests that tell
#                      memcheck where palloc chunk boundaries are.  Without it
#                      memcheck sees one big malloc'd arena and a use-after-
#                      pfree looks like a perfectly valid access.
#
# --enable-tap-tests installs PostgreSQL's TAP modules (PostgreSQL::Test::*)
# and needs IPC::Run: the tap/ files run here too, because the rotation worker's
# error path — and anything else only a TAP scenario reaches — gets no Assert()
# coverage from the SQL suites.  softhsm2 lets the PKCS#11 halves run.
#
# -O1 rather than -O2: assertions plus valgrind annotations are already the
# slow path, and -O1 keeps stack frames and variable names readable in the
# reports.  -fno-omit-frame-pointer for the same reason.
#
# Built by ci/scripts/run-cassert.sh (make ci-cassert) and reused by
# ci/scripts/run-valgrind.sh when VG_BASE_IMAGE=pg-tde-cassert.
ARG PG_VERSION=18.6
FROM debian:bookworm

ARG PG_VERSION=18.6
ENV PG_PREFIX=/usr/local/pgsql
ENV PATH=/usr/local/pgsql/bin:$PATH
ENV PGDATA=/var/lib/postgresql/data

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates bison flex pkg-config \
        libreadline-dev zlib1g-dev libssl-dev libicu-dev libxml2-dev \
        libcurl4-openssl-dev \
        valgrind gdb procps \
        libipc-run-perl softhsm2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL -O "https://ftp.postgresql.org/pub/source/v${PG_VERSION}/postgresql-${PG_VERSION}.tar.bz2" \
    && tar xf "postgresql-${PG_VERSION}.tar.bz2"

WORKDIR /usr/src/postgresql-${PG_VERSION}
RUN ./configure \
        --prefix="${PG_PREFIX}" \
        --enable-cassert \
        --enable-debug \
        --with-openssl \
        --with-libxml \
        --with-icu \
        --enable-tap-tests \
        CFLAGS="-DUSE_VALGRIND -O1 -g -fno-omit-frame-pointer" \
    && make -j"$(nproc)" world-bin \
    && make install-world-bin \
    && cd / && rm -rf /usr/src/postgresql-${PG_VERSION}*

# The stock postgres image ships this user; debian:bookworm does not.
# The client binaries built against this server (pg_dump_tde and friends) carry
# no rpath to /usr/local/pgsql/lib, where libpq.so.5 lives.
RUN echo "${PG_PREFIX}/lib" > /etc/ld.so.conf.d/pgsql.conf && ldconfig

RUN useradd -m -s /bin/bash postgres \
    && mkdir -p "${PGDATA}" /var/lib/pg_vault_tde /tmp/valgrind /etc/pg_vault_tde \
    && chown -R postgres:postgres "${PGDATA}" /var/lib/pg_vault_tde /tmp/valgrind \
    && chmod 0700 /var/lib/pg_vault_tde

# Build the extension against the instrumented server, not the system one.
COPY . /build
WORKDIR /build
RUN make clean \
    && make PG_CONFIG="${PG_PREFIX}/bin/pg_config" \
    && make PG_CONFIG="${PG_PREFIX}/bin/pg_config" install

COPY .valgrind.supp /etc/pg_vault_tde/valgrind.supp

USER postgres
WORKDIR /tmp
