# ci/containers/pg-ubsan.Containerfile
#
# Stock PostgreSQL server, pg_vault_tde compiled with -fsanitize=undefined.
#
# Unlike the cassert image this needs no PostgreSQL rebuild: UBSan instruments
# only the objects it compiles, so the server binary is the ordinary packaged
# one and just happens to dlopen an instrumented .so.  That makes this the
# cheapest of the deep-checking stages — minutes, not a source build.
#
# libubsan1 is a runtime dependency, not just a build one: the .so carries a
# DT_NEEDED on it and the postmaster will refuse to load the module without it.
#
# Reports are non-fatal (halt_on_error=0) so one finding does not abort the
# run and mask the rest; ci/scripts/run-ubsan.sh collects every report at the
# end and fails the stage if any exist.
ARG PG_MAJOR=18
FROM postgres:${PG_MAJOR}

ARG PG_MAJOR=18
ENV CC=gcc
ENV PG_CFLAGS="-fno-lto"
ENV CFLAGS="-O1 -fno-lto"

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential postgresql-server-dev-${PG_MAJOR} \
        libssl-dev libcurl4-openssl-dev libpq-dev \
        libubsan1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build
RUN make clean && make TDE_SANITIZE=undefined && make TDE_SANITIZE=undefined install

RUN mkdir -p /var/lib/pg_vault_tde /tmp/ubsan \
    && chown postgres:postgres /var/lib/pg_vault_tde /tmp/ubsan \
    && chmod 0700 /var/lib/pg_vault_tde

# print_stacktrace needs the frame pointers TDE_SANITIZE already forces on.
ENV UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0:log_path=/tmp/ubsan/ubsan

RUN mkdir -p /docker-entrypoint-initdb.d \
    && cp sql/pg_vault_tde_init.sql /docker-entrypoint-initdb.d/
