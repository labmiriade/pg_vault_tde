# ci/containers/pg-asan.Containerfile
#
# Stock PostgreSQL server, pg_vault_tde compiled with -fsanitize=address
# (PSQLE-181).  The sibling of pg-ubsan.Containerfile, kept apart so that each
# sanitizer is built and judged on its own.
#
# No PostgreSQL rebuild: ASan instruments only the objects it compiles, and its
# runtime has to be the first library of every process that loads the module —
# the server is not linked against it, so LD_PRELOAD puts it there.  Its path
# depends on the image's gcc, so the build links it to a fixed one, and checks
# that the module really calls into ASan.
#
# What ASan sees here: overflows of memory from malloc (OpenSSL, libcurl,
# libc), of the stack and of globals, use after free and double free of the
# same.  palloc'd chunks carry no redzones — that is valgrind's and the
# assertion build's ground.  Leak detection is off: memory contexts are freed
# whole, never chunk by chunk.
#
# Reports are non-fatal (-fsanitize-recover=address, halt_on_error=0) so one
# finding does not abort the run and mask the rest; ci/scripts/run-asan.sh
# collects every report at the end and fails the stage if any exist.
ARG PG_MAJOR=18
FROM postgres:${PG_MAJOR}

ARG PG_MAJOR=18
ENV CC=gcc
ENV PG_CFLAGS="-fno-lto -fsanitize-recover=address"
ENV CFLAGS="-O1 -fno-lto"

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential postgresql-server-dev-${PG_MAJOR} \
        libssl-dev libcurl4-openssl-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build
RUN make clean && make TDE_SANITIZE=address && make TDE_SANITIZE=address install \
    && ln -s "$(readlink -f "$(gcc -print-file-name=libasan.so)")" /usr/local/lib/libasan-preload.so \
    && test -e /usr/local/lib/libasan-preload.so \
    && nm -D --undefined-only "$(pg_config --pkglibdir)/pg_vault_tde.so" | grep -q __asan_report_load

RUN mkdir -p /var/lib/pg_vault_tde /tmp/asan \
    && chown postgres:postgres /var/lib/pg_vault_tde /tmp/asan \
    && chmod 0700 /var/lib/pg_vault_tde

RUN mkdir -p /docker-entrypoint-initdb.d \
    && cp sql/pg_vault_tde_init.sql /docker-entrypoint-initdb.d/

# Last, so that no build step runs under them.  verify_asan_link_order=0: the
# runtime is preloaded into binaries that are not instrumented (bash, initdb,
# psql, the server), which is the case that option exists for.
ENV ASAN_OPTIONS=detect_leaks=0:halt_on_error=0:verify_asan_link_order=0:log_path=/tmp/asan/asan
ENV LD_PRELOAD=/usr/local/lib/libasan-preload.so
