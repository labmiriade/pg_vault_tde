# ci/containers/pg-analyze.Containerfile
#
# Clang static analyzer (scan-build) over the extension sources.
#
# Complements CodeQL rather than duplicating it: CodeQL matches declarative
# queries against a whole-program database and is strongest on taint and API
# misuse, while the clang analyzer does symbolic execution of each function and
# is strongest on the per-path arithmetic this codebase is full of — a NULL
# deref only on the error branch, a buffer size computed from a length that can
# be zero, a use-after-free reachable on one path out of five.
#
# No server needed: this stage only compiles.
ARG PG_MAJOR=18
FROM postgres:${PG_MAJOR}

ARG PG_MAJOR=18

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential postgresql-server-dev-${PG_MAJOR} \
        libssl-dev libcurl4-openssl-dev libpq-dev \
        clang clang-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build