# Use official PostgreSQL image as base
# Override PG_MAJOR to build for a different version:
#   podman build --build-arg PG_MAJOR=17 -t pg-vault-tde .
ARG PG_MAJOR=18
FROM postgres:${PG_MAJOR}

ARG PG_MAJOR=18

# Force GCC and disable LTO for extension build
ENV CC=gcc
ENV PG_CFLAGS="-fno-lto"
ENV CFLAGS="-O2 -fno-lto"

# Install build dependencies
RUN apt-get update && \
    apt-get install -y build-essential postgresql-server-dev-${PG_MAJOR} libssl-dev libcurl4-openssl-dev libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /build

# Copy extension source
COPY . /build

# Build the extension
RUN make && make install

# Copy only the init script (CREATE EXTENSION) to docker-entrypoint-initdb.d
# Do NOT copy pg_vault_tde--1.0.sql here: it's the extension definition script
# and must only be run via CREATE EXTENSION, not directly
RUN mkdir -p /docker-entrypoint-initdb.d && \
    cp sql/pg_vault_tde_init.sql /docker-entrypoint-initdb.d/

# Create wallet base directory outside PGDATA.
# In production this is done by the package installer (postinst / %pre scriptlet).
# Here we replicate that step for the container image.
RUN mkdir -p /var/lib/pg_vault_tde && \
    chown postgres:postgres /var/lib/pg_vault_tde && \
    chmod 0700 /var/lib/pg_vault_tde

# Set environment for PostgreSQL to find the extension
ENV LD_LIBRARY_PATH=/usr/lib/postgresql/${PG_MAJOR}/lib:$LD_LIBRARY_PATH

# Expose default PostgreSQL port
EXPOSE 5432

# Default command (inherited from postgres image)
