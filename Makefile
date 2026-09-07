# Makefile for pg_vault_tde (PGXS)
#
# All source modules are listed here. Extension compiles as a single .so.
# PGXS handles the include paths, DESTDIR, and make installcheck wiring.
#
# Hardware-accelerated AES (AES-NI, VAES, ARM Crypto Extensions, SVE2) is
# provided automatically at runtime by OpenSSL's EVP layer — see
# src/crypto/pg_vault_tde_hw_accel.c and `make check-cpu` / `make bench-cpu`
# below. There is no separate CPU-specific build: it would not make the
# crypto path any faster, since pg_vault_tde never implements AES itself.
#
# Optimization level:
#   make TDE_OPTIMIZE=standard            (default — -O2)
#   make TDE_OPTIMIZE=max                 (-O3 -funroll-loops -fomit-frame-pointer)

TDE_OPTIMIZE    ?= standard

# Optimization flags
ifeq ($(TDE_OPTIMIZE),max)
   TDE_OPT_CFLAGS := -O3 -funroll-loops -fomit-frame-pointer
else
   TDE_OPT_CFLAGS := -O2
endif

# ---------------------------------------------------------------------------
# PostgreSQL version validation
#
# Supported range: PG 17 .. PG 19.  Update TDE_PG_MAX when adding a new
# major version (see .github/copilot-instructions.md § 0.5).
# ---------------------------------------------------------------------------
TDE_PG_MIN := 17
TDE_PG_MAX := 19

PG_CONFIG   ?= pg_config
TDE_PG_MAJOR := $(shell $(PG_CONFIG) --version | sed 's/PostgreSQL //' | cut -d. -f1)
$(if $(shell [ $(TDE_PG_MAJOR) -lt $(TDE_PG_MIN) ] && echo fail), \
  $(error pg_vault_tde requires PostgreSQL >= $(TDE_PG_MIN), detected $(TDE_PG_MAJOR)))
$(if $(shell [ $(TDE_PG_MAJOR) -gt $(TDE_PG_MAX) ] && echo fail), \
  $(warning pg_vault_tde is untested on PostgreSQL $(TDE_PG_MAJOR) — max tested is $(TDE_PG_MAX)))

$(info === pg_vault_tde build: OPT=$(TDE_OPTIMIZE) PG=$(TDE_PG_MAJOR) ===)

EXTENSION   = pg_vault_tde
MODULE_big  = pg_vault_tde

OBJS = \
	src/pg_vault_tde.o \
	src/kms/pg_vault_tde_kms.o \
	src/kms/pg_vault_tde_kms_local.o \
	src/kms/pg_vault_tde_kms_pkcs11.o \
	src/kms/pg_vault_tde_catalog.o \
	src/kms/pg_vault_tde_rotation_bgw.o \
	src/kms/pg_vault_tde_seal.o \
	src/crypto/pg_vault_tde_crypto.o \
	src/crypto/pg_vault_tde_hw_accel.o \
	src/tam/pg_vault_tde_tam.o \
	src/tam/pg_vault_tde_toast.o \
	src/iam/pg_vault_tde_iam.o \
	src/logical/pg_vault_tde_pgoutput.o \
	src/logical/pg_vault_tde_rmgr.o

# SQL scripts installed as part of the extension.
DATA = sql/pg_vault_tde--1.7.sql 

# pg_regress test targets (filenames without .sql suffix)
REGRESS = pg_vault_tde_init

# Artefacts left behind by `make check-standalone` (pg_regress).
EXTRA_CLEAN = tmp_check results regression.diffs regression.out

# Isolation test specs (test/isolation/{specs,expected}/per_table_dek_rotation.*)
ISOLATION = per_table_dek_rotation
ISOLATION_OPTS = --inputdir=test/isolation

PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

TDE_BUILD_VERSION := $(shell cat VERSION)

# ---------------------------------------------------------------------------
# dist: build a PGXN-ready release zip (dist/pg_vault_tde-<version>.zip) from
# the current git HEAD.
#
# The version comes from VERSION — the same string META.json declares, and the
# only one PGXN ever reads — not from the .control file's default_version,
# which stays 2-part (X.Y) and would name the bundle after a version that
# appears nowhere in the metadata PGXN Manager parses.
#
# Content is filtered by .gitattributes (export-ignore): internal CI, wiki
# sources and the container-only test suites stay out. The result must remain
# buildable on its own — the pgxn-bundle job in
# .github/workflows/build-packages.yml unpacks this zip and compiles it.
#
# See PGXN.md for the full upload procedure.
# Lands in dist/ alongside the packaging/ .deb+.rpm build output — both are
# git-ignored release artifacts, never committed.
# ---------------------------------------------------------------------------
.PHONY: dist
dist:
	mkdir -p dist
	git archive --format zip --prefix=$(EXTENSION)-$(TDE_BUILD_VERSION)/ \
	    --output ./dist/$(EXTENSION)-$(TDE_BUILD_VERSION).zip HEAD

# Extra compiler/linker flags — must come AFTER include $(PGXS) so they
# append to PGXS defaults rather than being overwritten by them.
#
# OpenSSL 3.x and libcurl are required. pkg-config locates them.
# -std=c99 enforces the language standard mandated by copilot-instructions.md.
# -Wall -Wextra catch common PostgreSQL extension pitfalls early.
# VERSION must be a single line with no trailing content; note that changing
# VERSION does not force a rebuild of already-compiled .o files under plain
# incremental `make` — a `make clean` is needed after bumping VERSION for the
# embedded build-version string to update (accepted limitation, not solved
# via fancier Make dependency tracking).
override CFLAGS  += -Wall -Wextra -std=c99 \
                    -Wno-unused-parameter \
                    -I$(srcdir)/src \
                    $(TDE_OPT_CFLAGS) \
                    $(shell pkg-config --cflags openssl libcurl) \
                    -DPG_VAULT_TDE_BUILD_VERSION='"$(TDE_BUILD_VERSION)"'
# -ldl: dlopen() of the vendor PKCS#11 module (pkcs11 KMS provider).
# No-op on glibc >= 2.34 (dlopen lives in libc) but required for portability.
override SHLIB_LINK += $(shell pkg-config --libs openssl libcurl) -ldl

# ---------------------------------------------------------------------------
# check-cpu: print CPU hardware encryption capabilities. This does not affect
# the build — OpenSSL detects and uses these instructions automatically at
# runtime regardless of how pg_vault_tde.so was compiled.
# ---------------------------------------------------------------------------
.PHONY: check-cpu
check-cpu:
	@echo "=== CPU Hardware Encryption Capabilities ==="
	@grep -m1 "model name" /proc/cpuinfo 2>/dev/null || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown CPU"
	@echo "x86 flags:" ; grep -m1 "^flags" /proc/cpuinfo 2>/dev/null | tr ' ' '\n' | grep -E "^(aes|avx|vaes|pclmulqdq|sse4)" | sort || echo "  not applicable"
	@echo "ARM features:" ; grep "^Features" /proc/cpuinfo 2>/dev/null | tr ' ' '\n' | grep -E "(aes|sha|pmull|crc)" | sort || echo "  not applicable"
	@openssl speed -evp aes-256-gcm 2>/dev/null | tail -3 || echo "  openssl speed not available"

# ---------------------------------------------------------------------------
# bench-cpu: quick OpenSSL AES-256-GCM benchmark + HW engine detection
# ---------------------------------------------------------------------------
.PHONY: bench-cpu
bench-cpu:
	@echo "=== pg_vault_tde: OpenSSL AES-256-GCM benchmark ==="
	@openssl speed -evp aes-256-gcm 2>&1 | grep -E "(Doing|aes)"
	@echo ""
	@echo "=== Check if AES-NI is loaded in OpenSSL ==="
	@openssl engine 2>/dev/null | grep -i "aesni" && echo "  AES-NI engine active" || echo "  Using default provider (auto-dispatch)"

# ===========================================================================
# Local CI Pipeline (containerized)
#
# All targets delegate to ci/scripts/ which auto-detect podman/docker.
# Override container runtime:  make ci-all CONTAINER_RT=docker
# ===========================================================================
.PHONY: ci-all ci-regress ci-checksums ci-tap ci-isolation ci-vault ci-wallet ci-pkcs11 ci-schema ci-bench ci-install-test ci-clean

ci-all:
	@bash ci/scripts/run-all.sh

ci-regress:
	@bash ci/scripts/run-regress.sh

ci-checksums:
	@bash ci/scripts/run-checksums.sh

ci-tap:
	@bash ci/scripts/run-tap.sh

ci-isolation:
	@bash ci/scripts/run-isolation.sh

ci-vault:
	@bash ci/scripts/run-vault.sh

ci-wallet:
	@bash ci/scripts/run-wallet.sh

ci-pkcs11:
	@bash ci/scripts/run-pkcs11.sh

ci-schema:
	@bash ci/scripts/run-schema.sh

ci-bench:
	@bash ci/scripts/run-bench.sh; rc=$$?; \
	if [ $$rc -eq 7 ]; then echo "ci-bench: avg overhead above threshold (non-fatal WARN, matches run-all.sh)"; exit 0; fi; \
	exit $$rc

ci-install-test:
	@bash ci/scripts/run-install-test.sh --all

ci-clean:
	@echo "Cleaning up CI containers and images ..."
	@RT=$$(command -v podman 2>/dev/null || echo docker); \
	$$RT rm -f pg-tde-test pg-tde-checksums pg-tde-vault vault-mock 2>/dev/null || true; \
	$$RT rmi -f pg-tde-test:latest vault-mock:latest 2>/dev/null || true; \
	echo "CI cleanup complete."

# ---------------------------------------------------------------------------
# check-standalone: run the regression test with no container, no KMS service
# and no server configuration to edit by hand.
#
# PGXS refuses `make check` for out-of-tree extensions ("\"make check\" is not
# supported" in pgxs.mk), so this drives pg_regress directly: it creates a
# throwaway cluster under tmp_check/ on a free port, appends test/regress.conf
# to its postgresql.conf — the extension must be preloaded, which is precisely
# why plain `make installcheck` fails on a fresh machine — runs the test, and
# tears the cluster down. No existing cluster is touched.
#
# The extension must already be installed into the tree $(PG_CONFIG) points at:
# pg_regress can create a cluster, but not populate an installation's extension
# directory.
#
# This is the entry point for anyone outside the project, packagers included.
# It does NOT replace the ci-* targets above: those cover the KMS providers,
# TAP, isolation, checksums and benchmarks, and `make ci-all` remains the full
# suite.
# ---------------------------------------------------------------------------
PG_REGRESS := $(shell $(PG_CONFIG) --pkglibdir)/pgxs/src/test/regress/pg_regress
sharedir   := $(shell $(PG_CONFIG) --sharedir)

.PHONY: check-standalone
check-standalone: all
	@test -f "$(sharedir)/extension/$(EXTENSION).control" || { \
	    echo "ERROR: $(EXTENSION) is not installed in $(sharedir)/extension."; \
	    echo "Run 'make install' first (as a user who can write there)."; \
	    echo "pg_regress creates the cluster, but not the installation."; \
	    exit 1; }
	@test -x "$(PG_REGRESS)" || { \
	    echo "ERROR: pg_regress not found at $(PG_REGRESS)."; \
	    echo "Install the PostgreSQL server development package for this major."; \
	    exit 1; }
	$(PG_REGRESS) \
	    --temp-instance=./tmp_check \
	    --temp-config=$(srcdir)/test/regress.conf \
	    --inputdir=$(srcdir) \
	    --bindir=$(bindir) \
	    $(REGRESS)

# Full pipeline alias
.PHONY: ci-full
ci-full: ci-all

# ---------------------------------------------------------------------------
# pg_dump_tde: standalone backup encryption wrapper for pg_dump
#
# This binary is NOT a PostgreSQL extension module (.so).  It is a standalone
# C tool that forks pg_dump, intercepts its stdout through a pipe, and
# re-encrypts each 64 KB block with AES-256-GCM before writing to disk.
#
# Build:    make pg_dump_tde
# Install:  make install-pg-dump-tde
# Clean:    make clean-pg-dump-tde
#
# The object files use a _bin.o suffix to avoid collisions with the _bin.o
# objects already compiled as -fPIC for the extension .so.
# ---------------------------------------------------------------------------
PG_DUMP_TDE_SHARED = \
	src/backup/pg_vault_tde_backup.c \
	src/backup/pg_dump_tde_kms_vault.c \
	src/backup/pg_dump_tde_kms_local.c 

PG_DUMP_TDE_SRCS = \
	$(PG_DUMP_TDE_SHARED) \
	src/backup/pg_dump_tde.c 

PG_RESTORE_TDE_SRCS = \
	$(PG_DUMP_TDE_SHARED) \
	src/backup/pg_restore_tde.c 

PG_DUMP_TDE_OBJS = $(PG_DUMP_TDE_SRCS:.c=_bin.o)
PG_RESTORE_TDE_OBJS = $(PG_RESTORE_TDE_SRCS:.c=_bin.o)

# pg_basebackup_tde: pg_basebackup wrapper that also stores one sealed
# wrapped-DEK bundle per database (via pg_vault_tde_seal_keys_bytea).
# libpq only: no frontend KMS, no block encryption — the physical files are
# already encrypted on disk.
PG_BASEBACKUP_TDE_SRCS = src/backup/pg_basebackup_tde.c
PG_BASEBACKUP_TDE_OBJS = $(PG_BASEBACKUP_TDE_SRCS:.c=_bin.o)

# pkg-config fallback: if not available, use well-known paths.
HAS_PKG_CONFIG := $(shell command -v pkg-config 2>/dev/null)

ifdef HAS_PKG_CONFIG
  OPENSSL_CFLAGS  := $(shell pkg-config --cflags openssl)
  OPENSSL_LIBS    := $(shell pkg-config --libs openssl)
  LIBCURL_CFLAGS  := $(shell pkg-config --cflags libcurl)
  LIBCURL_LIBS    := $(shell pkg-config --libs libcurl)
else
  OPENSSL_CFLAGS  :=
  OPENSSL_LIBS    := -lssl -lcrypto
  LIBCURL_CFLAGS  :=
  LIBCURL_LIBS    := -lcurl
endif

PG_DUMP_TDE_CFLAGS = \
	$(TDE_OPT_CFLAGS) \
	-Wall -Wextra -std=c99 \
	-Wno-unused-parameter \
	-DFRONTEND \
	-D_GNU_SOURCE \
	-I$(shell $(PG_CONFIG) --includedir) \
	-I$(shell $(PG_CONFIG) --includedir-server) \
	-Isrc \
	-Isrc/include \
	$(OPENSSL_CFLAGS) \
	$(LIBCURL_CFLAGS)

PG_DUMP_TDE_LDFLAGS = \
    -L$(shell $(PG_CONFIG) --libdir) \
    -L$(shell $(PG_CONFIG) --pkglibdir) \
    -lpq -lpgcommon -lpgport \
    $(OPENSSL_LIBS) \
    $(LIBCURL_LIBS)

# Pattern rule for _bin.o objects (standalone compilation, no -fPIC).
# Must be declared before include $(PGXS) would shadow it, but we define
# it after so PGXS %.o rules are not confused.
%_bin.o: %.c
	$(CC) $(PG_DUMP_TDE_CFLAGS) -c -o $@ $<

pg_dump_tde: $(PG_DUMP_TDE_OBJS)
	$(CC) -o $@ $^ $(PG_DUMP_TDE_LDFLAGS)

pg_restore_tde: $(PG_RESTORE_TDE_OBJS)
	$(CC) -o $@ $^ $(PG_DUMP_TDE_LDFLAGS)

pg_basebackup_tde: $(PG_BASEBACKUP_TDE_OBJS)
	$(CC) -o $@ $^ $(PG_DUMP_TDE_LDFLAGS)

# Hook into the standard PGXS targets so the frontend tools are always
# built, installed, and cleaned together with the extension.
all: pg_dump_tde pg_restore_tde pg_basebackup_tde

bindir := $(shell $(PG_CONFIG) --bindir)

.PHONY: install-pg-dump-tde
install-pg-dump-tde: pg_dump_tde pg_restore_tde pg_basebackup_tde
	install -d $(DESTDIR)$(bindir)
	install -m 755 pg_dump_tde pg_restore_tde pg_basebackup_tde $(DESTDIR)$(bindir)/

install: install-pg-dump-tde

.PHONY: clean-pg-dump-tde
clean-pg-dump-tde:
	rm -f pg_dump_tde pg_restore_tde pg_basebackup_tde \
	    $(PG_DUMP_TDE_OBJS) $(PG_RESTORE_TDE_OBJS) $(PG_BASEBACKUP_TDE_OBJS)

clean: clean-pg-dump-tde
