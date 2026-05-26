# Makefile for pg_vault_tde (PGXS)
#
# All source modules are listed here. Extension compiles as a single .so.
# PGXS handles the include paths, DESTDIR, and make installcheck wiring.
#
# Hardware acceleration variants:
#   make TDE_TARGET_ARCH=generic          (default — portable)
#   make TDE_TARGET_ARCH=x86_64-aesni     (AES-NI on Intel/AMD)
#   make TDE_TARGET_ARCH=x86_64-vaes      (VAES + AVX2 on Intel Ice Lake+ / AMD Zen4+)
#   make TDE_TARGET_ARCH=aarch64-ce       (ARM Crypto Extensions, ARMv8-A)
#   make TDE_TARGET_ARCH=aarch64-sve2     (ARM SVE2 + Crypto, ARMv9-A)
#
# Optimization level:
#   make TDE_OPTIMIZE=standard            (default — -O2)
#   make TDE_OPTIMIZE=max                 (-O3 -funroll-loops -fomit-frame-pointer)

TDE_TARGET_ARCH ?= generic
TDE_OPTIMIZE    ?= standard

# Arch-specific flags
ifeq ($(TDE_TARGET_ARCH),x86_64-aesni)
   TDE_ARCH_CFLAGS := -maes -mpclmul -msse4.1 -msse4.2 -DTDE_HW_AES_NI
else ifeq ($(TDE_TARGET_ARCH),x86_64-vaes)
   TDE_ARCH_CFLAGS := -maes -mpclmul -msse4.1 -msse4.2 -mvaes -mavx -mavx2 -DTDE_HW_VAES
else ifeq ($(TDE_TARGET_ARCH),aarch64-ce)
   TDE_ARCH_CFLAGS := -march=armv8-a+crypto+crc -DTDE_HW_ARM_CE
else ifeq ($(TDE_TARGET_ARCH),aarch64-sve2)
   TDE_ARCH_CFLAGS := -march=armv9-a+crypto+sve2 -DTDE_HW_ARM_SVE2
else
   TDE_ARCH_CFLAGS :=
endif

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

$(info === pg_vault_tde build: ARCH=$(TDE_TARGET_ARCH) OPT=$(TDE_OPTIMIZE) PG=$(TDE_PG_MAJOR) ===)

EXTENSION   = pg_vault_tde
MODULE_big  = pg_vault_tde

OBJS = \
	src/pg_vault_tde.o \
	src/kms/pg_vault_tde_kms.o \
	src/kms/pg_vault_tde_kms_local.o \
	src/kms/pg_vault_tde_catalog.o \
	src/kms/pg_vault_tde_rotation_bgw.o \
	src/crypto/pg_vault_tde_crypto.o \
	src/crypto/pg_vault_tde_hw_accel.o \
	src/tam/pg_vault_tde_tam.o \
	src/tam/pg_vault_tde_toast.o \
	src/iam/pg_vault_tde_iam.o \
	src/backup/pg_vault_tde_backup.o \
	src/logical/pg_vault_tde_pgoutput.o

# SQL scripts installed as part of the extension
# Always list the base install AND every upgrade path.
DATA = sql/pg_vault_tde--1.0.sql \
       sql/pg_vault_tde--1.0--1.4.sql \
       sql/pg_vault_tde--1.4--1.5.sql \
       sql/pg_vault_tde--1.5--1.6.sql

# pg_regress test targets (filenames without .sql suffix)
REGRESS = pg_vault_tde_init

# Isolation test specs
ISOLATION = dek_rotation
ISOLATION_OPTS = --spec-dir=isolation

PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Extra compiler/linker flags — must come AFTER include $(PGXS) so they
# append to PGXS defaults rather than being overwritten by them.
#
# OpenSSL 3.x and libcurl are required. pkg-config locates them.
# -std=c99 enforces the language standard mandated by copilot-instructions.md.
# -Wall -Wextra catch common PostgreSQL extension pitfalls early.
override CFLAGS  += -Wall -Wextra -std=c99 \
                    -Wno-unused-parameter \
                    -I$(srcdir)/src \
                    $(TDE_ARCH_CFLAGS) \
                    $(TDE_OPT_CFLAGS) \
                    $(shell pkg-config --cflags openssl libcurl)
override SHLIB_LINK += $(shell pkg-config --libs openssl libcurl)

# ---------------------------------------------------------------------------
# check-cpu: print CPU hardware encryption capabilities
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
.PHONY: ci-all ci-regress ci-checksums ci-tap ci-isolation ci-vault ci-wallet ci-schema ci-bench ci-install-test ci-clean

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

ci-schema:
	@bash ci/scripts/run-schema.sh

ci-bench:
	@bash ci/scripts/run-bench.sh

ci-install-test:
	@bash ci/scripts/run-install-test.sh --all

ci-clean:
	@echo "Cleaning up CI containers and images ..."
	@RT=$$(command -v podman 2>/dev/null || echo docker); \
	$$RT rm -f pg-tde-test pg-tde-checksums pg-tde-vault vault-mock 2>/dev/null || true; \
	$$RT rmi -f pg-tde-test:latest vault-mock:latest 2>/dev/null || true; \
	echo "CI cleanup complete."

# Full pipeline alias
.PHONY: ci-full
ci-full: ci-all
