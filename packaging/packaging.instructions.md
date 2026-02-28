# DevOps & Packaging Instructions — @DevOps

> **Scope**: `.github/workflows/`, `packaging/`, `Containerfile`,
> `bitbucket-pipelines.yml`, `ci/`

---

## CI Pipeline Architecture

### GitHub Actions (`.github/workflows/ci.yml`)

5 jobs, against PostgreSQL 17 and 18 on Ubuntu 24.04:

| Job | Purpose | PG Versions | Dependencies |
|-----|---------|-------------|-------------|
| `build` | Compile with `-Wall -Wextra`, zero warnings required | 17, 18 | None |
| `regress` | Run 24 `pg_regress` SQL tests | 17, 18 | `build` |
| `tap` | Run TAP tests with mock Vault | 17, 18 | `build` |
| `isolation` | Run isolation tests (concurrency / MVCC) | 17, 18 | `build` |
| `memcheck` | Valgrind + AddressSanitizer | 17, 18 | `build` |

### Bitbucket Pipelines (`bitbucket-pipelines.yml`)

Mirror of GitHub Actions for Bitbucket-hosted repositories.
Uses the same test commands and validation gates.

### Local CI Pipeline (`ci/`)

Containerized pipeline for pre-push validation. Run via `make ci-*` targets.
See `ci/README.md` for full documentation.

---

## Container Build (`Containerfile`)

Base image: `postgres:${PG_MAJOR}` (parameterized via `ARG PG_MAJOR=18`)  
Required packages:
- `postgresql-server-dev-${PG_MAJOR}`
- `libssl-dev`, `libcurl4-openssl-dev`
- `pkg-config`, `build-essential`

The container MUST:
1. Accept `PG_MAJOR` as a build argument (default: 18)
2. Build the extension from source
3. Install into the PostgreSQL extension directory
4. Run the full regression suite as validation

---

## Packaging Matrix

| Format | Script | Package Name Pattern | Spec | PG Versions |
|--------|--------|---------------------|------|-------------|
| DEB (generic) | `packaging/build_deb.sh` | `postgresql-${PG_MAJOR}-pg-vault-tde` | `packaging/debian/` | 17, 18 |
| DEB (AES-NI) | `packaging/build_deb.sh --arch-variant aesni` | `...-aesni` | `packaging/debian/control.aesni` | 17, 18 |
| DEB (ARM CE) | `packaging/build_deb.sh --arch-variant armce` | `...-armce` | `packaging/debian/control.arm` | 17, 18 |
| RPM (generic) | `packaging/build_rpm.sh` | `postgresql${PG_MAJOR}-pg_vault_tde` | `packaging/rpm/pg_vault_tde.spec` | 17, 18 |
| RPM (AES-NI) | `rpmbuild -ba ...` | `...-aesni` | `packaging/rpm/pg_vault_tde-aesni.spec` | 17, 18 |
| RPM (ARM CE) | `rpmbuild -ba ...` | `...-armce` | `packaging/rpm/pg_vault_tde-arm.spec` | 17, 18 |

### Release Checklist

When bumping version:
- [ ] Update `packaging/debian/changelog` (version + date)
- [ ] Update `Version:` in ALL RPM `.spec` files
- [ ] Update `pg_vault_tde.control` (`default_version`)
- [ ] Verify `sql/pg_vault_tde--1.0.sql` filename matches control version
- [ ] Tag the release commit

---

## Hardware Architecture Flags

| `TDE_TARGET_ARCH` | Compiler Flags | Preprocessor Define |
|-------------------|---------------|-------------------|
| `generic` (default) | *(none)* | *(none)* |
| `x86_64-aesni` | `-maes -mpclmul -msse4.1 -msse4.2` | `TDE_HW_AES_NI` |
| `x86_64-vaes` | `-maes -mpclmul -msse4.1 -msse4.2 -mvaes -mavx -mavx2` | `TDE_HW_VAES` |
| `aarch64-ce` | `-march=armv8-a+crypto+crc` | `TDE_HW_ARM_CE` |
| `aarch64-sve2` | `-march=armv9-a+crypto+sve2` | `TDE_HW_ARM_SVE2` |

All variants produce the same `.so` filename (`pg_vault_tde.so`). ABI is
compatible across variants — the difference is in OpenSSL provider selection.

---

## Test Execution Environment

### Local CI Pipeline (`make ci-*`)

All test stages run inside containers built from `ci/containers/pg-test.Containerfile`.
The pipeline auto-detects `podman` or `docker` and uses a mock Vault for integration tests.

| Command | What It Tests |
|---------|---------------|
| `make ci-regress` | 24-test SQL regression suite |
| `make ci-checksums` | Same + page checksums (`initdb -k`) |
| `make ci-tap` | TAP tests (extension load, backup hooks) |
| `make ci-isolation` | MVCC / DEK rotation concurrency |
| `make ci-vault` | Vault Transit API integration (Compose) |
| `make ci-bench` | Performance benchmark (informational) |
| `make ci-all` | All of the above in sequence |

All commands are idempotent (can be run repeatedly without manual cleanup).
Use `make ci-clean` to remove containers and images.

---

## Dependency Rules

- DevOps files MUST NOT modify any C source code
- CI workflows MUST run the SAME test commands as local development
- Container builds MUST use the same `Makefile` targets as local builds
- Package scripts MUST NOT bundle runtime dependencies not declared in control files

---

## Adding a New PostgreSQL Version (Checklist)

When PostgreSQL N+1 becomes GA:

1. **RPM specs**: Update `%global pgmajorversion` or create version-specific spec
2. **DEB control**: Update `postgresql-XX-pg-vault-tde` package name and deps
3. **DEB changelog**: Add entry mentioning PG N+1 support
4. **Containerfile**: Verify `postgres:N+1` base image exists on Docker Hub
5. **CI matrix**: Add PG N+1 to GitHub Actions matrix and Bitbucket steps
6. **`ci/.env`**: Add N+1 to `PG_SUPPORTED_VERSIONS`
7. **Makefile**: Update `TDE_PG_MAX` to N+1
8. **Test**: Run `PG_VERSION=N+1 make ci-all` — all 24 tests must pass
9. **`build_deb.sh` / `build_rpm.sh`**: Verify scripts work with new PG version
10. **Tag release**: Include "Added PG N+1 support" in release notes
