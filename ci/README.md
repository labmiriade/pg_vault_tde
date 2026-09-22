# ci/ — Local Testing Pipeline

Enterprise-grade local CI pipeline for pg_vault_tde.
Runs all test stages inside containers with a mock HashiCorp Vault.

## Quick Start

```bash
# Run everything (build + all tests + bench):
make ci-all

# Run only the regression suite (fastest feedback loop):
make ci-regress

# Run with page checksums enabled:
make ci-checksums

# Run with a real Vault mock (HTTP endpoint):
make ci-vault

# Run the full pipeline with TAP + isolation + memcheck:
make ci-full

# Benchmark:
make ci-bench BENCH_ROWS=100000
```

## Architecture

```
ci/
├── README.md                    ← this file
├── .env                         ← Default environment variables
├── compose.yml                  ← Podman/Docker Compose orchestration
├── containers/
│   ├── pg-test.Containerfile    ← PG test image (ARG PG_MAJOR=18)
│   └── vault-mock.Containerfile ← Lightweight mock Vault (Go binary)
├── vault-mock/
│   ├── vault_mock.go            ← Tiny Go HTTP server mocking Vault Transit
│   └── go.mod                   ← Go module definition
└── scripts/
    ├── lib.sh                   ← Shared utilities (runtime detection, logging)
    ├── run-all.sh               ← Master orchestrator (all stages)
    ├── run-regress.sh           ← SQL regression suite
    ├── run-checksums.sh         ← Page-checksum compatibility
    ├── run-tap.sh               ← TAP tests with mock Vault
    ├── run-isolation.sh         ← Isolation / concurrency tests
    ├── run-vault.sh             ← Vault integration tests (compose)
    ├── run-upgrade.sh           ← Upgrade compat vs the previous release tag
    └── run-bench.sh             ← Performance benchmark
```

## Pipeline Stages

| Stage | Script | Container(s) | What It Tests |
|-------|--------|--------------|---------------|
| **build** | (embedded) | `pg-test` | Zero-warning compile gate |
| **regress** | `run-regress.sh` | `pg-test` | SQL regression suite |
| **checksums** | `run-checksums.sh` | `pg-test` | Page checksum compatibility |
| **tap** | `run-tap.sh` | `pg-test` | TAP tests (extension load, backup) |
| **isolation** | `run-isolation.sh` | `pg-test` | MVCC + DEK rotation concurrency |
| **vault** | `run-vault.sh` | `pg-test` + `vault-mock` | Vault Transit API integration |
| **upgrade** | `run-upgrade.sh` | `pg-test` + `pg-tde-baseline` | Data written by the previous release tag still reads; declared in `ci/upgrade-compat.expected` |
| **bench** | `run-bench.sh` | `pg-test` | Performance vs plain heap |

## Container Runtime

Supports both `podman` and `docker`. The scripts auto-detect which is
available, preferring `podman`. Override with `CONTAINER_RT=docker`.

## Exit Codes

- `0` — all stages passed
- `1` — build failure
- `2` — regression test failure
- `3` — TAP test failure
- `4` — isolation test failure
- `5` — vault integration failure
- `6` — benchmark failure (informational, not fatal by default)

## Advanced Usage

```bash
# Run specific stages only:
bash ci/scripts/run-all.sh --only regress tap

# Skip the (slow) benchmark:
bash ci/scripts/run-all.sh --skip-bench

# Override runtime:
CONTAINER_RT=docker make ci-all

# Override benchmark params:
BENCH_ROWS=500000 BENCH_ITERATIONS=5 make ci-bench

# Direct script invocation (bypasses Makefile):
bash ci/scripts/run-vault.sh

# Clean up containers and images:
make ci-clean
```

## Environment Variables

Set them in the shell. `ci/scripts/lib.sh` also sources `ci/.env` if that file
exists, so local overrides can live there; the file is not tracked in the repo.

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAINER_RT` | (auto) | `podman` or `docker` |
| `PG_VERSION` | `18` | PostgreSQL major version for container builds |
| `PG_MAJORS` | `"17 19"` | Majors exercised by `make ci-matrix` (regress + tap) |
| `PG_TEST_IMAGE` | `pg-tde-test` | Name of the test container image |
| `VAULT_MOCK_TOKEN` | `test-token` | Vault mock authentication token |
| `PG_TEST_PORT` | `15432` | Host port for regression container |
| `BENCH_ROWS` | `200000` | Rows per INSERT, per profile |
| `BENCH_PROFILES` | `"tiny oltp wide"` | Row-width profiles (~32 B / ~256 B / ~512 B) |
| `BENCH_THRESHOLD_PCT` | `100` | Avg overhead % above which the bench WARNs (exit 7) |
| `PG_STARTUP_TIMEOUT` | `30` | Seconds to wait for PG startup |

## Multi-Version PostgreSQL Testing

The pipeline supports testing against multiple PostgreSQL major versions.
The `pg-test.Containerfile` accepts a `PG_MAJOR` build argument.

```bash
# Test against PG 17:
PG_VERSION=17 make ci-regress

# Test against PG 18 (default):
make ci-regress

# Run full pipeline against all supported versions:
for v in 17 18; do
  echo "=== Testing PG $v ==="
  PG_VERSION=$v make ci-all
done
```

### Adding a New Major Version

PG 19 is already wired in: `TDE_PG_MAX` in the `Makefile` covers 17..19 and
`PG_MAJORS` defaults to `"17 19"`.  `make ci-matrix` skips a major whose base
image is not on Docker Hub yet, so nothing is needed until `postgres:19` ships
— at that point only the packaging matrix has to follow.

For a major beyond that range:

1. Verify the `postgres:N` base image exists on Docker Hub
2. Run `PG_VERSION=N make ci-regress` to validate
3. Raise `TDE_PG_MAX` in the `Makefile`
4. Add `N` to the `PG_MAJORS` default in `ci/scripts/run-matrix.sh`
5. Add the matching rows to `packaging/build-matrix.json`
6. Add the PG N steps to `bitbucket-pipelines.yml`
