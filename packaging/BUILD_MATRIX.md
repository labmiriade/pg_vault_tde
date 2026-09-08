# Package Build Matrix

`build-matrix.json` is the single source of truth for which
(OS, PostgreSQL major) combinations are packaged. Both
`.github/workflows/build-packages.yml` (stable releases, from a `v*` tag) and
`.github/workflows/dev-prerelease.yml` (rolling `dev-latest` builds from
`develop`) read it at run time via `fromJSON`, so the two channels can never
drift apart.

## Fields

| Field | Meaning |
|---|---|
| `format` | `deb` or `rpm` — selects the packaging path in `build_in_container.sh` |
| `os` | Base image, passed as `--os-version`. Must appear in that script's `VALID_DEB_OS` / `VALID_RPM_OS` |
| `pg` | PostgreSQL major, passed as `--pg-version` |
| `slug` | Appended to the artifact filename to disambiguate builds that would otherwise collide (`build_in_container.sh` names packages after format+PG only, so `rockylinux:9` and `almalinux:9` both produce `*.el9.x86_64.rpm`) |
| `functional_test` | `true` when the regression/TAP/isolation/KMS/backup suites run on this OS and PG major (`make ci-all`). Today that is the `postgres:17` / `postgres:18` official images, which are Debian 13 |
| `install_test` | `true` when the built package is installed on a clean system of this OS and `CREATE EXTENSION` is verified (`ci/scripts/run-install-test.sh`, currently `ubuntu:22.04` and `rockylinux:9`) |

Both flags are booleans and both are required on every row:
`packaging/gen-support-matrix.sh` refuses to run otherwise rather than silently
rendering a missing flag as "not verified". They are independent checks, not
levels of one scale — a row can have its sources fully exercised while its
package is never installed, and the reverse.

## Changing it

Each entry is one CI job, and every job runs in parallel, so the cost of an
added row is wall-clock queueing rather than money — GitHub Actions does not
bill public repositories. The hard ceiling is GitHub's 256-jobs-per-run matrix
limit, which is far away; the practical one is the account's concurrent-job
allowance (20 on the Free plan), above which jobs queue rather than fail.

Because it is read **from the ref being built**, each release tag carries its
own matrix. A `v1.7.x` tag can therefore keep building for PG 17-18 while
`develop` has already moved on to 18-19 — declare the support window per
version by editing this file on the branch it applies to, rather than by
gating anything in the workflows.

When adding a PostgreSQL major, also raise `TDE_PG_MAX` in the `Makefile`;
when adding an OS, add it to `VALID_DEB_OS` / `VALID_RPM_OS` in
`packaging/build_in_container.sh` first, or the build will reject it.

Drop rows for OSes past end-of-life rather than accumulating them: the matrix
is meant to slide with the supported window, not to grow forever.

## Regenerating the published matrix

This file is the source of truth for the user-facing Support Matrix in
`doc/pg_vault_tde.md`. After **any** edit here:

```bash
bash packaging/gen-support-matrix.sh
```

Commit the resulting documentation change together with the JSON. The script
is a maintainer tool kept in the git repository only: it is excluded from the
PGXN release bundle, so a tree unpacked from a distribution archive will not
have it.

**No CI job checks this, deliberately**: the table stays editable by hand or by
an assistant when a one-off wording change is wanted. That makes it the
responsibility of whoever touches the matrix — change the JSON, regenerate,
review the diff, commit both. A reviewer seeing this file change with no
accompanying `doc/pg_vault_tde.md` diff should ask why before approving.

Lower a flag when coverage actually drops — if an OS leaves the test set, its
row goes back to `false`. A matrix that only ever gains ticks stops being
evidence.
