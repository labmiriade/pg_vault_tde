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
