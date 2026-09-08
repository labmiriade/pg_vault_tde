# Contributing

Thanks for your interest in pg_vault_tde.

## Before You Start

- **Everyone taking part in this project is expected to follow our
  [Code of Conduct](CODE_OF_CONDUCT.md).**
- **Found a security vulnerability?** Do not open an issue or a pull request.
  Follow [SECURITY.md](SECURITY.md) and report it privately.
- **Reporting a bug or proposing a feature?** Use the
  [issue templates](https://github.com/labmiriade/pg_vault_tde/issues/new/choose).
  For bugs, please check
  [Known Limitations and Troubleshooting](https://github.com/labmiriade/pg_vault_tde/wiki/Known-Limitations-and-Troubleshooting)
  first — several behaviours that look like defects are documented consequences
  of what a PostgreSQL extension is able to intercept.

By contributing, you agree that your work is licensed under the
[PostgreSQL License](LICENSE), the same terms as the rest of the project.

## Working on a Change

- Build cleanly against **both PostgreSQL 17 and 18**, with no compiler
  warnings. Every push and pull request is compile-checked on both by CI.
- Run at least `make ci-regress` locally before opening a PR; see
  [ci/README.md](ci/README.md) for the full set of suites (TAP, isolation,
  Vault, wallet, memcheck).
- Add tests that fail without your change.
- If you change `packaging/build-matrix.json`, run
  `bash packaging/gen-support-matrix.sh` and commit the regenerated Support
  Matrix in `doc/pg_vault_tde.md` in the same change. No CI job checks it.
- The pull request template lists what reviewers will check — in particular
  the extra checklists for changes touching cryptography, key material, or the
  access methods. Reading it before you start will save you a review round.

## How Review Works

The canonical repository lives on an internal Bitbucket instance; this GitHub
repository is a mirror that also accepts external contributions. Here's what
happens after you open a PR:

1. Open your pull request here against `develop` (or `main` for release-only
   fixes) as usual.
2. A bot mirrors your branch to our internal Bitbucket repository as
   `github-pr/<PR number>-<slug>` and leaves a comment here confirming it.
3. A maintainer reviews it internally using the same standards as any other
   contribution, and may ask for changes — just push more commits to your
   branch and they'll be re-mirrored automatically.
4. Once merged internally (with a merge commit, so your original commits are
   preserved), the next sync to GitHub carries those exact commits into
   `develop`/`main`. GitHub then recognizes them and **closes this PR
   automatically** as merged.

If your PR is squashed instead of merged internally for any reason, it won't
auto-close — a maintainer will close it manually with a reference to the
corresponding Bitbucket commit.

No separate GitHub account setup is required on your side; just open the PR
and follow the discussion there.
