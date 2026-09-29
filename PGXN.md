---

## Releasing to PGXN

pg_vault_tde's distribution metadata lives in [META.json](META.json)
(mandatory for [PGXN](https://pgxn.org/), the PostgreSQL Extension Network)
and [Changes](Changes) (release history). This section is for maintainers
cutting a new release, not for end users installing the extension — see
"1. Install" above or [wiki: Installation](https://github.com/labmiriade/pg_vault_tde/wiki/Installation)
for that.

### One-time setup

Register a PGXN Manager account at
<https://manager.pgxn.org/account/register> if you don't already have one.
No API token/CLI upload path is offered by PGXN Manager — every release is
uploaded by hand through its web UI.

### Signing

A release is signed by a maintainer, with their own key; no signing key lives in
CI. Two signatures: the **tag**, and the **`SHA256SUMS`** of the GitHub Release —
the SHA-256 of every asset: the `.deb` and `.rpm` packages, the PGXN zip, its SPDX
SBOM and the grype report. One signature over that list covers every file in it.

Once, per maintainer:

1. Add your public key to `packaging/RELEASE-KEYS.asc`
   (`gpg --armor --export <fingerprint> >> packaging/RELEASE-KEYS.asc`) and your
   fingerprint to [SECURITY.md](SECURITY.md#release-signing-keys).
2. Add your fingerprint to the Bitbucket repository variable `RELEASE_TAG_SIGNERS`
   (comma-separated, 40 hex digits each). The GitHub synchronization refuses to
   mirror a `v*` tag that is not signed by one of them. It checks there because it
   is the last point where it can: the mirror rewrites every commit, and a tag moved
   onto a rewritten one arrives on GitHub unsigned. The keys travel with the tag;
   the variable, which pushing a tag cannot change, says whose count.

Every release, after the tag (step 6 below) has reached GitHub:

1. Run *Build & Publish Packages* with the tag and the version. It always creates a
   **draft** release, with every asset and an unsigned `SHA256SUMS`; a draft is
   visible to the repository's maintainers only.
2. Sign `SHA256SUMS` and publish — from the draft's page (download `SHA256SUMS`, run
   the `gpg` line, attach `SHA256SUMS.asc`, *Publish release*), or with `gh`:
   ```bash
   gh release download vX.Y.Z --dir rel && cd rel
   sha256sum --check SHA256SUMS                      # the draft holds what the list says
   gpg --armor --detach-sign SHA256SUMS              # → SHA256SUMS.asc
   gh release upload vX.Y.Z SHA256SUMS.asc
   gh release edit vX.Y.Z --draft=false
   ```

### Keeping pins current

GitHub Actions are pinned by commit and third-party images by digest;
`make ci-pins` (the first stage of `make ci-all`, and a step of the GitHub
build) fails otherwise. To move one, resolve the new target and edit the
reference with its version:

```bash
git ls-remote https://github.com/actions/checkout 'refs/tags/v4*'   # the commit, and ^{} for an annotated tag
podman pull docker.io/openbao/openbao:2.x.y && \
  podman image inspect --format '{{.RepoDigests}}' docker.io/openbao/openbao:2.x.y
```

then run the stages that use it (`make ci-openbao`, `make ci-vault`, …).

### What ends up in the bundle

`make dist` names the zip after `VERSION` (the three-part version `META.json`
declares), not after the control file's `default_version`, and filters its
content through `.gitattributes` (`export-ignore`): internal CI, the wiki
sources, the container-only test suites and the `sql/regression_test*.sql`
files stay out. What remains must still build on its own.

Because the filter lives in the repository and not in the `dist` target, the
bundle is now identical whether it is cut from the internal Bitbucket clone or
from the public GitHub mirror — before, the former shipped `ci/` and
`bitbucket-pipelines.yml`, which `git filter-repo` strips from the latter. Both
properties are enforced by the `pgxn-bundle` CI job, which refuses internal
paths and then compiles the unpacked zip; do not tighten `.gitattributes`
without letting that job run.

### Every release

1. **Bump the version in lockstep**, in three places that must agree:
   - `pg_vault_tde.control` → `default_version = 'X.Y'` — PostgreSQL's own
     extension version, tied 1:1 to the `sql/pg_vault_tde--X.Y.sql` filename
     and to `extversion` in `pg_extension`. Stays 2-part; nothing outside
     PostgreSQL reads this file, so it does not need to follow semver.
   - `VERSION` and `META.json` (top-level `"version"` **and**
     `provides.pg_vault_tde.version`) → `X.Y.0` — PGXN requires a 3-part
     semantic version (`https://pgxn.org/spec/` — "three-part dotted
     integers, such as `1.2.0`"). `VERSION` is also compiled into the
     extension itself (the Makefile embeds its content as
     `-DPG_VAULT_TDE_BUILD_VERSION`, returned by
     `pg_vault_tde_build_version()` / the `build_version` column of
     `pg_vault_tde_health_check()`) — it distinguishes binary builds that
     share the same `extversion` (e.g. a C-only bugfix with no SQL script
     change), so it must always mirror `META.json`'s `"version"` exactly,
     and a plain `make` after bumping it needs a preceding `make clean` for
     the new string to actually take effect (CFLAGS changes alone don't
     invalidate already-built `.o` files).
     Both map 1:1 to the control file's `X.Y` with a trailing `.0`.
   - Add the corresponding `sql/pg_vault_tde--X.Y.sql` (and, if upgrading an
     already-installed extension in place, an
     `sql/pg_vault_tde--<old>--X.Y.sql` migration script) and point
     `META.json`'s `provides.pg_vault_tde.file` at the new SQL file.
2. **Add an entry to [Changes](Changes)** for the new version.
3. **Build and smoke-test the exact bundle PGXN will receive**. The
   `pgxn-bundle` job in `.github/workflows/build-packages.yml` already does all
   of this on the tag, and attaches the zip plus its `.sha256` to the GitHub
   Release — prefer downloading that artifact over rebuilding by hand. To
   reproduce locally:
   ```bash
   make dist                       # → dist/pg_vault_tde-X.Y.Z.zip, named after VERSION
                                    #   (git archive of HEAD: commit the version bump
                                    #   first, or it won't be in the zip)
   cd /tmp && unzip -o /path/to/dist/pg_vault_tde-X.Y.Z.zip && cd pg_vault_tde-X.Y.Z

   # PGXN's own build/test recipe — must pass before uploading:
   make USE_PGXS=1
   make USE_PGXS=1 install
   make USE_PGXS=1 check-standalone   # throwaway cluster, no server to set up;
                                      # `installcheck` also works if you already
                                      # have one preloading pg_vault_tde
   ```
4. **Validate META.json** before uploading (catches schema mistakes PGXN
   Manager would otherwise reject at upload time):
   ```bash
   cpanm PGXN::Meta::Validator     # the module PGXN Manager itself validates with
   validate_pgxn_meta -v META.json
   ```
   Note that `pgxnclient` has **no** `validate-meta` command — it is a client for
   installing distributions from the network, not a metadata checker. The
   `pgxn-bundle` CI job runs the validator above on every tagged release, so this
   step is a local convenience rather than a gate.
5. **Upload**: log in at <https://manager.pgxn.org/>, click "Upload" in the
   side navigation, and submit `dist/pg_vault_tde-X.Y.Z.zip`. PGXN Manager
   parses `META.json` from the zip, so double-check the version inside the
   zip matches what you intend to release before submitting — once a
   version is published it cannot be re-uploaded under the same number.
6. **Tag the release**, signed with your key (see [Signing](#signing)):
   `git tag -s vX.Y.Z -m 'pg_vault_tde X.Y.Z' && git push origin vX.Y.Z` on
   Bitbucket. The GitHub synchronization refuses a tag not signed by a key of
   `RELEASE_TAG_SIGNERS`; the tags up
   to `v1.7.1` are annotated but not signed. `default_version` in the control
   file moves on in-tree before a tag is made, so don't assume the control
   file version and the latest git tag are the same thing when preparing a
   release.
