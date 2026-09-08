# PGDG readiness — yum.postgresql.org / apt.postgresql.org

Maintainer notes for submitting pg_vault_tde to the PostgreSQL community
package repositories. Excluded from the PGXN release bundle (`.gitattributes`).

Neither repository uses upstream packaging: the `.spec` is written by the PGDG
maintainer, `debian/` by the Debian PostgreSQL team. What they judge is whether
the **source** is straightforward to package.

## Pre-submission checklist

Run against the release bundle from `make dist`, never a git clone.

- [ ] **Builds from the tarball for every supported major, on both layouts**,
      with `PG_CONFIG` pointed at the versioned path
      (`/usr/lib/postgresql/N/bin/pg_config`, `/usr/pgsql-N/bin/pg_config`).
- [ ] **Nothing escapes `DESTDIR`.** Install as an unprivileged user into a
      staging directory: any write outside it then fails loudly. Every file must
      land under the version-specific prefix, so two majors can coexist.
- [ ] **Every build dependency is declared.** Build the SRPM, `dnf builddep` it
      — that installs exactly and only the declared `BuildRequires` — then
      `rpmbuild --rebuild`. This is how mock builds, and it is the check that
      catches dependencies satisfied only by `build_in_container.sh`.
      Note that `postgresqlNN-devel` does *not* pull in clang/llvm, while
      Debian's `postgresql-server-dev-NN` does.
- [ ] **The package is verifiable.** `make check-standalone` needs no container,
      no KMS service and no existing cluster. It does require the extension
      installed in the tree `pg_config` points at, which is why the package
      builds themselves skip tests; `debian/rules` and the spec say so.
- [ ] **A released tarball exists** at a permanent URL with a checksum, produced
      by the `pgxn-bundle` job in `.github/workflows/build-packages.yml`. This is
      what a maintainer puts in `Source0:`; they will not package from git.

## Open question for the maintainer

`pg_dump_tde`, `pg_restore_tde` and `pg_basebackup_tde` install into
`$(bindir)`, which is version-specific on both layouts. Side-by-side majors
therefore do not collide, but neither directory is on a default `PATH`, and
Debian's `pg_wrapper` covers only postgresql-common's own programs. Whether to
add wrappers is a packaging-policy decision — ask, do not decide unilaterally.

## Submission material

- **Licence**: PostgreSQL (`LICENSE`).
- **Supported majors**: see the Support Matrix in `doc/pg_vault_tde.md`.
- **Runtime dependencies**: OpenSSL 3.x (`EVP_EncryptInit_ex2` / AES-256-WRAP,
  added in 3.0) and libcurl. Distributions shipping only OpenSSL 1.1.1 cannot
  be supported.
- **Server configuration**: must be preloaded
  (`shared_preload_libraries = 'pg_vault_tde'`); publishers replicating
  encrypted tables must also list the plugin in `output_plugin_libraries`.
- **Post-install**: `/var/lib/pg_vault_tde/` owned by the server user, created
  by postinst / `%pre`, never by `make install`.
- **No vendored dependencies.**

## Approach

Contact `pgsql-pkg-yum@` and `pgsql-pkg-debian@` only once the checklist is
complete and the tarball is published — one message per list, linking the
tarball and the documentation, not the git repository. Record each reply as its
own issue rather than patching in response.
