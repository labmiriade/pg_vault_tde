<!--
  Thanks for contributing to pg_vault_tde.

  Note: this GitHub repository is a mirror. Your branch is mirrored to our
  internal Bitbucket for review, and this PR closes automatically once it is
  merged there. See CONTRIBUTING.md for exactly what happens after you open it.

  If your change fixes a security vulnerability, do not describe the
  vulnerability here — go through SECURITY.md first and we will coordinate.
-->

## Summary

<!-- What does this change, and why? One or two paragraphs. -->

## Related Issue

<!-- e.g. Fixes #123 — or "none" if this stands alone. -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (existing behaviour, on-disk format, GUC, or SQL signature changes)
- [ ] Documentation only
- [ ] Build, packaging, or CI
- [ ] Refactor or performance work with no behaviour change

## How Has This Been Tested?

<!--
  Which suites did you run, on which PostgreSQL major, with which KMS provider?
  e.g. `make ci-regress` on PG 18 with the local wallet; `make ci-vault` on PG 17.
-->

## Checklist

### Always

- [ ] The code builds with **zero compiler warnings** on the PostgreSQL majors it targets (17 and 18).
- [ ] `make ci-regress` passes.
- [ ] I have added or updated tests covering the change, and they fail without it.
- [ ] I have read [CONTRIBUTING.md](CONTRIBUTING.md) and agree my contribution is licensed under the [PostgreSQL License](LICENSE).
- [ ] My commits have a clear message explaining *why*, not only *what*.

### If this touches encryption, keys, or the KMS

- [ ] No key material (DEK, KEK, passphrase, PIN, token) can reach the server log, an error message, a temporary file, or a core dump.
- [ ] Every buffer that held key material is cleansed (`OPENSSL_cleanse` or equivalent) on **all** paths, including error paths.
- [ ] No nonce or IV can repeat under the same key.
- [ ] Authentication tags are verified, and a verification failure raises an error rather than returning data.
- [ ] Comparisons of secret values are constant-time (`CRYPTO_memcmp`).
- [ ] I have considered whether this needs an `AUDIT` log event, and added one if so.

### If this touches the storage or index access method

- [ ] No path can write plaintext derived from an `encrypted_heap` table to disk.
- [ ] The on-disk format is unchanged — or, if it changed, an upgrade path is documented and the version was bumped accordingly.
- [ ] Behaviour is correct on both PG 17 and PG 18 (API differences guarded by version macros).

### If this changes user-visible behaviour

- [ ] `README.md` and the relevant `wiki/` pages are updated.
- [ ] New or changed GUCs are documented in the GUC reference.
- [ ] New or changed SQL functions are documented in the SQL function reference.
- [ ] `Changes` has an entry.
- [ ] `VERSION`, `META.json`, `pg_vault_tde.control`, and the packaging files were bumped together if this is a release-bearing change (see `packaging/packaging.instructions.md`).

## Notes for Reviewers

<!-- Anything you are unsure about, deliberate trade-offs, or areas you want scrutinised. -->
