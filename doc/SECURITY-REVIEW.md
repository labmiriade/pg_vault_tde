# pg_vault_tde - Security Review

This document is the method for reviewing the security of `pg_vault_tde`: the threat
model a review works against, the trust boundaries it has to cross, the checklist it
goes through, the risks the project has accepted and documented, and the findings
recorded so far. The review of a given release is written by a person, against this
document, and signed (see [Workflow](#workflow)). Automated tools - CodeQL,
scan-build, UBSan, Valgrind, a PostgreSQL built with assertions - produce evidence
that a review can cite; they are not the review.

It exists because the PostgreSQL packaging repositories (yum.postgresql.org,
apt.postgresql.org) accept new extensions only with a security review of their code
written by a person - see the RFC in
[GitHub discussion #9](https://github.com/labmiriade/pg_vault_tde/discussions/9).

| | |
|---|---|
| Version under review | 1.7.2 |
| Reviews signed so far | [1.7.2](security/reviews/v1.7.2.md) (self-review) |
| Reporting a vulnerability | [SECURITY.md](../SECURITY.md) |

---

## Threat model

### What is protected

- The **values** stored in `encrypted_heap` tables: heap tuples, their out-of-line
  (TOAST) values, the same bytes in WAL, and the archives of the client tools.
- The **keys**: each relation's DEK, the KEK that wraps it (a version in the local
  wallet, a Vault/OpenBao transit key, a key on a PKCS#11 token), and the secrets that
  open the KEK (wallet passphrase, Vault token or AppRole credentials, PKCS#11 PIN).
- The **integrity** of those values: damaged ciphertext is refused, never decrypted
  into a wrong value, and a ciphertext moved to another database, relation or key
  generation is refused. Integrity against someone who *writes* the data files, within
  one relation, is not claimed ([PSQLE-177](#findings), [PSQLE-218](#findings)).

### Attackers in scope

| | Attacker | Holds | Must not obtain |
|---|---|---|---|
| A1 | Theft of files or backups | Relation and TOAST files, a copy of the data directory, a base backup, a `pg_dump_tde` archive, a key-seal bundle - without the KEK | Any value, any DEK |
| A2 | Access to the data directory without access to the database | Read access to `PGDATA` (a storage or backup operator, a volume snapshot), no role in the cluster, no access to the KMS or the wallet directory | Any value, any DEK |
| A3 | The replication stream | Physical replication: the WAL stream. Logical replication: see the accepted risk [Logical decoding](#accepted-risks) | From WAL: any value, any DEK. Structural metadata is not protected (see non-goals) |
| A4 | A memory dump | A core file, a swap or hibernation image, taken after the key material in it was no longer needed | Key material the extension has finished with: it must have been cleansed |

### Non-goals

A review does not treat these as findings; the design does not defend against them.

- **A PostgreSQL superuser, or any role that can read the table through SQL.**
  Decryption is transparent; TDE protects the storage layer, not in-database
  authorization. The same goes for the roles the key-management functions are open to
  (superuser, see [PSQLE-206](#findings)).
- **The operating-system user that runs PostgreSQL** (`postgres`). It can read the
  wallet directory, the passphrase source and the memory of every backend.
- **A server compromised while it runs**: code executing in a backend, a debugger
  attached to one, a dump of a running server - the DEKs of every relation in use sit
  in shared memory.
- **WAL structural metadata** - LSNs, block numbers, relation OIDs, tuple headers.
  Only tuple payloads are ciphertext; full WAL encryption is not possible from an
  extension.
- **Traffic between clients and the server**, and between primary and standby: TLS
  (`ssl = on`, `sslmode`) is a separate control.
- **Availability**: a KMS that is slow or down, resource exhaustion, a lost wallet
  without a backup.
- **Side channels** of the host: timing, cache, power.

### Properties a review verifies

1. No path writes a value of an `encrypted_heap` table to disk in plaintext, except
   the [accepted risks](#accepted-risks).
2. Every ciphertext is authenticated before any byte of its plaintext is used, and a
   failure is an error, never a value. What the tag covers is exactly what
   [PSQLE-177](#findings) and [PSQLE-218](#findings) say.
3. No key is written to disk unwrapped, logged, or returned by an SQL function.
4. Key material is cleansed (`OPENSSL_cleanse`) as soon as it is no longer needed,
   on the error paths too.
5. The functions and settings that manage keys are reachable only by the roles the
   documentation names.

---

## Trust boundaries

The last column is what the code is meant to check on each crossing; the
[checklist](#checklist) verifies that it does.

| Boundary | What crosses it | Trusted | Checked on arrival |
|---|---|---|---|
| Server ↔ Vault / OpenBao (HTTPS, libcurl) | Token or AppRole credentials, wrapped and unwrapped DEKs, transit key rotations | The Vault server named by `vault_url`, identified by TLS | Certificate and host name (libcurl's defaults, never turned off; `vault_ca_cert` sets the CA). JSON responses are untrusted input |
| Server ↔ local wallet | The PKCS#12 file under `/var/lib/pg_vault_tde/<db_oid>/`, the passphrase from `wallet_passphrase_env`, `_file` or `_command` | The wallet directory (outside `PGDATA`, mode 0700) and the passphrase source | The PKCS#12 MAC, before any key is used |
| Server ↔ PKCS#11 module | A vendor library loaded into every backend, the PIN from `pkcs11_pin_env`, wrap and unwrap calls | The module named by `pkcs11_library` | Return codes; keys are `CKA_SENSITIVE`, never extractable |
| Server ↔ client tools (`pg_basebackup_tde`, `pg_dump_tde`, `pg_restore_tde`) | libpq sessions; wrapped DEKs, seal bundles and archives written and read on the client host | The client host, which holds key material during a restore | Archive and bundle framing, lengths and HMAC before use |
| Roles ↔ SQL surface | Calls to the extension's functions, settings of its GUCs | Nothing: the caller is checked | The calling role (`GetOuterUserId()`), table privileges (`MAINTAIN`), GUC contexts |
| Extension ↔ PostgreSQL core | Table and index access methods, `ProcessUtility`, object-access and planner hooks, a custom WAL resource manager, background workers | The core | Each callback against the core contract it replaces |

---

## Checklist

A review goes through every item and records, for each, *verified*, *finding* (with
its ID) or *not applicable*. File names are starting points, not limits.

An item marked *(rule `tde-…`)* is also checked on every build by that rule in
`ci/semgrep/` (`make ci-semgrep`). A rule catches the pattern it names, not every way
of getting the item wrong: the item is still reviewed, and so is every
`nosemgrep` comment in the code.

### Cryptography - `src/crypto/`, `src/iam/`

- [ ] AES-256-GCM for tuples and TOAST chunks: a 96-bit IV per encryption from
      `pg_strong_random()` (rule `tde-strong-random`), never reused under one DEK - including across `fork()`
      ([PSQLE-178](#findings)); the documented limit of encryptions per DEK.
- [ ] The tag is verified before any plaintext is used; a failure raises an error and
      frees the buffers.
- [ ] The AAD is rebuilt from the reader's context, not read from disk, and the tag
      covers what [PSQLE-177](#findings) and [PSQLE-218](#findings) say - no more is claimed anywhere.
- [ ] AES-256-SIV for `tde_btree` keys: key length, determinism limited to equality,
      no plaintext key reaches the index page.
- [ ] Key wrapping: AES-256 key wrap (local), transit (Vault), `CKM_AES_KEY_WRAP_PAD`
      (PKCS#11); each wrapped DEK carries the version of the KEK that wrapped it.
- [ ] Derivations and MACs: PKCS#12 iteration counts, PBKDF2 of the seal passphrase,
      HMAC compared with `CRYPTO_memcmp` (rule `tde-constant-time-compare`).
- [ ] Every buffer that held a key, an IV batch or a passphrase is cleansed, on the
      error paths too (rule `tde-cleanse-before-free`).

### Key management - `src/kms/`

- [ ] The shared-memory DEK cache: who can reach it, its capacity, and that evicted
      and replaced entries are cleansed.
- [ ] The local wallet: permissions checked, written to a temporary file and renamed
      durably, every KEK version kept, never replaced while keys are wrapped under it.
- [ ] Vault: TLS verification, token renewal, bounds on every response parsed, no
      token in a log line or an error (rule `tde-no-secret-in-message`).
- [ ] PKCS#11: the module never initialised in the postmaster, a `getpid()` guard
      after `fork()`, the PIN cleansed after login.
- [ ] Rotations (`rotate_online()`, `rotate_kek()`, `wallet_change_passphrase()`):
      a rotation that aborts, fails or crashes leaves every key needed to read the
      data (TAP 29, 30, 46).
- [ ] Secrets in GUCs, SQL arguments and commands - [PSQLE-177](#findings).

### SQL surface - `sql/pg_vault_tde--1.7.sql` and the C functions it binds

- [ ] Every function: its `GRANT`s, and whether it is `SECURITY DEFINER`; every
      `SECURITY DEFINER` function has a fixed `search_path` ([PSQLE-217](#findings)).
- [ ] Every privileged function checks the calling role, not the owner
      ([PSQLE-205](#findings), [PSQLE-206](#findings); rule `tde-caller-superuser`).
- [ ] Every GUC: context (`PGC_SUSET` or `PGC_POSTMASTER`), `GUC_SUPERUSER_ONLY` on
      those that name secrets or paths, `GUC_NOT_IN_SAMPLE` on secret values.
- [ ] Functions that take a server file path ([PSQLE-206](#findings)).
- [ ] The extension's tables (`pg_vault_tde_catalog`, `pg_vault_tde_rotation_progress`)
      are revoked from `PUBLIC`.

### Hooks and core integration - `src/pg_vault_tde.c`, `src/tam/`, `src/iam/`, `src/logical/`

- [ ] Every read path of the table access method decrypts, and no write path stores a
      value unencrypted; the callbacks that rewrite tables (`CLUSTER`, `VACUUM FULL`,
      the index build) apply heapam's logic to decrypted copies.
- [ ] No callback leaves the relcache entry pointing at heapam
      (`rd_tableam`), and none trusts that pointer across an invalidation (rule
      `tde-rd-tableam`).
- [ ] `ProcessUtility` and the object-access hook: the checks on `DROP`,
      `ALTER TABLE … SET ACCESS METHOD` and index creation cover every path that
      reaches them.
- [ ] The planner hook changes plans only for `tde_btree` indexes.
- [ ] The custom WAL resource manager: redo matches heapam's, decoding never hands
      ciphertext to an output plugin as a value.
- [ ] Background workers (rotation, preload): the role they run as, and their
      behaviour on `SIGTERM`, cancel and crash.

### Plaintext on disk

- [ ] Heap, TOAST and WAL payloads written only through the encryption path.
- [ ] Temporary files, `pg_statistic`, index keys, the server log: each either
      encrypted or listed under [Accepted risks](#accepted-risks) with its mitigation.
- [ ] Core dumps and swap: what the extension cleanses, and what it cannot (the shared
      cache while the server runs).

### Client tools - `src/backup/`

- [ ] Each tool secures its session (`search_path`) before calling the extension, and
      calls it schema-qualified ([PSQLE-178](#findings); rule `tde-client-qualified-call`).
- [ ] Archives and bundles read on restore are untrusted input: framing, lengths and
      the HMAC checked before any field is used.
- [ ] Files written on the client host: permissions, and where key material ends up.
- [ ] Passphrases and keys cleansed after use.

### Error paths

- [ ] No error message, detail or hint carries a key, an IV or a plaintext value
      (rule `tde-no-secret-in-message`, for secrets named as such).
- [ ] `PG_TRY`/`PG_CATCH` blocks cleanse what they allocated; variables modified
      inside them are `volatile`.
- [ ] Code that must run on failure does not rely on a `PG_CATCH` a `FATAL` would skip.
- [ ] Evidence: the error-path SQL suite (tests 141–153), and the Valgrind, UBSan, ASan
      and assertion-enabled stages of `make ci-all`.

---

## Accepted risks

Each is a documented property of the design, with its mitigation where one exists. A
review checks that the documentation still says what the code does.

| Risk | Why it is accepted | Documented in |
|---|---|---|
| **`pg_statistic` holds plaintext** value distributions after `ANALYZE` | Statistics are computed on decrypted values by core; no extension hook can encrypt the catalog | [README › Designing encrypted tables](../README.md#designing-encrypted-tables); [pg_vault_tde.md › Planner Statistics](pg_vault_tde.md#planner-statistics) |
| **`WITH HOLD` cursors spill plaintext** to a temporary file past `work_mem` (as do sorts and hashes) | The executor's tuplestore bypasses the table access method; there is no hook | [README › Limitations (v1.7), item 6](../README.md#limitations-v17); [README › Before the first encrypted table](../README.md#before-the-first-encrypted-table) |
| **The v5 tuple header and layout stay in plaintext**: header, null bitmap, varlena length headers, alignment | Core reads raw on-disk tuples (MVCC, `VACUUM`, `heap_update`); only attribute values can be encrypted | [pg_vault_tde.md › Wire Format per Encrypted Region](pg_vault_tde.md#wire-format-per-encrypted-region); [README › Upgrading to 1.7.2 › Why](../README.md#why) |
| **`tde_btree` is deterministic**: equal keys give equal ciphertext under one DEK | An index needs equality on ciphertext; AES-SIV reveals equality and nothing about order | [pg_vault_tde.md › tde_btree](pg_vault_tde.md#tde_btree); [README › `tde_btree` answers equality only](../README.md#tde_btree-answers-equality-only) |
| **Legacy `tde_btree` operator classes store keys in plaintext** (`tde_int4_ops`, `tde_int8_ops`, `tde_uuid_ops`, `tde_date_ops`, `tde_timestamptz_ops`) | The classes are kept only for indexes already built on them, and a new index can use them only with `allow_plaintext_index = on`; 1.8 removes the classes. Native btree indexes, which the same setting allows, are not affected | [pg_vault_tde.md › Operator Class](pg_vault_tde.md#operator-class); [README › SQL Functions](../README.md#sql-functions) (`check_plaintext_index_keys`, known defect) |
| **`PRIMARY KEY` and `UNIQUE` constraints are backed by a native btree**, with the key in plaintext | Core builds that index itself; the extension can only warn | [README › What Gets Encrypted](../README.md#what-gets-encrypted); [README › Designing encrypted tables](../README.md#designing-encrypted-tables) |
| **Logical decoding sends plaintext**: the output plugin decrypts for subscribers | That is its purpose; the stream needs TLS and the subscriber its own encryption | [pg_vault_tde.md › Logical Decoding and Replication](pg_vault_tde.md#logical-decoding-and-replication) and [› Structural limitations](pg_vault_tde.md#structural-limitations) |
| **The tag binds database, relation, key generation and the value bytes - not a tuple's position, its header, or the layout that divides its bytes among variable-length attributes** ([PSQLE-177](#findings), [PSQLE-218](#findings)) | heapam chooses a tuple's place after the tuple, ciphertext included, has been formed; core rewrites the header without the key. The layout could be authenticated: 1.8 | [pg_vault_tde.md › What the authentication tag does not cover](pg_vault_tde.md#what-the-authentication-tag-does-not-cover) |

---

## Findings

One row per ticket, and a ticket that covers two findings lists both. Every finding
has a ticket. This table changes in the commit that changes a status. Findings describe what to correct, not how
to exploit it.

Severity: **High** — breaks a property above for an attacker in scope, or grants a
privilege the documentation does not. **Medium** — the same, given a precondition (a
granted role, a particular configuration). **Low** — defence in depth, or a
documentation gap.

| Ticket | Area | Finding | Severity | Status |
|---|---|---|---|---|
| PSQLE-177 | Cryptography, key management | (1) The AAD binds database, relation and key generation, not a tuple's position or its header. (2) Secrets can reach the server log or plaintext configuration: `SET` or `ALTER SYSTEM` of a secret GUC, passphrases passed as SQL arguments; `wallet_passphrase_command` runs through `popen()` | Low | (1) Accepted, documented. (2) Resolved: documented |
| PSQLE-178 | Client tools, cryptography | (1) `pg_basebackup_tde` does not secure its session's `search_path` and calls the extension's function unqualified. (2) IVs come from a per-process batch of 256 random values, with no check that the process drawing from it is the one that filled it; there is no written limit of encryptions per DEK before rotation | Medium | Fixed in 1.7.2: the tool empties its `search_path` and calls the extension's schema; the batch is refilled by a process that did not fill it; the limit (2^32 per DEK generation) is documented |
| PSQLE-180 | Supply chain | GitHub Actions pinned by tag rather than by commit; floating container images in CI (`openbao:2`, `vault:latest`); a binary downloaded without a checksum; release assets neither checksummed as a whole nor signed | Medium | Fixed in 1.7.2: actions pinned by commit, service images by digest, downloads checked, all checked by `make ci-pins`; releases carry `SHA256SUMS` signed by a maintainer, an SPDX SBOM and a vulnerability scan; a release tag reaches GitHub only signed by a maintainer |
| PSQLE-205 | SQL surface | `pg_vault_tde_reencrypt_table()`, granted to `pg_monitor`, rewrote any table without a privilege check | Medium | Fixed in 1.7.2: requires `MAINTAIN` on the table, checked on the calling role; removing the grant is 1.8 (PSQLE-212) |
| PSQLE-206 | SQL surface | (1) The key-management functions checked `superuser()` inside `SECURITY DEFINER`, which is the owner; `wallet_init()` is granted to `pg_monitor`; `pkcs11_keygen()` checked nothing. (2) `pg_vault_tde_seal_keys()` and `pg_vault_tde_unseal_keys()` write and read a file on the server at a path the caller chooses | High | Fixed in 1.7.2: the calling role must be a superuser — for (2) the same power as writing server files; removing the grant is 1.8 (PSQLE-212) |
| PSQLE-217 | SQL surface | The 12 `SECURITY DEFINER` functions run without a fixed `search_path`; two are `LANGUAGE SQL` (`pg_vault_tde_reencrypt_table(text, int)`, `pg_vault_tde_check_plaintext_index_keys()`). The fix changes the extension script. Until then, a superuser can run `ALTER FUNCTION … SET search_path = pg_catalog, <extension schema>` on each, and revoke `reencrypt_table()` from `pg_monitor` ([README](../README.md#who-may-call-reencrypt_table)) | Medium | Open — 1.8 |
| PSQLE-218 | Cryptography | The v5 layout — the null bitmap and the length headers of variable-length attributes — is outside the tag and the AAD: a writer to the data files can redistribute a row's bytes among its variable-length attributes without failing the tag, though not change or add one. Fix: authenticate the layout in a new tuple format | Low (needs write access to the data files) | Open — 1.8 |

---

## Workflow

- **Independence.** The person who signs a review should not be the author of the
  code it covers — for a delta review, of the delta. While the project has a single
  maintainer, the author writes and signs it: the review then says so in its first
  line (*self-review*), and a review by another person replaces it when there is one.
- **Signature.** The review is a file, `doc/security/reviews/v<version>.md`, with a
  detached signature by its reviewer next to it, `v<version>.md.asc`
  (`gpg --armor --detach-sign`). A file's signature, unlike a commit's or a tag's,
  survives the GitHub mirror, which rewrites every commit; it also ships in the source
  bundle, which the release's signed `SHA256SUMS` covers. The file states the
  reviewer, the key fingerprint, the commit reviewed, the scope and the date. The
  release tag, signed, comes after the commit that adds it.
- **Scope.**
  - *Full review* - every release that changes `extversion` (1.7 → 1.8), and any
    release that changes the cryptography, the on-disk format or the handling of keys.
  - *Delta review* - other patch releases: the diff since the last reviewed tag,
    against this checklist.
- **Findings.** Every finding becomes a ticket, and [Findings](#findings) lists it
  under that ticket; a release is not tagged while a High finding is open.
- **Evidence.** `make ci-security-report` (PSQLE-182), or the Bitbucket custom
  pipeline `security-report`, run on the commit under review, writes
  `doc/security/evidence/v<version>.md`: that commit and whether the tree was clean,
  the system libraries the module and the client tools link, by soname (OpenSSL 3,
  libcurl, libpq: not in the SBOM, updated by the system), the tools and their
  versions, and the result and counts of the pin check, the
  Semgrep rules, the SBOM of the source bundle and its grype scan, the error-path
  suite, scan-build, UBSan, ASan, Valgrind and the assertion-enabled build
  (PSQLE-181), with every `nosemgrep` line of the code. It is
  committed with the review; the release tag may differ from the commit it names only
  in `doc/security/` and the [Reviews](#reviews) table
  (`git diff --stat <commit> v<version>`). CodeQL's alerts and the signed checksums
  are those of the release (PSQLE-180), which publishes the same SBOM and scan.

### Reviews

| Version | Scope | Reviewer | Commit / tag | Date |
|---|---|---|---|---|
| 1.7.2 | Full (first review; the on-disk format changed); self-review | Matteo Durighetto | `02bcf69f6a0d22cc9a81686f7113e6ef80ad1cd4` | 2026-10-02 |

---

## Where this document lives

- [SECURITY.md](../SECURITY.md) links here.
- The file is part of the PGXN release bundle: `make dist` archives `doc/`, and only
  `doc/logical_decoding_research.md` is excluded (`.gitattributes`). Every link above
  points into the bundle - the README and `doc/` - never to the wiki, which the bundle
  does not carry.
