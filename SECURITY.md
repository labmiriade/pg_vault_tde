# Security Policy

`pg_vault_tde` is a Transparent Data Encryption extension: a defect in it can
expose data that its users believe is encrypted at rest. We treat security
reports as the highest-priority class of issue and we would much rather hear
about a problem privately, first, than read about it anywhere else.

## Supported Versions

Security fixes are issued for the current minor release series. Older series
receive fixes only for critical issues, and only where the fix does not
require an on-disk format change.

| Version | Supported |
|---------|-----------|
| 1.7.x   | ✅ Yes — current release series |
| 1.6.x   | ⚠️ Critical fixes only |
| ≤ 1.5.x | ❌ No — please upgrade |

Supported PostgreSQL majors are 17 and 18. Reports against an unsupported
PostgreSQL major are welcome, but a fix may require you to upgrade.

## Reporting a Vulnerability

**Please do not open a public GitHub issue, pull request, or discussion for a
security vulnerability.** Public issue trackers are indexed immediately, and a
report there is a disclosure whether or not it was meant as one.

Use one of these two private channels instead:

1. **GitHub Private Vulnerability Reporting (preferred).** Go to the
   [Security tab](https://github.com/labmiriade/pg_vault_tde/security) of this
   repository and click **Report a vulnerability**. This opens a private
   advisory visible only to you and the maintainers, keeps the whole
   discussion in one place, and lets us credit you and issue a CVE from the
   same thread when the fix ships.

2. **Email.** If you cannot or would rather not use GitHub, write to
   **supportodb@miriade.it** with `pg_vault_tde security` in the subject line.
   Tell us in that first mail if you need an encrypted channel and we will
   arrange one before you send any details.

### What to Include

The more of this you can provide, the faster we can confirm and fix:

- The `pg_vault_tde` version (`SELECT extversion FROM pg_extension WHERE
  extname = 'pg_vault_tde';`) and the PostgreSQL major version.
- The KMS provider in use (`vault`, `local`, or `pkcs11`) and anything unusual
  about how it is configured.
- A description of the impact — what an attacker gains, and what access they
  need to start with.
- Reproduction steps, ideally as SQL plus the relevant `postgresql.conf`
  settings. A failing test case is the ideal report.
- Any log excerpts, backtraces, or `AUDIT` lines you have. Please redact real
  key material and real data before sending.

### What Happens Next

| When | What we do |
|------|------------|
| Within 3 working days | We acknowledge your report and tell you who is handling it. |
| Within 10 working days | We confirm or dispute the finding and give you a severity assessment and a rough remediation timeline. |
| While we work | We keep you updated at least every 10 working days, and we send you the proposed fix for review before release whenever you want to see it. |
| At release | We publish a fixed version, a GitHub Security Advisory, and a `Changes` entry. |

We aim to ship a fix for a confirmed critical issue within 30 days of
confirmation, and to coordinate the public disclosure date with you. If you
have a disclosure deadline of your own, tell us at the start and we will work
to it rather than against it.

### Recognition

We credit reporters by name (or by handle, or not at all — your choice) in the
advisory and in `CONTRIBUTORS.md`. We do not operate a paid bug bounty.

## Scope

**In scope** — anything that breaks the guarantees the extension actually
makes:

- Recovery of plaintext, of a Data Encryption Key, or of a Key Encryption Key
  from any artifact that is supposed to contain only ciphertext: relation
  files, TOAST files, `pg_basebackup` output, `pg_dump_tde` archives, key seal
  bundles, or the `pg_vault_tde_catalog` table.
- Any path that writes plaintext derived from an `encrypted_heap` table to
  disk without going through the encryption path, beyond the cases already
  documented as known limitations (see below).
- Flaws in the cryptography: nonce or IV reuse, an authentication tag that is
  not verified, a weak or predictable key derivation, a padding or timing
  oracle.
- Key-material leaks: a DEK or KEK reaching the server log, a core dump, a
  temporary file, an error message, or memory that is never cleansed.
- Privilege escalation, or any bypass of the `SECURITY DEFINER` and role
  checks guarding the extension's SQL functions.
- Memory-safety defects in the C code reachable from SQL or from KMS
  responses — buffer overflows, use-after-free, or a crash that is
  exploitable rather than merely a crash.
- Authentication or transport flaws against a KMS backend, including
  certificate validation that is skipped or an authentication token that is
  logged.

**Out of scope** — these are documented properties of the design, not
vulnerabilities. Please read
[Security Considerations](https://github.com/labmiriade/pg_vault_tde/wiki/Security-Considerations)
and
[Known Limitations and Troubleshooting](https://github.com/labmiriade/pg_vault_tde/wiki/Known-Limitations-and-Troubleshooting)
before reporting:

- A PostgreSQL superuser, or any suitably privileged role, reading plaintext
  through SQL. Decryption is transparent by design; TDE protects the storage
  layer, not in-database authorization.
- Plaintext visible in the memory of a running backend to someone who can
  already read that process's memory.
- WAL structural metadata (LSNs, block numbers, relation OIDs) being
  plaintext. Only tuple payload bytes are ciphertext, and full WAL encryption
  is not achievable from an extension.
- `pg_statistic` holding plaintext value distributions after `ANALYZE`.
- The `WITH HOLD` cursor tuplestore spilling plaintext to a temporary file
  above `work_mem`.
- Anything requiring physical access to unlocked hardware, or an attacker who
  already holds the KEK.
- Vulnerabilities in PostgreSQL itself — report those to the
  [PostgreSQL security team](https://www.postgresql.org/support/security/) —
  or in OpenSSL, libcurl, HashiCorp Vault, OpenBao, or your HSM vendor's
  PKCS#11 module. Report those upstream. If the flaw is in *how we use* one of
  them, that is in scope and we want to hear about it.
- Reports produced solely by an automated scanner, with no demonstrated impact
  on this extension.
- Denial of service through ordinary resource exhaustion (a very large query,
  an intentionally slow KMS).

## Deployment Hardening

If you are looking for how to configure a deployment securely rather than how
to report a flaw, start with the hardening checklist in
[Security Considerations](https://github.com/labmiriade/pg_vault_tde/wiki/Security-Considerations).
