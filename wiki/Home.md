# pg_vault_tde

**Transparent Data Encryption (TDE) for PostgreSQL 17+.**

pg_vault_tde is a PostgreSQL extension that transparently encrypts table data
at rest, with zero modifications to PostgreSQL core. It plugs in as a Table
Access Method (`encrypted_heap`) and an Index Access Method (`tde_btree`):
every tuple is encrypted with **AES-256-GCM** before it reaches the storage
manager, and decrypted after it leaves — application queries never change.

Encryption keys are managed by **HashiCorp Vault / OpenBao**, a **local
PKCS#12 wallet**, or a **PKCS#11 hardware security module (HSM)**, and are
cached in shared memory with support for online rotation.

This wiki is the operational reference for **DBAs and DevOps/platform
engineers** who install, configure, and run pg_vault_tde in production. It
does not cover the C internals of the extension itself (see
`doc/pg_vault_tde.md` in the source repository if you need to modify the
extension's code).

---

## At a Glance

| | |
|---|---|
| **Current release** | v1.7 |
| **PostgreSQL 17** | ✅ Supported |
| **PostgreSQL 18** | ✅ Supported |
| **PostgreSQL 19** | 🔜 Planned |
| **Tuple encryption** | AES-256-GCM |
| **Index key encryption** | AES-256-SIV (equality-only) |
| **Key backends** | HashiCorp Vault / OpenBao, local PKCS#12 wallet, PKCS#11 / HSM |
| **License** | BSD (PostgreSQL License) |

---

## Where Do I Start?

- **Never used pg_vault_tde before?** Start with [Installation](Installation),
  then [Getting Started](Getting-Started).
- **Choosing how to store your encryption keys?** Read
  [Key Management Overview](Key-Management-Overview).
- **Preparing for a production rollout?** Read
  [Security Considerations](Security-Considerations),
  [Backup and Restore](Backup-and-Restore), and
  [Auditing and Monitoring](Auditing-and-Monitoring).
- **Something isn't behaving as expected?** Check
  [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting).
- **Looking for an exact parameter or function signature?** Jump straight to
  [GUC Reference](GUC-Reference) or [SQL Function Reference](SQL-Function-Reference).

---

## Documentation Map

### Setup
- [Installation](Installation) — package/source install, `shared_preload_libraries`, `CREATE EXTENSION`
- [Getting Started](Getting-Started) — your first encrypted table, end to end

### Key Management
- [Key Management Overview](Key-Management-Overview) — provider comparison, DEK/KEK model, multi-tenant configuration
- [KMS: HashiCorp Vault / OpenBao](KMS-HashiCorp-Vault-OpenBao)
- [KMS: Local Wallet](KMS-Local-Wallet)
- [KMS: PKCS#11 / HSM](KMS-PKCS11-HSM)
- [Key Rotation](Key-Rotation) — DEK and KEK rotation runbook

### Using Encryption
- [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes) — `encrypted_heap`, `tde_btree`, what's encrypted and what isn't
- [Logical Replication](Logical-Replication) — publishing encrypted tables to subscribers

### Operations
- [Backup and Restore](Backup-and-Restore) — `pg_dump_tde`, `pg_basebackup_tde`, key sealing, standby setup
- [Auditing and Monitoring](Auditing-and-Monitoring) — audit log format, health checks, SIEM integration
- [Performance and Tuning](Performance-and-Tuning) — expected overhead, hardware acceleration
- [Security Considerations](Security-Considerations) — threat model and hardening checklist

### Reference
- [GUC Reference](GUC-Reference) — every configuration parameter
- [SQL Function Reference](SQL-Function-Reference) — every SQL-callable function
- [Compatibility and Versioning](Compatibility-and-Versioning) — PostgreSQL/OpenSSL support matrix, upgrade notes
- [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
- [Glossary](Glossary) — DEK, KEK, AAD, and other terms used throughout this wiki

---

## License & Copyright

BSD License (PostgreSQL License). Compatible with MIT, BSD, ISC, and Apache 2.0;
not derived from any GPL/AGPL-licensed code.

Copyright © 2026 Miriade S.r.l.
