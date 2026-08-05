# Glossary

**AAD (Additional Authenticated Data)** — Extra data bound into an AES-GCM
authentication tag without being encrypted itself. pg_vault_tde binds
`(database OID, relation OID, generation)` as AAD on every tuple, so
ciphertext copied from one table/database/generation cannot be pasted into
another and decrypt successfully.

**AES-256-GCM** — The authenticated encryption algorithm used for tuple
data. Produces ciphertext plus a 16-byte authentication tag; any tampering
with the ciphertext, IV, or AAD is detected on decrypt and raises an error
rather than returning wrong data.

**AES-256-SIV** — The deterministic, misuse-resistant authenticated
encryption algorithm used for `tde_btree` index keys (RFC 5297).
"Deterministic" means the same plaintext always produces the same ciphertext
under the same key, which is what makes equality index lookups possible —
at the cost of not preserving ordering (no range scans).

**DEK (Data Encryption Key)** — A 256-bit key that encrypts the actual
row/tuple data of one relation. Every `encrypted_heap` table has its own
DEK, generated automatically when the table is created. See
[Key Management Overview](Key-Management-Overview).

**`encrypted_heap`** — The Table Access Method (AM) that provides
transparent per-tuple AES-256-GCM encryption. See
[Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes).

**Generation (epoch)** — A per-relation counter that increments every time a
DEK is rotated. Rows are tagged with the generation they were encrypted
under, so old and new rows can coexist and both be read correctly during a
rotation window. See [Key Rotation](Key-Rotation).

**HSM (Hardware Security Module)** — A physical or cloud-hosted device that
stores cryptographic keys and performs key operations internally, so the key
material never leaves the device. pg_vault_tde talks to an HSM via
[PKCS#11](KMS-PKCS11-HSM).

**IAM (Index Access Method)** — The PostgreSQL extension point pg_vault_tde
uses to implement `tde_btree`.

**KEK (Key Encryption Key)** — The master key that encrypts ("wraps") every
DEK. Where the KEK lives (Vault, a local wallet, or an HSM) is what a KMS
provider decides. See [Key Management Overview](Key-Management-Overview).

**KMIP** — Key Management Interoperability Protocol. A planned (not yet
implemented) future KMS provider for pg_vault_tde (v1.8+).

**KMS (Key Management Service/System)** — In this documentation, one of
pg_vault_tde's three interchangeable backends for storing and using the
KEK: HashiCorp Vault/OpenBao, a local PKCS#12 wallet, or a PKCS#11 HSM.

**PKCS#11** — A standard cryptographic API for talking to hardware security
modules and smart cards. pg_vault_tde's `pkcs11` KMS provider implements
this API directly against the vendor's module. See
[KMS: PKCS#11 / HSM](KMS-PKCS11-HSM).

**PKCS#12** — A standard container file format for storing encrypted
cryptographic material (here, the KEK), protected by a passphrase. This is
the `wallet.p12` file used by the [local wallet provider](KMS-Local-Wallet).

**TAM (Table Access Method)** — The PostgreSQL extension point pg_vault_tde
uses to implement `encrypted_heap`. Introduced in PostgreSQL 12, it lets an
extension override how tuples are physically stored and retrieved without
modifying PostgreSQL core.

**TDE (Transparent Data Encryption)** — Encryption of data at rest that
requires no changes to application queries. pg_vault_tde's implementation of
TDE operates at the table/tuple level, not the filesystem/block-device
level.

**`tde_btree`** — The Index Access Method that provides AES-256-SIV
encrypted, equality-only B-Tree indexing. See
[Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes).

**Transit (HashiCorp Vault Transit secrets engine)** — The Vault/OpenBao
component that performs encrypt/decrypt ("wrap"/"unwrap") operations on data
using a key that never leaves Vault. This is what pg_vault_tde's `vault` KMS
provider talks to. See
[KMS: HashiCorp Vault / OpenBao](KMS-HashiCorp-Vault-OpenBao).

**Unwrap** — Decrypting a wrapped DEK using the KEK, to get back the raw DEK
bytes needed for tuple encryption/decryption.

**Wallet** — The PKCS#12 file used by the local KMS provider
(`wallet.p12`). See [KMS: Local Wallet](KMS-Local-Wallet).

**Wrap** — Encrypting a DEK using the KEK, so it can be safely stored on
disk in `pg_vault_tde_catalog`.

## See Also
- [Key Management Overview](Key-Management-Overview)
- [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes)
- [Home](Home)
