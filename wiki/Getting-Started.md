# Getting Started

This page walks through the smallest possible end-to-end setup: install,
configure one key backend, create an encrypted table, and confirm the data is
actually encrypted at rest. It assumes the extension is already loaded — see
[Installation](Installation).

## 1. Pick a Key Backend

For a first try, the **local wallet** provider is the fastest path — no
external service required. Production deployments typically use HashiCorp
Vault / OpenBao or a PKCS#11 HSM; see
[Key Management Overview](Key-Management-Overview) to choose.

```ini
# postgresql.conf
pg_vault_tde.kms_provider          = 'local'
pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_PASSPHRASE'
pg_vault_tde.wallet_auto_open      = on
pg_vault_tde.enabled               = on
```

```bash
export TDE_WALLET_PASSPHRASE='my-strong-wallet-passphrase'
```

Restart PostgreSQL, then initialize the wallet once (as superuser):

```sql
\set PASSPHRASE `echo $TDE_WALLET_PASSPHRASE`
SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
SELECT * FROM pg_vault_tde_wallet_status();
```

Full details, including HashiCorp Vault/OpenBao and PKCS#11/HSM setup, are in
[Key Management Overview](Key-Management-Overview).

## 2. Create an Encrypted Table

```sql
CREATE TABLE users (
    id     bigserial PRIMARY KEY,
    email  text,
    ssn    text,
    dob    date
) USING encrypted_heap;

INSERT INTO users (email, ssn, dob)
VALUES ('alice@example.com', '123-45-6789', '1990-01-15');

-- Data is transparently decrypted on read — no application changes needed
SELECT email, ssn FROM users WHERE id = 1;
```

The `USING encrypted_heap` clause is the only difference from a normal
`CREATE TABLE`. Every column value in the table is encrypted with
AES-256-GCM; regular `heap` tables elsewhere in the database are completely
unaffected.

## 3. Add an Encrypted Index (Optional)

Equality lookups (`=`, `IN`, `ON CONFLICT`) can use a `tde_btree` index, which
encrypts the index keys themselves with AES-256-SIV:

```sql
CREATE INDEX ON users USING tde_btree (email);

SELECT id FROM users WHERE email = 'alice@example.com';  -- uses the encrypted index
```

`tde_btree` does **not** support range predicates (`>`, `<`, `BETWEEN`) or
index-only scans — see
[Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes) for the full
picture before deciding which columns to index this way.

## 4. Confirm It's Actually Encrypted

```sql
-- Integrity/format scan over every tuple in the table
SELECT * FROM pg_vault_tde_verify_integrity('users');

-- Storage overhead added by encryption (37 bytes/tuple with the current wire format)
SELECT * FROM pg_vault_tde_encrypted_size('users');
```

For a byte-level check, stop PostgreSQL and grep the relation file on disk
for a plaintext value you inserted (e.g. `123-45-6789`) — it should not
appear.

## What Gets Encrypted

| Layer | Encrypted? | Notes |
|---|---|---|
| Tuple user data | ✅ Yes — AES-256-GCM | Every column value in an `encrypted_heap` table |
| HeapTupleHeader (xmin/xmax/ctid/infomask) | ✗ No | Required in plaintext for MVCC |
| `tde_btree` index keys | ✅ Yes (equality only) | AES-256-SIV; opt-in per index |
| Standard `btree`/other index keys | ✗ No | Use `tde_btree` if the key values themselves are sensitive |
| TOAST (large column values) | ✅ Yes | Encrypted per-chunk, same DEK as the parent table |
| WAL | ✅ Yes | Tuple bytes are encrypted before `heap_insert()` |
| `pg_statistic` (ANALYZE output) | ✗ No | Plaintext — see [Security Considerations](Security-Considerations) |

Only tables explicitly created (or altered) with `encrypted_heap` are
affected — this is an opt-in, per-table access method, not a cluster-wide
setting.

## Next Steps

- [Key Management Overview](Key-Management-Overview) — choosing and configuring a production key backend
- [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes) — full compatibility matrix (scans, VACUUM, replication, …)
- [Backup and Restore](Backup-and-Restore) — don't take a backup before reading this
- [Security Considerations](Security-Considerations)
