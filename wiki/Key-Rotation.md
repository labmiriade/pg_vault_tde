# Key Rotation

pg_vault_tde supports two independent kinds of rotation. Knowing which one
you need is the first decision in any rotation runbook:

| | **DEK rotation** | **KEK rotation** |
|---|---|---|
| What changes | The per-table Data Encryption Key | The master Key Encryption Key that wraps every DEK |
| What gets re-encrypted | Every row of the target table (and its `tde_btree` indexes, if rebuilt) | Nothing — only the wrapped DEK blobs in `pg_vault_tde_catalog` are re-wrapped |
| Function | `pg_vault_tde_rotate_online(regclass, batch_size)` | `pg_vault_tde_rotate_kek()` |
| Scope | One table (or index) at a time | Cluster-wide (the KEK is per-database, per-provider) |
| Locking | `ShareRowExclusiveLock` while re-encrypting: reads continue, writes wait; never `AccessExclusiveLock` on the table | Transactional catalog updates only |
| Typical trigger | Suspected compromise of a specific table's key, routine per-table key hygiene | Suspected KEK compromise, compliance-mandated rotation interval, wallet passphrase change |

Both are **online** operations — no downtime and no exclusive lock that
blocks reads for the duration of the rotation.

## DEK Rotation

```sql
SELECT pg_vault_tde_rotate_online('mytable', 1000);   -- 1000 = batch size

-- Monitor progress for one relation:
SELECT * FROM pg_vault_tde_get_rotation_status('mytable');
-- Or cluster-wide, across every in-progress/completed rotation:
SELECT * FROM pg_vault_tde_rotation_status;   -- view, readable by pg_monitor
```

`rotate_online` accepts either a table or a `tde_btree` index relation:

| Target | What happens |
|---|---|
| `encrypted_heap` table | Generates a new table DEK, re-encrypts every tuple in place in one transaction (`ShareRowExclusiveLock` on the table: `SELECT` continues, writes wait), then rebuilds any `tde_btree` indexes on the table so their AES-SIV ciphertexts match the new DEK. Every other index — `PRIMARY KEY` and `UNIQUE` included — gets an entry for each rewritten row, as with an `UPDATE`. Up to 1.7.1 they got none; see *`rotate_online()` and indexes* in the README. |
| `tde_btree` index | Generates a new **index** DEK, then rebuilds the index (`AccessExclusiveLock` on the index, `ShareRowExclusiveLock` on its table) with keys encrypted under the new DEK. The parent table's DEK and heap data are untouched. Passing a non-`tde_btree` index raises an error before touching shared memory or the catalog. |

Mechanically, rotation works by **generation epoch**. Every ciphertext
carries the generation of the key that wrote it:

1. The rotation locks the table against writes (`SELECT` continues), then
   takes its snapshot, so every row committed before it started is included.
2. The current DEK moves to `prev_dek`, and the new DEK stays in the
   rotation worker's own memory. The worker re-encrypts every row with it,
   out-of-line (TOAST) values included, in one transaction.
3. Every other session keeps reading with the outgoing DEK, which is what
   the catalog shows them until the rotation commits.
4. At commit the shared cache switches to the new DEK before the lock is
   released, so the writers waiting on it resume with the new key. If the
   rotation fails, the outgoing DEK stays current.

> **Logical replication:** a rotation reaches subscribers as one `UPDATE`
> per row, and every logical slot of the database must decode past it before
> the publisher restarts or the same table is rotated again: until then the
> previous DEK exists only in shared memory. A slot left behind stops with
> `pg_vault_tde: decryption failed`.

> Up to 1.7.1 a rotation of a table that was being read or written could
> make it unreadable after the next restart. See *`rotate_online()` with
> concurrent access* in the README before restarting to install 1.7.2.
>
> Up to 1.7.1 a rotation also left the table's out-of-line values under the
> outgoing key: they became unreadable at the next restart or the next
> rotation. See *`rotate_online()` and out-of-line values* in the README.

If a table has `tde_btree` indexes, rotating the table implicitly produces
correct index entries under the new table DEK (the index rebuild reads the
newly re-encrypted heap rows). To **also** rotate an index's own DEK, call
`rotate_online` on the index relation directly, as a separate step.

## KEK Rotation

```sql
-- Works identically for the local wallet, Vault Transit, and PKCS#11 providers:
SELECT pg_vault_tde_rotate_kek();
```

This re-wraps every stored DEK under a brand-new KEK. **No tuple data is
touched** — this is purely a catalog-level operation and is typically much
faster than a DEK rotation of any single large table.

> **Local wallet users:** `pg_vault_tde_wallet_change_passphrase(old, new)`
> already rotates the KEK as part of changing the passphrase — do not call
> `rotate_kek()` separately afterward. See
> [KMS: Local Wallet](KMS-Local-Wallet).

> **PKCS#11 users:** old KEK generations are never deleted from the token,
> so a crash mid-rotation is always safe to retry — see
> [KMS: PKCS#11 / HSM](KMS-PKCS11-HSM) for the generation model.

> **Local wallet users:** since 1.7.2 the wallet file keeps every KEK version,
> and a rotation adds the new one before it re-wraps anything. A rotation that
> rolls back, fails or crashes loses nothing. Up to 1.7.1 it replaced the only
> KEK before committing, and a rotation that did not commit made the database
> unreadable — see *KEK versions in the local wallet* in the README.

## One Key Operation at a Time

Rotations and wallet operations are tested on their own and under concurrent
reads and writes, not against one another. Until 1.8, run `rotate_online()`,
`rotate_kek()`, `wallet_change_passphrase()`, `wallet_lock()` /
`wallet_unlock()`, `migrate_vault_to_wallet()`, `seal_keys()` /
`unseal_keys()` and `reencrypt_table()` one at a time in each database, and
start the next only once `pg_vault_tde_rotation_status` shows no rotation
`running`: no KEK rotation or passphrase change during a DEK rotation, no
`wallet_lock()` during a rotation, no two DEK rotations at once (even of
different tables), no DDL on a table being rotated. See *One key operation at
a time* in the README.

## Recommended Rotation Cadence

pg_vault_tde does not enforce a rotation schedule — this is a policy
decision driven by your compliance requirements (e.g. PCI DSS) and threat
model. As a starting point:

- **KEK rotation**: on suspected compromise, on offboarding anyone with
  access to KEK material, or on a fixed compliance-mandated interval (e.g.
  annually). Cheap enough to run more often if policy requires it.
- **DEK rotation**: for tables holding the most sensitive data, on a
  schedule aligned with your data classification policy; otherwise, on
  suspected compromise of a specific table's key or generation.

## Interaction With Backups

If a KEK or DEK is rotated **after** a physical backup was sealed (see
[Backup and Restore](Backup-and-Restore)), the primary and the standby/backup
can drift out of sync. Re-run `pg_vault_tde_seal_keys()` (or
`pg_basebackup_tde`) after any rotation, and re-run
`pg_vault_tde_unseal_keys()` on the standby to realign it.

Do not run `pg_vault_tde_unseal_keys()` concurrently with
`pg_vault_tde_rotate_online()` on the same table — PostgreSQL's own MVCC
checks make the conflict fail safely (a `tuple concurrently updated` or
duplicate-key error, nothing partially imported); simply re-run
`unseal_keys()` once the rotation has finished.

## See Also
- [Key Management Overview](Key-Management-Overview)
- [KMS: HashiCorp Vault / OpenBao](KMS-HashiCorp-Vault-OpenBao)
- [KMS: Local Wallet](KMS-Local-Wallet)
- [KMS: PKCS#11 / HSM](KMS-PKCS11-HSM)
- [Backup and Restore](Backup-and-Restore)
- [SQL Function Reference](SQL-Function-Reference)
