# Key Rotation

pg_vault_tde supports two independent kinds of rotation. Knowing which one
you need is the first decision in any rotation runbook:

| | **DEK rotation** | **KEK rotation** |
|---|---|---|
| What changes | The per-table Data Encryption Key | The master Key Encryption Key that wraps every DEK |
| What gets re-encrypted | Every row of the target table (and its `tde_btree` indexes, if rebuilt) | Nothing — only the wrapped DEK blobs in `pg_vault_tde_catalog` are re-wrapped |
| Function | `pg_vault_tde_rotate_online(regclass, batch_size)` | `pg_vault_tde_rotate_kek()` |
| Scope | One table (or index) at a time | Cluster-wide (the KEK is per-database, per-provider) |
| Locking | `RowExclusiveLock` while re-encrypting; never `AccessExclusiveLock` on the table | Transactional catalog updates only |
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
| `encrypted_heap` table | Generates a new table DEK, re-encrypts every tuple in place (`RowExclusiveLock`), then rebuilds any `tde_btree` indexes on the table so their AES-SIV ciphertexts match the new DEK. Plain `btree` indexes on encrypted columns need no rebuild. |
| `tde_btree` index | Generates a new **index** DEK, then rebuilds the index (`AccessExclusiveLock` on the index only, not the table) with keys encrypted under the new DEK. The parent table's DEK and heap data are untouched. Passing a non-`tde_btree` index raises an error before touching shared memory or the catalog. |

Mechanically, rotation works by **generation epoch**, not a blocking
in-place key swap:

1. The current DEK is promoted to `prev_dek` and the shared-memory copy of
   the live DEK is wiped; the per-relation generation counter is
   incremented.
2. Each backend detects the generation mismatch lazily, on its next
   encrypt/decrypt call for that relation — no signal or broadcast is
   needed.
3. Rows still encrypted under the previous generation remain readable via
   `prev_dek` throughout the rotation window.
4. Once `rotate_online` finishes re-encrypting every row, the window closes.

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
