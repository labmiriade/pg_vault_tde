# Backup and Restore

pg_vault_tde ships three tools to keep backups confidential and keep primary/
standby key state in sync: `pg_dump_tde` / `pg_restore_tde` for logical
backups, and `pg_basebackup_tde` (a wrapper around `pg_basebackup`) for
physical backups. This page also covers doing it manually with plain
`pg_basebackup` plus the key-sealing functions directly.

## Logical Backups: `pg_dump_tde` / `pg_restore_tde`

Plain `pg_dump` reads rows through the normal decrypt-on-read path, so **the
resulting dump file is plaintext** — encryption doesn't survive a logical
dump unless you use these wrappers.

```bash
# Encrypted dump
pg_dump_tde -h localhost -U postgres -d mydb -o /backup/mydb.tde

# Restore encrypted dump
pg_restore_tde -h localhost -U postgres -d mydb -i /backup/mydb.tde
```

All other `pg_dump`/`pg_restore` options are forwarded through. Internally:

1. `pg_dump_tde` forks `pg_dump -Fc`, capturing its stdout through a pipe.
2. It reads `pg_vault_tde.kms_provider` from the target database's GUCs,
   generates a fresh DEK, wraps it via the active KMS provider, and writes a
   backup header (magic + format version + wrapped DEK) to the output file.
3. The `pg_dump` stream is encrypted in independently-authenticated 64 KB
   blocks (the block sequence number is bound as GCM AAD, so reordering
   blocks is detectable).
4. If `pg_dump` fails mid-stream, the partial output file is deleted
   automatically — you will never be left with a truncated, silently
   "successful" backup file.

### Current Limitations

1. Only `-Fc` (custom) dump format is supported.
2. `-j` (parallel jobs) is **not** supported — `pg_dump`'s parallel mode only
   works with the directory format (`-Fd`), which these tools don't produce.
3. Fixed block size of 64 KB (not configurable).
4. **Restore is locked to the original KEK** used to wrap the dump's DEK. If
   you need to restore into a database using a *different* wallet (`local`
   provider) than the one that created the dump, restore will fail — you
   need either the original wallet, or a new wallet that has re-imported the
   original KEK.
   - **`DROP DATABASE` deletes that database's `.p12` wallet file.** Any
     `pg_dump_tde` backup created before the drop becomes permanently
     undecryptable if no other copy of the wallet survives. Treat the wallet
     file as part of what you must retain, not just the dump.
5. File-only input/output: `-o`/`--output` (dump) and `-i`/`--input`
   (restore) are mandatory. Neither tool supports piping or stdin/stdout.
6. `kms_provider = 'pkcs11'` is **not** supported by these tools yet — they
   exit with a clear error. Use `pg_basebackup`/`pg_basebackup_tde` for
   PKCS#11-backed databases instead.
7. Running plain `pg_dump` against a pg_vault_tde database still produces a
   plaintext backup — this is expected (see above), not a bug in `pg_dump`.

## Physical Backups: `pg_basebackup`

`pg_basebackup` works against a pg_vault_tde cluster with **no special
configuration on the primary**: encrypted relation files are copied as-is,
and the wrapped DEKs travel with the data directory inside the
`pg_vault_tde_catalog` table. Critically, **the KEK never travels with the
backup** — it stays in the KMS/wallet/HSM, the same model used by Oracle
RMAN, SQL Server TDE, and Percona `pg_tde`.

### Provisioning the KEK on a Standby / Restore Target

The wrapped DEKs arrive for free with the base backup; the KEK must be made
available on the target separately, depending on provider:

| Provider | What to do on the standby/target |
|---|---|
| `local` | Copy the primary's `wallet.p12` to the standby (it lives outside `PGDATA`, so a plain base backup does **not** include it) |
| `vault` | Point the standby at the **same** Vault/OpenBao instance — nothing to copy |
| `pkcs11` | Ensure the standby has access to the same (or a replicated) HSM token under the same label |

### Sealing the DEK Catalog (Manual)

`pg_vault_tde_seal_keys()` writes a signed, point-in-time snapshot of every
wrapped DEK to accompany a backup; `pg_vault_tde_unseal_keys()` verifies and
re-imports it on the target. This makes the key state **tamper-evident** and
guards against key-rotation drift between primary and standby.

```sql
-- On the primary, before pg_basebackup:
SELECT pg_vault_tde_seal_keys('/backup/keys.sealed', 'a-seal-passphrase');
```
```bash
pg_basebackup -h primary -D /backup/data -X stream
# local provider only: also transport the wallet, e.g.
#   scp /path/to/wallet.p12 standby:/path/to/wallet.p12
```
```sql
-- On the standby, after restoring the data directory and provisioning the KEK:
SELECT pg_vault_tde_unseal_keys('/backup/keys.sealed', 'a-seal-passphrase');
```

The HMAC key protecting the sealed bundle is derived from the seal
passphrase (PBKDF2-SHA256) and is independent of the KMS provider, so the
same bundle format works across local and Vault deployments.
`unseal_keys()` verifies the HMAC **before** touching the catalog — a
tampered bundle or wrong passphrase is rejected and nothing is written.

> **Rotation drift.** If the KEK or a DEK is rotated after a backup was
> sealed, primary and standby can drift apart. Re-run `seal_keys()` (or
> `pg_basebackup_tde`) after any rotation, and `unseal_keys()` on the
> standby, to realign. See [Key Rotation](Key-Rotation).

> **Concurrency.** Don't run `unseal_keys()` while
> `pg_vault_tde_rotate_online()` is rotating the same table — PostgreSQL's
> MVCC checks make this fail safely (a `tuple concurrently updated` or
> duplicate-key error, nothing partially imported); just re-run
> `unseal_keys()` once the rotation finishes.

### Automatic Key Sealing: `pg_basebackup_tde`

`pg_basebackup_tde` wraps `pg_basebackup` and performs the sealing step
**automatically**, for every database in the cluster that has the extension
installed (the DEK catalog is per-database; `pg_basebackup` itself is
cluster-wide):

```bash
# Passphrase from a 0600 file (the ~/.pgpass pattern):
pg_basebackup_tde -h primary -D /backup/data -X stream \
    --seal-passphrase-file /etc/pg_vault_tde/seal.pass

# ...or from the environment:
export PG_VAULT_TDE_SEAL_PASSPHRASE='a-seal-passphrase'
pg_basebackup_tde -h primary -D /backup/data -X stream
```

The passphrase is **never** accepted as a command-line argument — it would
leak into `ps` output and shell history. `--seal-passphrase-file` (first
line of the file) takes precedence over the environment variable.

All other options are forwarded verbatim to `pg_basebackup`. For every
database with `pg_vault_tde` installed, the wrapper calls
`pg_vault_tde_seal_keys_bytea()` **before** the backup starts (a
point-in-time key snapshot) and, **only if the backup succeeds**, writes one
bundle per database next to the backup:

```
/backup/data/pg_vault_tde_keys.<datname>.sealed   (mode 0600)
```

Use `--keys-dir DIR` to store the bundles elsewhere (e.g. outside `PGDATA`).
Databases without the extension are skipped; a failed backup leaves no
bundle files behind, so you never end up with a sealed-keys file that
doesn't correspond to a valid backup.

Restore stays manual: restore the data directory, provision the KEK on the
target, then for each database:

```sql
SELECT pg_vault_tde_unseal_keys('/backup/data/pg_vault_tde_keys.<db>.sealed', '...');
```

The tar format (`-Ft`) is **not** supported by `pg_basebackup_tde` — use the
plain format, or fall back to running `pg_vault_tde_seal_keys()` manually
alongside a tar-format `pg_basebackup`.

## Choosing an Approach

| Scenario | Recommended tool |
|---|---|
| Single-database logical backup, portable across major versions | `pg_dump_tde` / `pg_restore_tde` |
| Standby provisioning / point-in-time recovery base | `pg_basebackup_tde` (or `pg_basebackup` + manual `seal_keys`/`unseal_keys`) |
| `kms_provider = 'pkcs11'` | `pg_basebackup_tde` only — the logical tools don't support PKCS#11 yet |
| Cluster with multiple databases, some without the extension | `pg_basebackup_tde` (skips databases without the extension automatically) |

## See Also
- [Key Management Overview](Key-Management-Overview)
- [Key Rotation](Key-Rotation)
- [SQL Function Reference](SQL-Function-Reference)
- [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
