# KMS: Local Wallet

The local wallet provider (`pg_vault_tde.kms_provider = 'local'`, introduced
in v1.6) protects the KEK with a PKCS#12 file on local disk, encrypted with a
passphrase. It has **no external service dependency**, making it suitable for
standalone servers, air-gapped/offline environments, and development.

## Where the Wallet Lives

```
/var/lib/pg_vault_tde/<DB_OID>/wallet.p12
```

The path is computed automatically at runtime from the current database's
OID (`SHOW pg_vault_tde.wallet_path` returns the effective path even if you
never set it explicitly). It is **deliberately outside `PGDATA`** — this is
what lets a plain `pg_basebackup` copy the wrapped DEKs without also copying
the KEK material next to them (see
[Backup and Restore](Backup-and-Restore) and
[Security Considerations](Security-Considerations)). Override only if you
have a specific reason to store the wallet elsewhere:

```ini
pg_vault_tde.wallet_path = '/custom/path/to/wallet.p12'
```

> **Package installs** create the wallet's base directory
> (`/var/lib/pg_vault_tde/`) automatically. **Source builds** must create it
> manually — see [Installation](Installation).

## Configuration

```ini
pg_vault_tde.kms_provider          = 'local'
pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_PASSPHRASE'   # env var NAME only
pg_vault_tde.wallet_auto_open      = on
pg_vault_tde.enabled               = on
```

```bash
export TDE_WALLET_PASSPHRASE='my-strong-wallet-passphrase'
```

The GUC holds the **name** of an environment variable, never the passphrase
value itself — the passphrase is never written to `postgresql.conf` or
visible in `pg_settings`. Two alternative ingestion methods are also
supported (see [GUC Reference](GUC-Reference) for full parameter details):

- `wallet_passphrase_file` — a file path containing the passphrase (trimmed;
  the file's permissions must be `0400`).
- `wallet_passphrase_command` — a shell command whose stdout is the
  passphrase (analogous to PostgreSQL's own `ssl_passphrase_command`).

`wallet_dev_mode_passphrase` (only honored when `dev_mode = on`) is a
convenience for development/CI and emits a `WARNING` on every use — never set
`dev_mode = on` in production.

## First-Time Setup

```sql
-- \set reads the shell variable without exposing the value in
-- pg_stat_activity or the server log (backslash-set is a psql meta-command)
\set PASSPHRASE `echo $TDE_WALLET_PASSPHRASE`
SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
```

This creates the wallet file and generates the KEK inside it. Check status
any time with:

```sql
SELECT * FROM pg_vault_tde_wallet_status();
-- wallet_exists, wallet_open, kek_algorithm, last_opened, file_perms
```

## Locking and Unlocking

The wallet can be locked (evicting all DEKs from shared memory) and unlocked
interactively, **without a server restart**:

```sql
SELECT pg_vault_tde_wallet_unlock('my-strong-wallet-passphrase');
SELECT pg_vault_tde_wallet_lock();
```

If `wallet_auto_open = on` and the passphrase environment variable is set,
the wallet unlocks automatically on server startup.

## Changing the Passphrase

```sql
SELECT pg_vault_tde_wallet_change_passphrase('old-passphrase', 'new-passphrase');
```

This function **automatically rotates the KEK** as part of the passphrase
change — a separate `pg_vault_tde_rotate_kek()` call afterward is unnecessary.
Rationale: if an attacker already has the old passphrase, they already have
the old KEK; changing only the passphrase without rotating the key
underneath it would provide no additional protection.

## Rotation

`pg_vault_tde_rotate_kek()` works with the local wallet exactly as with the
other providers — see [Key Rotation](Key-Rotation).

## Disaster-Recovery Note

The wallet file lives outside `PGDATA` and is therefore **not** included in a
plain `pg_basebackup`. If you lose `wallet.p12` without a separate copy,
every DEK it protects becomes permanently unrecoverable — there is no
key-escrow mechanism. Plan explicitly for this:

- Back up `wallet.p12` separately from your `pg_basebackup`/WAL archiving
  strategy, with equivalent durability guarantees.
- Before decommissioning a standby or replacing a wallet, confirm you are not
  about to orphan the only copy — `DROP DATABASE` deletes that database's
  `.p12` wallet file, and any backup encrypted under its KEK becomes
  undecryptable if no other copy of the wallet survives (see
  [Backup and Restore](Backup-and-Restore)).
- For multi-server topologies, transport the wallet to standbys explicitly —
  see [Backup and Restore](Backup-and-Restore).

## See Also
- [Key Management Overview](Key-Management-Overview)
- [Key Rotation](Key-Rotation)
- [Backup and Restore](Backup-and-Restore)
- [GUC Reference](GUC-Reference)
