# Logical Replication

pg_vault_tde ships a logical decoding output plugin, `pg_vault_tde_pgoutput`,
so that `encrypted_heap` tables can be published to logical replication
subscribers **in plaintext**, even though their on-disk storage and WAL are
ciphertext. Subscribers see normal decrypted rows — no client-side
decryption logic is needed.

## Why a Plugin Is Needed

The table access method's decrypt-on-read callbacks run inside the query
executor. A logical decoder reads raw WAL records directly, bypassing the
executor entirely — so without a dedicated plugin, a subscriber would
receive encrypted garbage instead of usable rows.

## Setting It Up

The plugin wraps the built-in `pgoutput` transparently: it decrypts each
tuple in place before delegating to `pgoutput` for serialization, so the
wire protocol emitted is **identical** to standard `pgoutput` — it works
with both `pg_recvlogical` and a native `CREATE SUBSCRIPTION`/`CREATE
PUBLICATION` workflow, with no special syntax on the publisher side beyond
normal publication setup:

```sql
CREATE PUBLICATION mypub FOR TABLE secrets;
```

## TOAST Columns Need an Extra Step

Externally-TOASTed column values need more than in-place decryption: the
core reorder buffer reassembles a TOASTed value from its chunks **before**
any output-plugin callback runs, and it cannot do that correctly against
still-encrypted chunks. pg_vault_tde resolves this with a custom WAL
resource manager, gated by a dedicated GUC:

```ini
pg_vault_tde.toast_custom_rmgr = on   # PGC_POSTMASTER — requires a restart
```

This requires `pg_vault_tde` to already be in `shared_preload_libraries`
(true by default for the extension) and defaults to **off**. Enable it if
any published table has TOASTable columns whose out-of-line values need to
reach subscribers.

## Requirements and Supported Operations

| Operation | Requirement |
|---|---|
| INSERT (inline values, TOASTed values, bursts) | `pg_vault_tde.toast_custom_rmgr = on` if the table has TOASTable columns |
| Initial table sync (COPY) | Works automatically via the normal TAM decrypt-on-read path |
| UPDATE / DELETE | **`REPLICA IDENTITY FULL` + a primary key**, mandatory |

### Why `REPLICA IDENTITY FULL` + a Primary Key Is Mandatory

With `REPLICA IDENTITY DEFAULT`, PostgreSQL core derives the replica
identity by reading the **encrypted** old tuple as if it were the identity
key — producing a constant, meaningless value. The subscriber would then
silently target the wrong row on UPDATE/DELETE. Tables without a primary key
are unsupported for the same reason (there is no key to match on). These are
documented, structural limitations of the extension API — not bugs — because
to PostgreSQL core, an `encrypted_heap` tuple is just an opaque ciphertext
blob wherever it tries to read a single column value directly.

```sql
ALTER TABLE secrets REPLICA IDENTITY FULL;   -- required on any table that is
                                              -- a logical-replication UPDATE/DELETE source
```

## Structural Limitations

- **Aborted, non-streamed transactions.** A TOAST-writing transaction that
  reaches a full snapshot and then aborts *without ever being streamed*
  leaves its captured chunks in memory until the decoding process exits —
  there is no output-plugin hook for non-streamed aborts. This is a slow,
  per-abort memory leak in the decoding process, not a per-row leak; restart
  the logical decoding worker/`walsender` periodically if your workload has
  many such aborts.
- **Resource manager ID.** The custom WAL resource manager currently uses the
  experimental ID `RM_EXPERIMENTAL_ID` (128); a stable ID will be reserved
  with the PostgreSQL community before this feature reaches general
  availability. Confirm no other extension on the same server also claims
  this experimental ID.

## See Also
- [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes)
- [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
- [GUC Reference](GUC-Reference)
