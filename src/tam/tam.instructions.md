# TAM Module Instructions — @Architect

> **Scope**: `src/tam/pg_vault_tde_tam.c`, `src/tam/pg_vault_tde_toast.c`,
> `src/include/pg_vault_tde_tam.h`, `src/include/pg_vault_tde_toast.h`

---

## Architecture Pattern

This module uses the **mutable-copy pattern**: a `static TableAmRoutine tde_methods`
struct initialized by `memcpy` from `GetHeapamTableAmRoutine()`, with specific
callbacks replaced by TDE wrappers. All structural operations (VACUUM, HOT,
CLUSTER, truncate, scan state management) delegate to heapam **unchanged**.

### Write Path Contract

Every write callback MUST follow this sequence:
1. Materialize slot → `HeapTuple` (plaintext)
2. Call `tde_encrypt_heap_tuple()` → palloc'd encrypted `HeapTuple`
3. Call the heapam storage function (`heap_insert`, `heap_update`, etc.)
4. Copy physical TID back to the slot
5. `OPENSSL_cleanse` + `pfree` the plaintext copy

### TOAST deletion waits for the heap operation (PSQLE-193)

The pre-TOAST runs before `heap_update()`, because the new row needs its TOAST
pointers before it is encrypted; core toasts inside `heap_update()`, once the
row is known to be updatable.  So the pre-TOAST may insert chunks but never
delete any: `pg_vault_tde_toast_tuple()` clears `TOAST_NEEDS_DELETE_OLD` before
`toast_tuple_cleanup()`.  `pg_vault_tde_tuple_update()` then calls
`tde_toast_delete_unshared()`: on `TM_Ok` it deletes the old row's values the
new one no longer references; on any other result it kills the chunks this
call inserted (`heap_abort_speculative`), because READ COMMITTED may skip the
row or retry on a newer version that still points at the old ones.  The old
row is fetched with `SnapshotAny` — after an EvalPlanQual recheck `otid` is a
version the statement's snapshot does not see.  Regression:
`test/isolation/specs/toast_update_concurrency.spec`.

### Dropped columns keep their values until the row is rewritten (PSQLE-192)

Core nulls dropped columns whenever it rewrites a row (the executor's UPDATE
projection, `reform_and_rewrite_tuple()` on VACUUM FULL/CLUSTER) and deletes their
chunks with the rest.  Every TAM path must do the same: `copy_for_cluster` rewrites
them as NULL (`tde_without_dropped()`), the rotation's fetch-back sets them to NULL,
and `tde_toast_delete_unshared()` — used by UPDATE and DELETE — counts them.
`tde_tuple_has_external_desc()` alone skips them, on purpose: a VACUUM FULL up to
1.7.1 left their pointers dangling, and HEAP_HASEXTERNAL must not make core follow
them.  Regression: `tap/33_toast_lifecycle.t`, `ci-upgrade` Probe E.

### The index build scan is heapam's, on decrypted copies (PSQLE-198, PSQLE-201)

`tde_index_build_heap_scan` is `heapam_index_build_range_scan`
(`access/heap/heapam_handler.c`) with one change: each tuple heapam would index is
decrypted before the predicate and `FormIndexDatum`, and tde_btree keys are
encrypted.  Everything that decides which tuples reach the index — `SnapshotAny` +
`HeapTupleSatisfiesVacuum`, recently dead tuples, `ii_BrokenHotChain`, waits on
in-progress writers, the predicate with `reltuples` counted before it, HOT roots —
must stay heapam's; diff it against each new PostgreSQL major.  A recently dead
tuple that no longer decrypts is skipped with `ii_BrokenHotChain` set.  It runs
with the relation impersonating heapam (`heap_getnext()` checks rd_tableam).

### `copy_for_cluster` is heapam's, on decrypted copies (PSQLE-204)

`tde_cluster_copy` is `heapam_relation_copy_for_cluster` with each kept tuple
decrypted before it is sorted or written (the sort computes `OldIndex`'s keys from
it) and `tde_cluster_write_tuple` in place of `reform_and_rewrite_tuple`.  The
decrypted copy keeps the original header and is rewrite_heap_tuple()'s old tuple.
`tuplesort_getheaptuple(state, forward)` hands back the sort's own tuple: cleanse
it, never free it.  `CLUSTER` on a tde_btree index is refused.

### Every place heapam deletes TOAST itself needs a TAM counterpart (PSQLE-197)

heapam decides to delete a row's TOAST from the on-disk `HEAP_HASEXTERNAL`, which
encrypted tuples never carry: `heap_delete()`, `heap_update()`,
`heap_abort_speculative()`.  Each has a TAM wrapper that deletes from the decrypted
row — `tuple_delete`, `tuple_update`, `tuple_complete_speculative`.  A new heapam
entry point that frees a row needs one too.

### Catching errors from a TOAST read needs a subtransaction (PSQLE-196)

`verify_integrity()` catches per-row decrypt errors with a bare
`PG_TRY`/`FlushErrorState()`, which is safe only because `tde_decrypt_heap_tuple()`
holds no resource.  A TOAST fetch does (buffer pins, index scan, locks): catch its
errors only inside `BeginInternalSubTransaction()` /
`RollbackAndReleaseCurrentSubTransaction()`, as `tde_value_fetches()` does.

### Write Path PG_TRY Contract (v1.6 patch — fix #1)

All four write callbacks (`pg_vault_tde_tuple_insert`,
`pg_vault_tde_tuple_insert_speculative`, `pg_vault_tde_multi_insert`,
`pg_vault_tde_tuple_update`) MUST wrap the **entire** pre-TOAST → encrypt →
heap_insert pipeline inside a single `PG_TRY` block.

**Why**: prior to the patch, `PG_TRY` started AFTER
`heap_toast_insert_or_update()` and `tde_encrypt_heap_tuple()`. An error in
either of those two stages would:

1. Leak the swapped `reltoastrelid` (the relation cache stayed pointing at
   the wrong TOAST OID until the next relcache invalidation).
2. Leak `palloc`'d plaintext / pre-TOAST intermediates without
   `OPENSSL_cleanse`.

**Pattern** (canonical):

```c
Oid     saved_toastrelid    = rel->rd_rel->reltoastrelid;
bool    toastrelid_swapped  = false;
HeapTuple plain_inflight    = NULL;   /* pre-TOAST intermediate */
HeapTuple toasted_inflight  = NULL;   /* post-TOAST, pre-encrypt */
HeapTuple ct_tuple          = NULL;   /* post-encrypt */

PG_TRY();
{
    /* 1. swap toastrelid so heap_toast_insert_or_update writes into
     *    pg_toast_NNNNN under heap AM, not encrypted_heap. */
    rel->rd_rel->reltoastrelid = pg_vault_tde_get_toast_relid(rel);
    toastrelid_swapped = true;

    /* 2. pre-TOAST + encrypt + heap_insert — ALL inside PG_TRY */
    plain_inflight   = ExecCopySlotHeapTuple(slot);
    toasted_inflight = heap_toast_insert_or_update(rel, plain_inflight, ...);
    ct_tuple         = tde_encrypt_heap_tuple(rel, toasted_inflight);
    heap_insert(rel, ct_tuple, cid, options, bistate);

    /* 3. restore */
    rel->rd_rel->reltoastrelid = saved_toastrelid;
    toastrelid_swapped = false;
}
PG_CATCH();
{
    if (toastrelid_swapped)
        rel->rd_rel->reltoastrelid = saved_toastrelid;
    if (plain_inflight)    { OPENSSL_cleanse(plain_inflight->t_data, plain_inflight->t_len); pfree(plain_inflight); }
    if (toasted_inflight && toasted_inflight != plain_inflight)
                           { OPENSSL_cleanse(...); pfree(toasted_inflight); }
    if (ct_tuple)          { pfree(ct_tuple); }
    PG_RE_THROW();
}
PG_END_TRY();
```

For `multi_insert`, the equivalent loop allocates **arrays**
(`plain_inflight[]`, `toasted_inflight[]`) sized at `ntuples`, and the
`PG_CATCH` walks the partially-populated arrays freeing/cleansing the slots
that were already produced before the error.

**TOAST chunk rollback**: TOAST chunks already committed by
`heap_toast_insert_or_update()` before the error are rolled back by the
surrounding subtransaction — DO NOT attempt manual cleanup of TOAST chunks
in `PG_CATCH`.

Tests **81** (catalog registration), **83** (transactional rollback after
pre-TOAST + encrypt), and **84** (per-table DEK isolation across parent + TOAST)
exercise this contract.

### TOAST RELKIND_TOASTVALUE bypass (v1.0–v1.6) → Transparent Encryption (v1.7)

**v1.0–v1.6 behavior**: `pg_vault_tde.toast_encryption=on` made the auto-created
TOAST relation inherit the `encrypted_heap` AM, but PG's `toast_save_datum()`
writes chunks via `heap_insert(toastrel, …)` directly — bypassing the TAM
dispatch — so chunks landed **plaintext** on disk (documented v1 limitation).

**v1.7 behavior**: TOAST chunks are now encrypted at the TAM level.
- **Write path**: `pg_vault_tde_tuple_insert()` now detects `RELKIND_TOASTVALUE`
  and encrypts each chunk using the **parent table's DEK** via
  `tde_encrypt_heap_tuple(chunk, parent_relid)`.
- **Read path**: All 7 read callbacks automatically route TOAST relid to parent
  DEK lookup via `pg_vault_tde_kms_get_rel_dek()` (see Phase 1 KMS routing).
  No explicit `RELKIND_TOASTVALUE` bypass needed anymore; TOAST chunks are
  decrypted transparently just like parent table tuples.

**Architecture**:
```
TOAST chunk INSERT:     chunk → encrypt(parent_relid) → heap_insert
TOAST chunk SELECT:     heap_fetch → decrypt(TOAST_relid) 
                           ↓ (pg_vault_tde_kms_get_rel_dek routes TOAST_relid → parent_relid)
                        plaintext chunk
```

**TOAST table DEK assignment**:
- Each TOAST table **inherits the parent table's DEK** (no separate entry in catalog).
- Parent-child DEK linkage is implicit: TOAST relid is passed to
  `pg_vault_tde_kms_get_rel_dek()`, which calls `pg_vault_tde_get_parent_relid()`
  (Phase 1, KMS layer) to find the parent and loads the parent's wrapped DEK.

**Test coverage**: Test #53 validates v1.7 TOAST round-trip (10 KB payload →
external storage → multiple chunks → encrypt + decrypt → round-trip check).

### Read Path Contract

Every read callback that populates a `TupleTableSlot` with buffer-backed
data MUST call `pg_vault_tde_decode_slot()`.

---

## Critical Implementation Rules

### decode_slot Invariants

1. **Double-decode guard**: `if (bslot->buffer == InvalidBuffer) return;`
   — NEVER remove this check. After `ExecForceStoreHeapTuple`, buffer is
   released but `base.tuple` still points to the decoded data.

2. **TID source**: Read `bslot->base.tuple->t_self` BEFORE `ExecClearTuple`.
   Never use `ExecFetchSlotHeapTuple(slot, false, ...)` — it returns
   tupdata workspace with uninitialized `t_self`.

3. **tts_tid patch**: After `ExecForceStoreHeapTuple`, ALWAYS set
   `slot->tts_tid = saved_tid`. `ExecForceStoreHeapTuple` does NOT
   update `tts_tid` for `BufferHeapTupleTableSlot`.

### rd_tableam Identity-Check Workaround

Required for callbacks that call heapam internal functions with
`rel->rd_tableam` assertions:
- `index_fetch_tuple` → `heap_hot_search_buffer`
- `index_build_range_scan` → `heap_getnext`

Pattern:
```c
const TableAmRoutine *saved_am = rel->rd_tableam;
*(const TableAmRoutine **)(void *)&rel->rd_tableam = GetHeapamTableAmRoutine();
result = heapam_cb(rel, ...);
*(const TableAmRoutine **)(void *)&rel->rd_tableam = saved_am;
```

**ALWAYS restore before any error path.** `RelationData` is per-backend but
leaving it corrupted causes cascading failures in subsequent operations on
the same relcache entry.

**The swap does not survive a relcache rebuild.** An invalidation of the relation
processed while it is swapped — at any lock acquisition, and a TOAST read takes
several — rebuilds the open entry, and `rd_tableam` is the TAM again: every later
dispatch through it decrypts.  `verify_integrity()` counted every later tuple as
failed that way (PSQLE-207).  Where heapam's functions can be called directly
(`heap_beginscan()`, `heap_getnextslot()`, `heap_endscan()`), call them and leave
`rd_tableam` alone; keep the swap only around a single heapam call that processes
no invalidations.

### TOAST Override

```c
static Oid pg_vault_tde_toast_am(Relation rel) {
    return HEAP_TABLE_AM_OID;
}
```
Without this, TOAST tables inherit `encrypted_heap` and crash. V1 limitation:
large detoasted values are stored unencrypted.

---

## PG18-Specific API Notes

`scan_bitmap_next_tuple` signature changed in PG18:
```c
// PG18: bool(TableScanDesc, TupleTableSlot *, bool *, uint64 *, uint64 *)
```
Always verify against `src/include/access/tableam.h` before modifying.

---

## PG Version Compatibility Checklist (TAM)

When adding support for PostgreSQL N+1, audit every TAM callback:

1. **Diff `tableam.h`** between PG N and PG N+1
2. Check each callback signature in the `TableAmRoutine` struct
3. Add `#if PG_VERSION_NUM >= (N+1)*10000` guards where needed
4. Run `make ci-regress` against PG N+1

### Known Version Differences (TAM)

| Callback / Function | PG 17 | PG 18 | Guard |
|---------------------|-------|-------|-------|
| `scan_bitmap_next_tuple` | 3 args | 5 args (+lossy, exact) | `PG_VERSION_NUM >= 180000` |
| `heap_beginscan` flags in `relation_copy_for_cluster` | `SO_ALLOW_STRAT\|SO_ALLOW_SYNC` sufficient | Must also include `SO_TYPE_SEQSCAN`; `heapgettup` calls `heap_fetch_next_buffer` which asserts `scan->rs_read_stream != NULL`, and the read stream is only initialized when `SO_TYPE_SEQSCAN` is set | `PG_VERSION_NUM >= 180000` |

**Add rows** here when PG 19+ introduces new TAM changes.

---

## Testing Checklist for New TAM Callbacks

When adding a new override:
- [ ] Add a regression test in `sql/regression_test.sql`
- [ ] Test creates `USING encrypted_heap` table
- [ ] Test inserts known data and verifies round-trip
- [ ] Test forces the specific scan path (`SET enable_xxx = off/on`)
- [ ] For rotation paths: verify old-DEK rows are rejected
- [ ] For index paths: verify `rd_tableam` workaround is applied if needed

---

## Forbidden Actions

- Do NOT call `tde_gcm_encrypt` / `tde_gcm_decrypt` directly — use
  `tde_encrypt_heap_tuple` / `tde_decrypt_heap_tuple` wrappers
- Do NOT include `openssl/*.h` — the crypto layer abstracts OpenSSL
- Do NOT add catalog lookups or SPI calls on the hot decrypt path
- Do NOT `Assert(user_len > 0)` — all-NULL rows have zero user data length

---

## Error Path Mapping

Every TAM callback has specific failure modes. This table maps each callback
to its expected error conditions and the correct `ereport` level:

| Callback | Failure Mode | ereport Level | Error Message |
|----------|-------------|---------------|---------------|
| `scan_getnextslot` | GCM tag mismatch | ERROR | "GCM authentication failed: tuple at (%u,%u) may be tampered or encrypted with a different DEK" |
| `scan_getnextslot` | DEK not set | ERROR | "pg_vault_tde: no DEK available |
| `tuple_insert` | encrypt returns NULL | ERROR | "pg_vault_tde: encryption failed for tuple" |
| `tuple_update` | old tuple GCM mismatch | ERROR | "GCM authentication failed on UPDATE source tuple" |
| `index_fetch_tuple` | rd_tableam restore failed | PANIC | "pg_vault_tde: failed to restore rd_tableam — relation cache corrupted" |
| `multi_insert` | any single tuple encrypt fail | ERROR | "pg_vault_tde: bulk insert encryption failed at tuple %d of %d" |
| `tuple_insert*` / `tuple_update` / `multi_insert` | pre-TOAST or encrypt fail mid-pipeline | ERROR (re-thrown via PG_RE_THROW) | Original heapam/encrypt errmsg; `PG_CATCH` restores `reltoastrelid` and cleanses plaintext intermediates (v1.6 patch — fix #1) |

## Callback × Test Coverage Matrix

| Callback | Test # | Forced Via | Verified |
|----------|--------|-----------|----------|
| `scan_getnextslot` | 12, 14 | Default SeqScan | ✅ |
| `tuple_insert` | 12 | INSERT | ✅ |
| `tuple_update` | 14 | UPDATE | ✅ |
| `tuple_delete` | 15 | DELETE | ✅ |
| `index_fetch_tuple` | 17 | `SET enable_seqscan = off` | ✅ |
| `multi_insert` | 18 | `COPY FROM` | ✅ |
| `scan_bitmap_next_tuple` | 23 | `SET enable_seqscan = off; SET enable_indexscan = off` | ✅ |
| `scan_analyze_next_tuple` | 21 | `ANALYZE` | ✅ |
| `scan_sample_next_tuple` | 24 | `TABLESAMPLE` | ✅ |
| `tuple_fetch_row_version` | — | `SELECT ... WHERE ctid = '(0,1)'` | via UPDATE recheck |
| `tuple_lock` | 22 | `SELECT FOR UPDATE` | ✅ |
| `tuple_insert` PG_TRY widening | 81, 82, 83 | DDL hook + 64 KB compressible + ROLLBACK | ✅ (v1.6 patch — fix #1) |
| `multi_insert` PG_TRY widening | 18, 84 | `COPY FROM` + per-table DEK isolation | ✅ (v1.6 patch — fix #1) |
| `tuple_update` PG_TRY widening | 14, 83 | UPDATE + transactional rollback | ✅ (v1.6 patch — fix #1) |

**Action item for @QA**: All TAM callbacks now have test coverage (tests 1-84).
