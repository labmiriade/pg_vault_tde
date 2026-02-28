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

### Read Path Contract

Every read callback that populates a `TupleTableSlot` with buffer-backed
data MUST call `pg_vault_tde_decode_slot()`. The 7 callbacks that require
this are listed in the [copilot-instructions.md](/.github/copilot-instructions.md)
Section 3 table.

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
4. Update the **Version-Specific API Differences** table in
   `copilot-instructions.md` § 0.5
5. Run `make ci-regress` against PG N+1

### Known Version Differences (TAM)

| Callback | PG 17 | PG 18 | Guard |
|----------|-------|-------|-------|
| `scan_bitmap_next_tuple` | 3 args | 5 args (+lossy, exact) | `PG_VERSION_NUM >= 180000` |

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
| `scan_getnextslot` | DEK not set | ERROR | "pg_vault_tde: no DEK available — call pg_vault_tde_set_test_dek() or configure Vault" |
| `tuple_insert` | encrypt returns NULL | ERROR | "pg_vault_tde: encryption failed for tuple" |
| `tuple_update` | old tuple GCM mismatch | ERROR | "GCM authentication failed on UPDATE source tuple" |
| `index_fetch_tuple` | rd_tableam restore failed | PANIC | "pg_vault_tde: failed to restore rd_tableam — relation cache corrupted" |
| `multi_insert` | any single tuple encrypt fail | ERROR | "pg_vault_tde: bulk insert encryption failed at tuple %d of %d" |

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

**Action item for @QA**: All TAM callbacks now have test coverage (tests 1-24).
