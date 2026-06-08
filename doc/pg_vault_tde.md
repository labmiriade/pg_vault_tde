# pg_vault_tde Technical Reference

**Version**: 1.6  
**PostgreSQL**: 17.x, 18.x (19.x planned)  
**License**: BSD (PostgreSQL License)  
**Copyright**: © 2026 Miriade S.r.l.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Table Access Method (TAM)](#table-access-method)
3. [Crypto Layer](#crypto-layer)
4. [KMS and Key Caching](#kms-and-key-caching)
5. [Index Access Method (IAM)](#index-access-method)
6. [Known Limitations](#known-limitations)
7. [Security Considerations](#security-considerations)
8. [Wire Format Reference](#wire-format-reference)
9. [SQL API Reference](#sql-api-reference)
10. [Extension Initialization](#extension-initialization)
11. [Testing Strategy](#testing-strategy)
12. [Packaging](#packaging)
13. [Roadmap](#roadmap)
14. [Contributing](#contributing)

---

## Architecture

pg_vault_tde is a PostgreSQL extension that provides Transparent Data
Encryption at the Table Access Method layer. It operates entirely within
the extension API; zero modifications to PostgreSQL core are required.

### PostgreSQL Version Compatibility

| PG Major | Status | Notes |
|----------|--------|-------|
| 17 | ✅ Supported | Baseline API set |
| 18 | ✅ Supported | `scan_bitmap_next_tuple` signature change — guarded with `PG_VERSION_NUM` |
| 19 | 🔜 Planned | Infrastructure ready; audit at release |

### Version-Specific API Differences

| API / Struct | PG 17 | PG 18 | Guard Macro |
|-------------|-------|-------|-------------|
| `scan_bitmap_next_tuple` | `(scan, slot, recheck)` | `(scan, slot, recheck, lossy, exact)` | `PG_VERSION_NUM >= 180000` |
| `shmem_request_hook` | Available | Available | *(none needed)* |
| `GetHeapamTableAmRoutine()` | Returns `const *` | Returns `const *` | *(none needed)* |

### Design Goals

| Goal | Achieved | Notes |
|---|---|---|
| Plug-and-play | ✅ | `shared_preload_libraries` + `CREATE EXTENSION` only |
| Zero core patches | ✅ | Pure extension API (`tableam`, `indexam`) |
| AES-256-GCM per-tuple | ✅ | Authenticated encryption; integrity verified on read |
| Hardware acceleration | ✅ | OpenSSL 3.x EVP dispatch → AES-NI / ARM Crypto |
| Key rotation | ✅ | Lazy generation-epoch detection; no scan needed |
| MVCC compatibility | ✅ | HeapTupleHeader stays plaintext |
| pg_dump / pg_restore | ✅ | Decrypts transparently at TAM scan layer |
| Page checksums | ✅ | Checksums cover encrypted bytes |

### Component Map

```
PostgreSQL Core
 └── Extension API
      ├── TAM: encrypted_heap          src/tam/pg_vault_tde_tam.c
      │    ├─ Write path (encrypt)     tde_encrypt_heap_tuple()
      │    └─ Read paths (decrypt)     pg_vault_tde_decode_slot()
      ├── IAM: tde_btree               src/iam/pg_vault_tde_iam.c
      │    └─ AES-256-SIV key encrypt  tde_iam_encrypt_key()
      ├── Crypto                       src/crypto/pg_vault_tde_crypto.c
      │    ├─ tde_gcm_encrypt()        AES-256-GCM via OpenSSL 3.x EVP
      │    └─ tde_gcm_decrypt()        Authenticated decryption
      ├── KMS                          src/kms/pg_vault_tde_kms.c
      │    ├─ Shared-memory DEK cache  pg_vault_tde_dek_cache (shmem)
      │    ├─ Per-backend local cache  pg_vault_tde_local_dek (TopMemCtx)
      │    └─ Rotation epoch counter   generation (uint64)
      ├── Backup                       src/backup/pg_vault_tde_backup.c
      └── Entry point                  src/pg_vault_tde.c (_PG_init)
```

### Key Lifecycle

```
Vault / OpenBao (KEK owner)
        │
        │  HTTP(S) via libcurl (async, non-blocking)
        ▼
pg_vault_tde_kms_request_async()       [src/kms/pg_vault_tde_kms.c]
        │
        │  Writes DEK (32 bytes) under LW_EXCLUSIVE
        ▼
pg_vault_tde_dek_cache (shmem)         [LWLockPair, generation counter]
        │
        │  Copied under LW_SHARED to per-backend
        ▼
pg_vault_tde_local_dek (TopMemCtx)     [OPENSSL_cleanse on rotation]
        │
        │  Passed to EVP encrypt/decrypt context
        ▼
tde_gcm_encrypt() / tde_gcm_decrypt()  [src/crypto/pg_vault_tde_crypto.c]
        │
        ▼
Disk: [HeapTupleHeader | IV(12) | Ciphertext | GCM-TAG(16)]
```

### Shared Memory Layout

```c
typedef struct TdeKmsSharedState {
    LWLock      lock;               /* protects dek + generation */
    uint64      generation;         /* bumped on each rotate_key() */
    bool        dek_valid;          /* false until first key injection */
    char        dek[TDE_DEK_LEN];   /* 32-byte AES-256 key */
} TdeKmsSharedState;
```

- `TDE_DEK_LEN` is defined **only** in `src/include/pg_vault_tde_kms.h`.
- The LWLock is embedded by VALUE (not pointer) — safe across fork.
- The LWLock tranche ID is allocated via `LWLockNewTrancheId()` inside
  `shmem_startup_hook` — that is the earliest safe call point in PG18
  because `WaitEventCustomCounterLock` (used internally by
  `LWLockNewTrancheId`) is a shared-memory spinlock that does not exist
  until after the segment is mapped.

---

## Table Access Method

### Design Pattern: Mutable Copy of heapam

```c
static TableAmRoutine tde_methods;  /* zero-initialised at load time */

void pg_vault_tde_tam_init(void) {
    memcpy(&tde_methods, GetHeapamTableAmRoutine(), sizeof(TableAmRoutine));
    /* save originals, then install TDE wrappers */
}
```

All structural operations (VACUUM, HOT, CLUSTER, index build, truncate, scan
state management) delegate to heapam unchanged. Only the four write paths,
seven read paths, and one rewrite path are overridden.

### Overridden Callbacks

#### Write Paths (encrypt before storing)

| Callback | Purpose |
|---|---|
| `tuple_insert` | Single-row INSERT |
| `tuple_insert_speculative` | Speculative INSERT (ON CONFLICT) |
| `multi_insert` | COPY FROM / bulk INSERT |
| `tuple_update` | UPDATE |

All write paths follow the same pattern:
1. Materialize the slot into a `HeapTuple` (plaintext)
2. Call `tde_encrypt_heap_tuple()` → returns palloc'd encrypted `HeapTuple`
3. Call the heapam storage function (`heap_insert`, `heap_update`)
4. Copy the physical TID back to the slot
5. `OPENSSL_cleanse` + `pfree` the plaintext copy

#### Read Paths (decrypt after fetching)

All read paths that cause heapam to fill a `TupleTableSlot` with a
buffer-backed `HeapTuple` MUST call `pg_vault_tde_decode_slot()`.

| Callback | Scan Type | Status |
|---|---|---|
| `scan_getnextslot` | SeqScan, TidRangeScan | ✅ Override |
| `index_fetch_tuple` | Index Scan, Index Only Scan | ✅ Override |
| `scan_bitmap_next_tuple` | BitmapHeapScan | ✅ Override |
| `scan_analyze_next_tuple` | ANALYZE | ✅ Override |
| `scan_sample_next_tuple` | TABLESAMPLE | ✅ Override |
| `tuple_fetch_row_version` | TidScan, UPDATE recheck | ✅ Override |
| `tuple_lock` | SELECT FOR UPDATE/SHARE | ✅ Override |

#### Rewrite Paths (decrypt → process → re-encrypt)

| Callback | Trigger | Notes |
|---|---|---|
| `relation_copy_for_cluster` | `VACUUM FULL`, `CLUSTER` | Reads each tuple via `heap_getnext` (with `rd_tableam` impersonation), decrypts, re-encrypts into the new heap via `rewrite_heap_tuple`. Clears `HEAP_HASEXTERNAL` on the encrypted copy before writing; `tde_tuple_has_external_slow` (per-attribute varlena scan) is used on subsequent DELETE to locate TOAST chunks regardless of the infomask flag. |

### pg_vault_tde_decode_slot

This function is the core of the read path. It:

1. Casts the slot to `BufferHeapTupleTableSlot` (known buffer-backed after heapam)
2. **Guards against double-decode**: checks `bslot->buffer == InvalidBuffer`
3. Saves `bslot->base.tuple->t_self` (physical TID from buffer page header)
4. Calls `heap_copytuple(bslot->base.tuple)` while buffer pin is held
5. Calls `ExecClearTuple(slot)` to release the buffer pin
6. Calls `tde_decrypt_heap_tuple(enc_copy)` (verifies GCM tag via OpenSSL)
7. Stamps `plain->t_self = saved_tid`, `plain->t_tableOid = saved_tableoid`
8. Calls `ExecForceStoreHeapTuple(plain, slot, true)`
9. **Manually sets `slot->tts_tid = saved_tid`** — `ExecForceStoreHeapTuple`
   does NOT restore `tts_tid` for virtual/minimal slots; it must be set explicitly

```c
static void pg_vault_tde_decode_slot(TupleTableSlot *slot)
{
    BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;

    /*
     * Guard against double-decode: after ExecForceStoreHeapTuple the buffer
     * is released (buffer == InvalidBuffer) but base.tuple is still set.
     * Re-entering here would try to decrypt already-plain data.
     */
    if (bslot->buffer == InvalidBuffer) return;

    /*
     * Read TID from the buffer-backed pointer directly, NOT from
     * ExecFetchSlotHeapTuple(slot, false, ...) which returns the tupdata
     * workspace with an uninitialized t_self.
     */
    ItemPointerData saved_tid;
    ItemPointerCopy(&bslot->base.tuple->t_self, &saved_tid);

    /* Copy encrypted data while the buffer pin is still held. */
    HeapTuple enc_copy = heap_copytuple(bslot->base.tuple);
    ExecClearTuple(slot);   /* releases buffer pin */

    HeapTuple plain = tde_decrypt_heap_tuple(enc_copy);
    pfree(enc_copy);

    plain->t_self    = saved_tid;
    plain->t_tableOid = slot->tts_tableOid;

    ExecForceStoreHeapTuple(plain, slot, true);
    slot->tts_tid = saved_tid;  /* ExecForceStoreHeapTuple does not set this */
}
```

### rd_tableam Identity-Check Workaround

Several heapam internal functions protect themselves with:
```c
if (rel->rd_tableam != GetHeapamTableAmRoutine())
    ereport(ERROR, "only heap AM is supported");
```

Since our `&tde_methods` lives at a different address than heapam's static
struct, these checks fail when called on our tables. Two callbacks require
the workaround:

1. **`index_fetch_tuple`** — calls `heap_hot_search_buffer` on every index lookup
2. **`index_build_range_scan`** — calls `heap_getnext` internally during `CREATE INDEX`

**Fix pattern** (safe — `RelationData` is per-backend):
```c
const TableAmRoutine **rdam =
    (const TableAmRoutine **)(void *)&rel->rd_tableam;
const TableAmRoutine *saved_am = *rdam;
*rdam = GetHeapamTableAmRoutine();   /* impersonate heapam */
result = heapam_original_cb(rel, ...);
*rdam = saved_am;                    /* restore BEFORE any error path */
/* Then decrypt slot contents */
```

`RelationData` is per-backend (local relcache copy). The swap window is a
single function call. No signal/interrupt can preempt between the swap and
restore in a single-threaded backend.

### TOAST Table Override

```c
static Oid pg_vault_tde_toast_am(Relation rel)
{
    (void) rel;
    if (pg_vault_tde_toast_encryption)
    {
        Oid encheap_oid = get_table_am_oid("encrypted_heap", true);
        if (OidIsValid(encheap_oid))
            return encheap_oid;
    }
    return HEAP_TABLE_AM_OID;
}
```

When `pg_vault_tde.toast_encryption = on` (the default), TOAST tables are
created with the `encrypted_heap` AM so that every TOAST chunk is encrypted
individually using the parent relation's DEK.  On PG 18 the `heap_getnext`
identity assertion inside the TOAST index build would reject `encrypted_heap`;
the `rd_tableam` impersonation workaround is applied during
`index_build_range_scan` to satisfy this assertion.

When `pg_vault_tde.toast_encryption = off`, TOAST tables fall back to standard
`heap` AM, leaving large column values stored unencrypted — a configuration
intentionally supported for performance-sensitive workloads where only the
tuple body (not TOAST chunks) needs confidentiality protection.

### PG18-Specific API Notes

#### scan_bitmap_next_tuple

The signature changed in PG18:

```c
/* PG ≤ 17 */
bool (*scan_bitmap_next_tuple)(TableScanDesc, TBMIterateResult *,
                               TupleTableSlot *);
/* PG 18 */
bool (*scan_bitmap_next_tuple)(TableScanDesc, TupleTableSlot *,
                               bool *, uint64 *, uint64 *);
```

Always verify against `src/include/access/tableam.h` before implementing
or modifying this callback.

---

## Crypto Layer

### Algorithm

- **Encryption**: AES-256-GCM via OpenSSL 3.x `EVP_EncryptInit_ex2`
- **IV generation**: `pg_strong_random()` (PostgreSQL's `/dev/urandom` wrapper)
  — NOT `RAND_bytes()` because PostgreSQL processes can fork at any time;
  OpenSSL PRNG state is not fork-safe in all configurations.
- **Hardware acceleration**: OpenSSL 3.x EVP dispatch automatically selects
  the hardware provider (AES-NI on x86_64; ARM Crypto Extensions on aarch64).
- **Authentication**: 128-bit GCM tag appended to every encrypted region.
  Any bit-flip in ciphertext, IV, or associated data raises an `ERROR`
  (not a silent wrong result).

### Wire Format per Encrypted Region

**Version 3** (all new tuples from pg_vault_tde v1.5 — default):

```
+-------+----------+----------------------------+----------+
| VER   | GEN      | CIPHERTEXT                 | GCM TAG  |
| 1 byte| 8 bytes  | N bytes (= plaintext len)  | 16 bytes |
+-------+----------+----------------------------+----------+
```

Total overhead: `TDE_V2_OVERHEAD = 37` bytes
(`TDE_V3_VERSION_BYTE=0x03` + `TDE_V2_GEN_LEN=8` + `TDE_IV_LEN=12` + `TDE_TAG_LEN=16`).

v3 passes `[database_oid(4) | relfilenode(4) | generation(8)]` as GCM Additional
Authenticated Data (AAD) — zero wire overhead; prevents cross-table ciphertext smuggling.

**Version 2** (pg_vault_tde v1.4): `VER = 0x02`; no AAD binding; fully readable by v1.5.

**Version 1** (legacy, written by pg_vault_tde < 1.4):

```
+------------+----------------------------+----------+
|  IV        |  CIPHERTEXT                |  GCM TAG |
|  12 bytes  |  N bytes (= plaintext len) |  16 bytes|
+------------+----------------------------+----------+
```

Total overhead: `TDE_GCM_OVERHEAD = 28` bytes per stored tuple.

The decrypt path auto-detects v1/v2 from the first byte: if byte 0 is
`0x02` AND the total length is ≥ `TDE_V2_OVERHEAD`, the v2 path is taken.
Otherwise the v1 path is used. A false-positive retry handles the 1/256
probability edge case where a v1 IV happens to start with `0x02`.

When `user_len == 0` (all-NULL tuple, or tuple with only system columns),
`tde_gcm_encrypt()` produces a 28-byte ciphertext block (IV + empty payload
+ GCM tag). This exercises the GCM tag path on zero data. The decrypt path
handles this symmetrically. Test 16 covers this edge case.

### Memory Security

- DEK copies in per-backend memory are `OPENSSL_cleanse`d before `pfree`.
- Plaintext `HeapTuple` intermediates are `OPENSSL_cleanse`d after encryption.
- Per-backend EVP contexts are freed via `on_proc_exit()` callbacks
  (`tde_iam_siv_ctx_cleanup` for AES-SIV; analogous cleanup for GCM contexts).
- Shared-memory DEK is `OPENSSL_cleanse`d during rotation before the new key
  is written.

---

## Performance

### Per-Backend EVP Context Pool

Creating and destroying an `EVP_CIPHER_CTX` on every tuple (as a naive
implementation would do) costs 2 heap allocations per operation. Instead,
pg_vault_tde maintains a **per-backend pool** of pre-allocated contexts:

```c
static EVP_CIPHER_CTX *tde_gcm_enc_ctx = NULL;  /* lazily initialised */
static EVP_CIPHER_CTX *tde_gcm_dec_ctx = NULL;
```

On each encrypt/decrypt call, the context is **reset** with
`EVP_CIPHER_CTX_reset()` (cheap — reuses the already-allocated struct)
instead of free + alloc. Contexts are freed in the `on_proc_exit()` callback
`tde_backend_cleanup()`. The same pattern is applied to the IAM SIV contexts
(`tde_iam_siv_enc_ctx`, `tde_iam_siv_dec_ctx`).

### IV Batch Generation

`pg_strong_random()` is a syscall to `/dev/urandom` or `getrandom(2)`. A
non-batched implementation would pay one syscall per encrypted tuple. Instead,
pg_vault_tde batches 256 IVs per `pg_strong_random()` call:

```c
#define TDE_IV_BATCH_SIZE 256
static unsigned char iv_batch[TDE_IV_BATCH_SIZE * TDE_IV_LEN];
static int           iv_batch_pos = TDE_IV_BATCH_SIZE;  /* start empty */

static void tde_next_iv(unsigned char *iv_out)
{
    if (iv_batch_pos >= TDE_IV_BATCH_SIZE)
    {
        pg_strong_random(iv_batch, sizeof(iv_batch));
        iv_batch_pos = 0;
    }
    memcpy(iv_out, iv_batch + iv_batch_pos * TDE_IV_LEN, TDE_IV_LEN);
    iv_batch_pos++;
}
```

This amortises the syscall cost across 256 tuples.

### Benchmark

Run the included benchmark against a live container:

```bash
bash bench_tde.sh 100000
```

The script runs INSERT, SELECT, UPDATE, index scan, and TABLESAMPLE workloads
on `plain_heap` vs `encrypted_heap`, and prints a comparison table with
overhead percentages. Use `pg_vault_tde.enabled = off` to isolate pure TAM
overhead (no crypto) from actual encryption cost.

```
┌───────────────────────────────────────────────────┐
│  Shared Memory  (pg_vault_tde_dek_cache)           │
│  ─────────────────────────────────────────────────│
│  LWLock (embedded by value)                        │
│  generation: uint64                                │
│  dek_valid: bool                                   │
│  dek[32]: char  (AES-256 raw key)                  │
└───────────────────────────────────────────────────┘
               ▲ LW_SHARED copy on miss
┌───────────────────────────────────────────────────┐
│  Per-backend  (TopMemoryContext)                   │
│  ─────────────────────────────────────────────────│
│  local_generation: uint64                          │
│  local_dek[32]: char                               │
└───────────────────────────────────────────────────┘
```

1. On first encrypt/decrypt, backend copies DEK from shmem under `LW_SHARED`.
2. On subsequent calls, backend compares `local_generation` with shmem
   `generation`. If equal, uses local copy (no lock needed after first load).
3. On mismatch, acquires `LW_SHARED`, refreshes local copy, updates
   `local_generation`.

### Generation-Epoch Rotation

`pg_vault_tde_rotate_key()`:
1. Acquires `LW_EXCLUSIVE` on the shmem lock.
2. `OPENSSL_cleanse`s `dek[32]`.
3. Increments `generation`.
4. Sets `dek_valid = false`.
5. Releases lock.

Each backend detects the mismatch lazily on the next encrypt/decrypt call.
Old-generation rows encrypted with DEK-A are permanently unreadable after the
key is wiped. A re-encryption utility is on the roadmap.

- **Bounded staleness**: At most one LWLock pair per encrypt/decrypt call.
- **No signals**: Generation mismatch is detected lazily; no SIGUSR1/SIGHUP needed.
- **Fork safety**: fork() after `shmem_startup_hook` is safe because the shmem
  segment is mapped by all backends independently.

---

## Index Access Method (IAM)

### tde_btree

The `tde_btree` access method provides a B-Tree index with deterministic
(equality-preserving) key encryption using **AES-256-SIV**
(Synthetic IV — RFC 5297).

| Property | Value |
|---|---|
| Algorithm | AES-256-SIV (deterministic authenticated encryption) |
| Key length | 64 bytes (two 32-byte AES keys) |
| Equality | Preserved (same plaintext → same ciphertext under same DEK) |
| Ordering | **Not preserved** — range scans return empty results |
| Use case | Equality predicates only (`=`, `IN`, `ON CONFLICT`) |
| Column support | `bytea` columns only in v1.4; other types require `CAST(col AS bytea)` |

AES-SIV is chosen over AES-GCM for index entries because:
- It produces a deterministic ciphertext (required for B-Tree comparisons).
- It provides authentication (misuse-resistant — no IV to manage).
- It prevents key reuse attacks that would be possible with AES-ECB.

### Implementation

The implementation uses the OpenSSL 3.x **provider API**:

```c
EVP_CIPHER *siv_cipher = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
```

The DEK (32 bytes) is expanded to 64 bytes for AES-SIV's double-key
requirement via PBKDF2-SHA256:

```c
PKCS5_PBKDF2_HMAC(dek, TDE_DEK_LEN,
                  (unsigned char *)"tde-siv", 7,
                  1,        /* 1 iteration — determinism, not stretching */
                  EVP_sha256(), 64, siv_key);
```

### ambuild (sorted bulk-load)

The `ambuild` callback uses btree's internal sort layer
(`_bt_spoolinit` / `_bt_spool` / `_bt_leafbuild`) via forward-declared
prototypes in `pg_vault_tde_iam.c`. These symbols are available at
runtime from the postgres binary on all ELF platforms, even though
they are not declared in the installed extension dev headers.

For each live heap tuple, `tde_build_callback()` encrypts each non-null
bytea column datum via `tde_encrypt_bytea_datum()`, then spools it into
the btree sort buffer. After the heap scan, `_bt_leafbuild()` writes all
encrypted entries to the index pages in sorted order.

### amrescan (query-time key encryption)

`pg_vault_tde_amrescan()` encrypts equality scan keys
(`sk_strategy == BTEqualStrategyNumber`) with AES-SIV before passing them
to the underlying btree scan. Range keys
(`sk_strategy != 3`) are passed through unchanged — they will produce
empty results because AES-SIV does not preserve ordering.

### Operator Class

```sql
-- Registered automatically by CREATE EXTENSION pg_vault_tde
CREATE OPERATOR CLASS tde_bytea_ops DEFAULT FOR TYPE bytea USING tde_btree AS
    OPERATOR 1 <  (bytea, bytea),
    OPERATOR 2 <= (bytea, bytea),
    OPERATOR 3 =  (bytea, bytea),
    OPERATOR 4 >= (bytea, bytea),
    OPERATOR 5 >  (bytea, bytea),
    FUNCTION 1 byteacmp(bytea, bytea);
```

### IAM Limitations (v1.6)

`tde_btree` now supports native operator classes for `text`, `int4`, `int8`, `uuid`,
`numeric`, `date`, `timestamptz` (added v1.5). **Caveat**: varlena types (`text`,
`bytea`, `numeric`) have their index key encrypted with AES-256-SIV. Fixed-size
pass-by-value types (`int4`, `uuid`, `date`, `timestamptz`) store the **index key in
plaintext** — the heap tuple remains fully encrypted but the btree page entry is not.
This requires a custom btree page format to fix; planned for v1.7.

Range scans on `tde_btree` columns return empty results by design (ordering not
preserved by AES-SIV, regardless of type).

---

## Known Limitations

### Current Limitations (v1.7)

| # | Limitation | Fix Version |
|---|-----------|-------------|
| 1 | **TOAST chunk-level storage encryption** — ✅ **Resolved in v1.6**: large values round-trip fully encrypted via `pg_vault_tde_toast_am` returning `encrypted_heap` AM. Disable with `pg_vault_tde.toast_encryption = off` for legacy behaviour. | v1.6 ✅ |
| 2 | **tde_btree fixed-size types plaintext index keys** — `int4`, `int8`, `uuid`, `date`, `timestamptz` btree index entries are plaintext (heap fully encrypted); only varlena types have encrypted index keys | v1.7 |
| 3 | **Logical replication TOAST gap** — tables with externally-TOAST'd columns not supported for logical decoding | v1.7 |
| 4 | **WAL unencrypted** — requires `XLogInsert()` hook unavailable in extension API | Permanently deferred |
| 5 | **All-or-nothing table encryption** — no per-column granularity | v1.8 |
| 6 | **Range scans on tde_btree** — `WHERE col > x` returns empty (AES-SIV not order-preserving) | By design, permanent |
| 7 | **BRIN on encrypted columns** — min/max of AES-SIV ciphertexts is meaningless | By design, permanent |

### Historical Limitations (v1.0) — Many Resolved Since

1. **TOAST encryption** (ticket #1) — ✅ **Resolved in 6**  
   `pg_vault_tde_toast_am` now returns `encrypted_heap` AM when
   `pg_vault_tde.toast_encryption = on` (default). Every TOAST chunk is
   encrypted individually using the parent relation's DEK.  The v1.0 behaviour
   (forced `HEAP_TABLE_AM_OID`) is available via `toast_encryption = off`.

2. **Row re-encryption after rotation** (ticket #2)  
   Existing rows encrypted with DEK generation N become **permanently
   unreadable** after rotating to generation N+1 (the old key is wiped).
   The `pg_vault_tde_reencrypt_table()` cursor-based utility is planned
   but not yet implemented.

3. **Vault HTTP connector** (ticket #3)  
   The libcurl-based async KMS integration is scaffolded in
   `src/kms/pg_vault_tde_kms.c` (`pg_vault_tde_kms_request_async()`).
   Production use currently requires injecting the DEK via
   `pg_vault_tde_set_test_dek()` (development only) or directly via
   `pg_vault_tde_kms_set_dek()` in C.

4. **multi_insert / COPY throughput** (ticket #4)
   The `multi_insert` callback encrypts per-slot and calls `heap_insert`
   in a loop, forfeiting WAL-batching optimizations. This degrades COPY
   workloads by roughly the single-insert overhead multiplied by batch size.
   Batch-encrypted `heap_multi_insert` is targeted for v1.1.

5. **Logical replication** (ticket #5)  
   A `pgoutput`-compatible decoding plugin that decrypts tuples before
   publishing to subscribers is required for logical replication
   compatibility. The WAL sender runs in a separate code path from the
   query executor.

6. **IAM range scans** (ticket #6)  
   `WHERE col > 'x'` on a column with a `tde_btree` index always returns
   empty: AES-SIV does not preserve ordering. Users requiring range
   predicates on encrypted columns must use sequential scans.

---

## Security Considerations

### Threat Model

pg_vault_tde encrypts **data at rest** (relation files, TOAST files, backup
media, standby base backups). It does **not** protect:

- In-memory tuple data during query execution.
- WAL structural metadata (tuple payloads in WAL are ciphertext; LSN,
  block numbers, and relation OIDs are plaintext).
- `pg_statistic` rows written by ANALYZE (see below).
- Network connections between backends and clients (use `ssl = on` in
  `pg_hba.conf`).

### Planner Statistics

`pg_statistic` is populated by ANALYZE after decryption through the TAM
read path. Statistics are stored **as plaintext** in the system catalog.
Protect via:
```sql
REVOKE SELECT ON TABLE pg_statistic FROM PUBLIC;
```

### WAL

Tuple payload bytes in WAL are the encrypted bytes written to disk —
a WAL stream viewer sees ciphertext in DATA positions. Structural
metadata (LSN, block numbers, relation OID, MVCC fields) is plaintext.

### Superuser Bypass

A PostgreSQL superuser executing SQL sees plaintext (decrypted through
the TAM layer). A superuser with OS-level file access sees encrypted content.
Row-level security and column-level privileges complement TDE for
access control but do not replace it.

### Key Material Lifecycle

| Event | Action |
|---|---|
| Backend start | Local DEK copy in `TopMemoryContext` |
| Query end | DEK remains in `TopMemoryContext` (not wiped per-query) |
| `rotate_key()` | Shmem DEK `OPENSSL_cleanse`d; generation incremented |
| Backend exit | `on_proc_exit` hook calls `OPENSSL_cleanse` on local copy |
| OS crash | Shmem lost; DEK must be re-injected from Vault on restart |

---

## Wire Format Reference

### Per-Page Layout

```
┌────────────────────────────────────────────────────────────────────┐
│  PageHeaderData (24 bytes, plain)                                  │
│  ItemId array (4 bytes per slot, plain)                            │
├────────────────────────────────────────────────────────────────────┤
│  Free space                                                        │
├────────────────────────────────────────────────────────────────────┤
│  ... tuples grow downward from end of page ...                     │
│                                                                     │
│  ┌─────────────────────────────┬──────────────────────────────┐   │
│  │  HeapTupleHeaderData        │  IV(12) │ Ciphertext │ TAG(16)│   │
│  │  (t_hoff bytes, PLAINTEXT)  │      (user data, ENCRYPTED)  │   │
│  └─────────────────────────────┴──────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
```

### Constants

| Constant | Value | Defined in |
|---|---|---|
| `TDE_IV_LEN` | 12 | `pg_vault_tde_crypto.h` |
| `TDE_TAG_LEN` | 16 | `pg_vault_tde_crypto.h` |
| `TDE_GCM_OVERHEAD` | 28 | `pg_vault_tde_crypto.h` (v1 wire format) |
| `TDE_V2_VERSION_BYTE` | `0x02` | `pg_vault_tde_crypto.h` |
| `TDE_V2_GEN_LEN` | 8 | `pg_vault_tde_crypto.h` |
| `TDE_V2_OVERHEAD` | 37 | `pg_vault_tde_crypto.h` (v2 wire format) |
| `TDE_DEK_LEN` | 32 | `pg_vault_tde_kms.h` **only** |

`TDE_DEK_LEN` MUST NOT be redefined in any `.c` file or other header
(header hygiene rule).

---

## SQL API Reference

### Access Methods

```sql
-- Table AM: encrypts all column data per tuple
CREATE TABLE t (...) USING encrypted_heap;

-- Index AM: deterministic AES-SIV for B-Tree key equality
CREATE INDEX ON t USING tde_btree (col);
```

### Functions

```sql
-- Key management
SELECT pg_vault_tde_set_test_dek();     -- inject random ephemeral DEK (DEV/TEST ONLY)
SELECT pg_vault_tde_rotate_key();       -- wipe DEK from shmem, bump generation
SELECT pg_vault_tde_key_generation();   -- → bigint: current epoch counter


-- Test / diagnostic (require DEK set; never use in production)
SELECT pg_vault_tde_encrypt_test('text');   -- → bytea: [IV(12)|CT|TAG(16)]
SELECT pg_vault_tde_decrypt_test(bytes);    -- → text: plaintext (verifies GCM tag)
```

### GUC Parameters

All parameters are in the `pg_vault_tde` namespace and are registered in
`_PG_init` via `DefineCustomXxxVariable`. They take effect at postmaster
start (`PGC_POSTMASTER`); `enabled` is changeable by superusers at runtime
(`PGC_SUSET`).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `vault_url` | string | `''` | Vault / OpenBao base URL |
| `vault_namespace` | string | `''` | Vault namespace (enterprise; empty for community) |
| `vault_token` | string | `''` | Auth token — hidden from `pg_settings` (`GUC_SUPERUSER_ONLY`) |
| `vault_role_id` | string | `''` | AppRole role_id UUID |
| `vault_secret_id` | string | `''` | AppRole secret_id — hidden from `pg_settings` (`GUC_SUPERUSER_ONLY`) |
| `vault_role_name` | string | `''` | AppRole role name for secret_id rotation **(v1.4)** — calls `secret-id/destroy` after login |
| `vault_k8s_role` | string | `''` | Kubernetes JWT auth role name |
| `vault_transit_mount` | string | `transit` | Transit secrets engine mount path |
| `vault_key_name` | string | `pg-tde-dek` | Transit key name for DEK wrapping |
| `vault_ca_cert` | string | `''` | Path to CA bundle for Vault TLS (`CURLOPT_CAINFO`) |
| `vault_timeout_ms` | integer | `5000` | Vault HTTP timeout in ms (0 = no timeout; range 0–300000) |
| `bgw_enabled` | boolean | `off` | Enable background worker for automatic token renewal. **Requires cluster restart** to take effect: the background worker is registered at postmaster startup via `RegisterBackgroundWorker()`, so changing this GUC via `pg_reload_conf()` updates the value but does not start or stop the worker dynamically. |
| `token_renewal_interval` | integer | `3600` | Token renewal interval in seconds (60–86400) |
| `enabled` | boolean | `on` | Master switch: `off` disables crypto for benchmarking overhead |

All variables are declared as `extern` in `src/include/pg_vault_tde_guc.h`
and included by any translation unit that needs them (`tam.c`, `kms.c`).

---

## Extension Initialization

### _PG_init Sequence

```
_PG_init()
  ├── DefineCustomStringVariable("pg_vault_tde.vault_url", ...)
  ├── DefineCustomStringVariable("pg_vault_tde.vault_token", ...)  [GUC_SUPERUSER_ONLY]
  ├── ... 6 more GUC parameters ...
  ├── install shmem_request_hook  → pg_vault_tde_shmem_request()
  │       └── pg_vault_tde_kms_shmem_request()
  │               └── RequestAddinShmemSpace(sizeof(pg_vault_tde_dek_cache))
  │           NOTE: NO RequestNamedLWLockTranche here.
  │           Tranche is allocated lazily in shmem_startup_hook (see below).
  ├── install shmem_startup_hook  → pg_vault_tde_shmem_startup()
  │       └── pg_vault_tde_kms_shmem_init()
  │               ├── ShmemInitStruct("pg_vault_tde_dek_cache", ..., &found)
  │               ├── if !found:
  │               │       ├── LWLockNewTrancheId()       ← requires shmem to be up!
  │               │       └── LWLockInitialize(&cache->lock, tranche_id)
  │               └── LWLockRegisterTranche(id, "pg_vault_tde_kms")  (every process)
  ├── pg_vault_tde_tam_init()
  │       └── memcpy(&tde_methods, GetHeapamTableAmRoutine(), sizeof(TableAmRoutine))
  │           + install 4 write + 7 read + 1 TOAST AM wrappers
  └── register on_proc_exit(tde_backend_cleanup)
          ├── tde_crypto_ctx_cleanup()   ← EVP_CIPHER_CTX_free + OPENSSL_cleanse iv_batch
          └── tde_iam_siv_ctx_cleanup()  ← EVP_CIPHER_CTX_free SIV enc/dec pool
```

#### Critical: Why LWLockNewTrancheId cannot be called from _PG_init

In PostgreSQL 17+, `LWLockNewTrancheId()` acquires
`WaitEventCustomCounterLock`, a spinlock stored **in shared memory**.
Shared memory does not exist at `_PG_init` time. Calling
`LWLockNewTrancheId()` (or `RequestNamedLWLockTranche()`) from `_PG_init`
causes an immediate segfault. The correct pattern is:

- `shmem_request_hook`: call `RequestAddinShmemSpace()` only.
- `shmem_startup_hook` (first process, `!found` branch): call
  `LWLockNewTrancheId()` + `LWLockInitialize()`.
- `shmem_startup_hook` (every process): call `LWLockRegisterTranche()` to
  register the display name in the local wait-event table.

This is the correct pattern for all PG17+ / PG18 extensions that need a
dynamic LWLock tranche.

---

## Testing Strategy

### Regression Tests (`sql/regression_test.sql`)

`sql/regression_test.sql` contains **70 tests**: the original 52 v1.4 baseline
TAM/TOAST additions (tests 53–70). Combined with the v1.5 and v1.6 supplement files the
full `make ci-regress` suite runs **105 tests**.

| Range | Area |
|---|---|
| 1–11 | AES-256-GCM crypto primitives, DEK rotation, tamper detection |
| 12 | TAM INSERT + SELECT basic round-trip |
| 13 | On-disk plaintext absence (raw file scan) |
| 14 | TAM UPDATE (ctid preservation, tuple refetch, HOT chains) |
| 15 | DELETE (no crash, row unreachable) |
| 16 | All-NULL rows (`user_len == 0` edge case) |
| 17 | Index scan (`index_fetch_tuple` + `rd_tableam` workaround) |
| 18 | COPY / bulk insert (`multi_insert` path) |
| 19 | Multi-column types (int, text, bool, numeric, timestamptz) |
| 20 | Key rotation isolation (DEK-A rows rejected after rotating to DEK-B) |
| 21 | ANALYZE (statistics computed on decrypted values) |
| 22 | SELECT FOR UPDATE (`tuple_lock` path) |
| 23 | BitmapHeapScan (`scan_bitmap_next_tuple` via forced bitmap scan) |
| 24 | TABLESAMPLE (`scan_sample_next_tuple` via SYSTEM(100)) |
| 25–48 | UPSERT, MERGE, TRUNCATE, REINDEX, ALTER, JOINs, CTEs, HW accel, Vault, logical decoding |
| 49 | Wire format v2 round-trip (version byte + generation counter) **(v1.4)** |
| 50 | tde_btree CREATE INDEX + equality index scan **(v1.4)** |
| 51 | health_check() `kms_provider` GUC coherence **(v1.4)** |
| 52 | tde_btree UNIQUE constraint **(v1.4)** |
### Page Checksum Test (`make ci-checksums`)

Starts PostgreSQL with `initdb -k` (`--data-checksums`). Verifies that:
1. Page checksums are enabled (`SHOW data_checksums = 'on'`).
2. Encrypted pages pass checksum validation (checksums cover encrypted bytes).
3. The relation file is physically non-zero (encryption actually ran).

### TAP Tests (`tap/`)

| File | Coverage |
|---|---|
| `tap/01_load.t` | Extension load, AM registration, basic SQL round-trip |
| `tap/02_backup.t` | `pg_basebackup` |

### Isolation Tests (`isolation/dek_rotation.spec`)

Verifies:
1. DEK rotation does not block concurrent read transactions.
2. New inserts after rotation use the new generation.
3. Reads that started before rotation complete without error (MVCC + local cache).

### Anti-Patterns (DO NOT)

- **DO NOT** mix rows encrypted with different DEKs in the same table during
  sequential scan tests — the scan encounters wrong-DEK rows first and raises
  GCM authentication errors before reaching target rows. Use **separate tables
  per DEK epoch** in rotation tests.
- **DO NOT** assume `slot->tts_tid` is valid after
  `ExecFetchSlotHeapTuple(slot, false, ...)` — it returns the `tupdata`
  workspace with uninitialised `t_self`. Read TID from
  `bslot->base.tuple->t_self` while the buffer pin is held.
- **DO NOT** call `pg_vault_tde_decode_slot` on an already-decoded slot
  without the double-decode guard (`bslot->buffer == InvalidBuffer`).

---

## Packaging

### DEB (Debian / Ubuntu)

```bash
# Build
bash packaging/build_deb.sh --no-sign

# Install
dpkg -i ../postgresql-18-pg-vault-tde_1.0-1_amd64.deb

# Verify
dpkg -l | grep pg-vault-tde
```

### RPM (RHEL / Rocky / Fedora)

```bash
# Build
bash packaging/build_rpm.sh

# Install
dnf install ~/rpmbuild/RPMS/x86_64/postgresql18-pg_vault_tde-1.0-1.*.rpm

# Verify
rpm -qi postgresql18-pg_vault_tde
```

### Hardware-Accelerated Variants

| Variant | Flag | Package suffix |
|---|---|---|
| Generic (portable) | `TDE_TARGET_ARCH=generic` | *(default)* |
| AES-NI (Intel/AMD) | `TDE_TARGET_ARCH=x86_64-aesni` | `-aesni` |
| VAES + AVX2 | `TDE_TARGET_ARCH=x86_64-vaes` | `-vaes` |
| ARM Crypto (ARMv8-A) | `TDE_TARGET_ARCH=aarch64-ce` | `-armce` |
| ARM SVE2 (ARMv9-A) | `TDE_TARGET_ARCH=aarch64-sve2` | `-sve2` |

The ARM CE variant is packaged as a separate `.so` (`pg_vault_tde_armce.so`)
and RPM (`postgresql18-pg_vault_tde-armce`) that can coexist with the
generic build. See `packaging/rpm/pg_vault_tde-arm.spec`.

### Version Matrix

| pg_vault_tde | PostgreSQL | OpenSSL | Status |
|---|---|---|---|
| 1.6.x | 17.x, 18.x | 3.x | ✅ Current |
| 1.7.x | 17.x, 18.x, 19.x | 3.x | 📋 Planned |
| 1.8.x | 17.x, 18.x, 19.x | 3.x | 📋 Planned |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full release roadmap.

| Version | Theme | Status | Tests |
|---------|-------|--------|-------|
| **v1.1** | KMS/Vault + Key Rotation + HW Accel | ✅ Completed | 41 |
| **v1.2** | Logical Decoding | ✅ Completed | — |
| **v1.3** | Vault KEK + multi_insert + BGW | ✅ Completed | 48 |
| **v1.4** | CI/CD + tde_btree + Wire Format v2 | ✅ Completed | 52 |
| **v1.5** | Per-Table DEK + Online Rotation + AAD | ✅ Completed | 72 |
| **v1.6** | Local Wallet KMS (production-ready) | ✅ Completed | 72 |
| **v1.7** | TOAST Chunks + HSM + Audit | 📋 Q4 2027 | ~100 |
| **v1.8** | KMIP + Column-Level + HA | 📋 Q2 2028 | ~130 |

### Permanent Deferrals

| Gap | Reason |
|-----|--------|
| WAL encryption | Requires PG core hook (`XLogInsert()`) — not extension API |
| BRIN on encrypted columns | min/max of ciphertexts is meaningless |
| General GiST (range, geometric) | Penalty/picksplit requires ordering |
| Full-text phrase search | Positional ordering destroyed by AES-SIV |

---

## Contributing

This extension follows PostgreSQL's BSD-derived coding style and
`pgindent` formatting conventions. All contributions must:

- Pass `make` with `-Wall -Wextra` and zero warnings
- Pass the full 72-test regression suite (`make ci-regress`)
- Pass the page checksum compatibility test (`make ci-checksums`)
- Use `palloc` / `pfree` exclusively (never `malloc` / `free`)
- Use `ereport` / `elog` exclusively (never `printf` / `exit`)
- Be C99 conformant with `snake_case` naming
- Clean IV + DEK memory with `OPENSSL_cleanse` before `pfree`
- Not introduce circular module dependencies (TAM → Crypto → KMS; never reverse)
- Not use GPL/AGPL libraries (breaks PostgreSQL License compatibility)

See [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
and [`AGENTS.md`](AGENTS.md) for AI-assisted development guidelines and
subagent coordination protocol.
