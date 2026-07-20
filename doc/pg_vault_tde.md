# pg_vault_tde Technical Reference

**Version**: 1.7  
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
6. [Logical Decoding and Replication](#logical-decoding-and-replication)
7. [PKCS#11 / HSM Provider](#pkcs11--hsm-provider)
8. [Known Limitations](#known-limitations)
9. [Security Considerations](#security-considerations)
10. [Wire Format Reference](#wire-format-reference)
11. [SQL API Reference](#sql-api-reference)
12. [Extension Initialization](#extension-initialization)
13. [Testing Strategy](#testing-strategy)
14. [Packaging](#packaging)
15. [Roadmap](#roadmap)
16. [Contributing](#contributing)

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
| `tuplesort_begin_index_btree()` assert on `relam` | Asserts `rd_rel->relam == BTREE_AM_OID` | No such assert | `PG_VERSION_NUM < 180000` — `pg_vault_tde_ambuild()` temporarily impersonates `BTREE_AM_OID` on `index->rd_rel->relam` during the sort |
| `BuildSpeculativeIndexInfo()` assert on ON CONFLICT | Asserts against non-btree-looking `relam` for unique `tde_btree` indexes | No such assert | `PG_VERSION_NUM < 180000` — `tde_executor_start_hook()` swaps `relam` back to `BTREE_AM_OID` for the duration of the query, restored via a `MemoryContextCallback` |

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
      ├── Per-relation DEK cache       src/kms/pg_vault_tde_catalog.c
      │    ├─ DEK cache (shmem HTAB)    TdeRelDekMap (one shared LWLock)
      │    └─ get DEK for a relation    pg_vault_tde_kms_get_rel_dek(relid)
      ├── KMS provider vtable           src/kms/pg_vault_tde_kms.c
      │    └─ Vault provider (libcurl)  vault_provider_{wrap,unwrap,rewrap}_dek()
      ├── Local wallet provider        src/kms/pg_vault_tde_kms_local.c (PKCS#12)
      ├── DEK catalog (on-disk)        src/kms/pg_vault_tde_catalog.c (wrapped_dek)
      ├── Rotation background worker   src/kms/pg_vault_tde_rotation_bgw.c
      ├── HW acceleration              src/crypto/pg_vault_tde_hw_accel.c
      ├── Logical decoding plugin      src/logical/pg_vault_tde_pgoutput.c
      ├── Backup                       src/backup/pg_vault_tde_backup.c
      │                                (+ pg_dump_tde.c / pg_restore_tde.c)
      └── Entry point                  src/pg_vault_tde.c (_PG_init)
```

### Key Lifecycle

```
Vault / OpenBao (KEK owner)  ──or──  Local wallet (PKCS#12, KEK-on-disk)
        │
        │  unwrap wrapped_dek via active provider vtable (synchronous;
        │  libcurl HTTP(S) for Vault, AES-256-WRAP for local)
        ▼
pg_vault_tde_kms_get_rel_dek(relid)    [src/kms/pg_vault_tde_catalog.c]
        │   fast path: LW_SHARED hash_search of TdeRelDekMap (cache hit)
        │   slow path: read pg_vault_tde_catalog.wrapped_dek → provider
        │              unwrap → hash_search(HASH_ENTER) under LW_EXCLUSIVE
        ▼
TdeRelDekMap (shmem HTAB)              [one entry per relid; single shared
        │                               LWLock; generation + prev_dek window]
        │  DEK (32 bytes) copied into a stack buffer on every call; the crypto
        │  layer caches the AES key schedule keyed by (relid, generation)
        ▼
tde_gcm_encrypt() / tde_gcm_decrypt()  [src/crypto/pg_vault_tde_crypto.c]
        │
        ▼
Disk: [HeapTupleHeader | IV(12) | Ciphertext | GCM-TAG(16) | VER(1) | GEN(8)]
```

### Shared Memory Layout

Since v1.7 the cache is a shared-memory **hash table** (`HTAB`) keyed by
`relid`, not a fixed array scanned linearly. Each entry is one `TdeRelDekMap`:

```c
/* Per-relation DEK entry — value type of the TdeRelDekMap HTAB (v1.5+) */
typedef struct TdeRelDekMap {
    Oid     relid;                   /* hash key */
    char    dek[TDE_DEK_LEN];        /* current AES-256 DEK, 32 bytes */
    char    prev_dek[TDE_DEK_LEN];   /* previous DEK (valid during rotation) */
    uint64  generation;              /* rotation epoch for this relation */
    bool    dek_valid;               /* true iff dek[] holds a live key */
    bool    prev_dek_valid;          /* true iff prev_dek[] is populated */
} TdeRelDekMap;
```

- `TDE_DEK_LEN` is defined **only** in `src/include/pg_vault_tde_kms.h`.
- The HTAB lives in `src/kms/pg_vault_tde_catalog.c`, created with
  `ShmemInitHash("TdeRelDekMap", capacity, capacity, &info, HASH_ELEM | HASH_BLOBS)`
  where `capacity = pg_vault_tde.max_encrypted_relations`. The segment is sized
  with `hash_estimate_size(capacity, sizeof(TdeRelDekMap))`.
- There is **no per-entry lock**. A single `LWLock` (file-scope `rel_dek_lock`)
  from a **named** tranche guards the whole table:
  `RequestNamedLWLockTranche("TdeRelDekMap", 1)` in the `shmem_request_hook`,
  then `&GetNamedLWLockTranche("TdeRelDekMap")[0].lock` in the
  `shmem_startup_hook`. The lock is taken `LW_SHARED` for lookups and
  `LW_EXCLUSIVE` for insert/evict/rotate.
- A second, fixed-size shmem struct (`pg_vault_tde_kms_cache`, in
  `pg_vault_tde_kms.c`) holds the shared Vault token. Its lock uses a **dynamic**
  tranche (`LWLockNewTrancheId()`), which is why that call lives in the
  `shmem_startup_hook` and not `_PG_init` — see [Extension Initialization](#extension-initialization).

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

All structural operations (VACUUM, CLUSTER, index build, truncate, scan state management) delegate to heapam unchanged. Only the five write paths, eight read paths, two visibility/build paths, and two rewrite path are overridden.

### Overridden Callbacks

#### Write Paths (encrypt before storing)

| Callback | Purpose |
|---|---|
| `tuple_insert` | Single-row INSERT |
| `tuple_insert_speculative` | Speculative INSERT (ON CONFLICT) |
| `multi_insert` | COPY FROM / bulk INSERT |
| `tuple_update` | UPDATE |
| `tuple_delete` | DELETE |

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
| `scan_getnextslot` | SeqScan | ✅ Override |
| `scan_getnextslot_tidrange` | TidRangeScan | ✅ Override |
| `index_fetch_tuple` | Index Scan, Index Only Scan | ✅ Override |
| `scan_bitmap_next_tuple` | BitmapHeapScan | ✅ Override |
| `scan_analyze_next_tuple` | ANALYZE | ✅ Override |
| `scan_sample_next_tuple` | TABLESAMPLE | ✅ Override |
| `tuple_fetch_row_version` | TidScan, UPDATE recheck | ✅ Override |
| `tuple_lock` | SELECT FOR UPDATE/SHARE | ✅ Override |

#### Visibility & Index-Build Paths
 
| Callback | Purpose |
|---|---|
| `tuple_satisfies_snapshot` | Visibility recheck for RI foreign-key trigger (`RI_FKey_check`) — heapam's version asserts a live buffer pin, which our decrypt-into-palloc'd-tuple path doesn't hold |
| `index_build_range_scan` | CREATE INDEX / REINDEX — decrypts each tuple before `FormIndexDatum` extracts key values, otherwise indexes would be built over ciphertext|


#### Rewrite Paths (decrypt → process → re-encrypt)

| Callback | Trigger | Notes |
|---|---|---|
| `relation_copy_for_cluster` | `VACUUM FULL`, `CLUSTER` | Reads each tuple via `heap_getnext` (with `rd_tableam` impersonation), decrypts, re-encrypts into the new heap via `rewrite_heap_tuple`. Clears `HEAP_HASEXTERNAL` on the encrypted copy before writing; `tde_tuple_has_external_slow` (per-attribute varlena scan) is used on subsequent DELETE to locate TOAST chunks regardless of the infomask flag. |
| `relation_toast_am` | TOAST table creation | Selects `encrypted_heap` as the TOAST AM when `pg_vault_tde.toast_encryption = on` (default), so TOAST chunks are encrypted through the same `tuple_insert`/`scan_getnextslot` hooks as the main table. |

### pg_vault_tde_decode_slot

This function is the core of the read path. It:

1. Casts the slot to `BufferHeapTupleTableSlot` (known buffer-backed after heapam)
2. **Guards against double-decode**: checks `bslot->buffer == InvalidBuffer`
3. Saves `bslot->base.tuple->t_self` (physical TID) and `t_tableOid` (relation OID) from the buffer page
4. Calls `tde_decrypt_heap_tuple(bslot->base.tuple, saved_tableoid)` — decrypts the
   buffer-backed tuple directly (verifies GCM tag via OpenSSL). **No `heap_copytuple`
   and no explicit `ExecClearTuple`**: the buffer pin must stay held until the
   force-store below. Releasing it early forces O(rows) buffer re-pins during a
   sequential scan instead of O(pages) (see performance note in the function header).
5. Stamps `plain->t_self = saved_tid`, `plain->t_tableOid = saved_tableoid`
6. Calls `ExecForceStoreHeapTuple(plain, slot, true)` — this performs the single
   internal `ExecClearTuple` that releases the buffer pin (the only release point)
7. **Manually sets `slot->tts_tid = saved_tid`** — `ExecForceStoreHeapTuple`
   does NOT restore `tts_tid` for buffer slots; it must be set explicitly

```c
static void pg_vault_tde_decode_slot(TupleTableSlot *slot)
{
    BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
    HeapTuple   plain;
    ItemPointerData saved_tid;
    Oid         saved_tableoid;

    /*
     * Guard against double-decode: after ExecForceStoreHeapTuple the buffer
     * is released (buffer == InvalidBuffer) but base.tuple is still set.
     * Re-entering here would try to decrypt already-plain data.
     */
    if (bslot->buffer == InvalidBuffer)
        return;

    /*
     * Read TID + relation OID from the buffer-backed pointer directly, NOT from
     * ExecFetchSlotHeapTuple(slot, false, ...) which returns the tupdata
     * workspace with an uninitialized t_self.
     */
    ItemPointerCopy(&bslot->base.tuple->t_self, &saved_tid);
    saved_tableoid = bslot->base.tuple->t_tableOid;

    /*
     * Decrypt the buffer-backed tuple in place (verifies GCM tag; ereport(ERROR)
     * on tamper).  Do NOT call heap_copytuple/ExecClearTuple first: the pin must
     * stay held until ExecForceStoreHeapTuple, which releases it exactly once per
     * tuple.  Releasing early causes O(rows) buffer hits on sequential scans.
     */
    plain = tde_decrypt_heap_tuple(bslot->base.tuple, saved_tableoid);

    ItemPointerCopy(&saved_tid, &plain->t_self);
    plain->t_tableOid = saved_tableoid;

    ExecForceStoreHeapTuple(plain, slot, true);   /* internal ExecClearTuple releases pin */
    ItemPointerCopy(&saved_tid, &slot->tts_tid);  /* ExecForceStoreHeapTuple does not set this */
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

**Version 4** is the **only** on-disk tuple format. It is an **IV-first trailer**
layout: the version byte and generation counter sit at the **end** of the blob, so
the data differs from byte 0 on every encryption (this is what disables HOT — see
[Known Limitations](#known-limitations)). The legacy v1/v2/v3 formats were **removed**.
(The byte `0x02` still appears only in the `pg_dump_tde` *backup block* format — a
separate code path, see [Backup](../README.md#encrypted-backups).)

```
+----------+----------------------------+----------+-------+----------+
| IV       | CIPHERTEXT                 | GCM TAG  | VER   | GEN      |
| 12 bytes | N bytes (= plaintext len)  | 16 bytes | 1 byte| 8 bytes  |
+----------+----------------------------+----------+-------+----------+
  random                                            0x04   uint64 LE
```

Total overhead: `TDE_V4_OVERHEAD = 37` bytes
(`TDE_GCM_IV_LEN=12` + `TDE_GCM_TAG_LEN=16` + `1` version byte + `TDE_V4_GEN_LEN=8`).

v4 binds each tuple to its location by passing
`[MyDatabaseId(4) | relid(4) | generation(8)]` (little-endian, `TDE_V4_AAD_LEN = 16`
bytes) as GCM Additional Authenticated Data — zero wire overhead; prevents
cross-table ciphertext smuggling. The AAD is reconstructed on decrypt from the
**stored** generation in the wire trailer (not the current generation), so old-generation
rows still authenticate during the rotation window.

When `user_len == 0` (all-NULL tuple, or tuple with only system columns),
`tde_gcm_encrypt()` still produces a full `TDE_V4_OVERHEAD`-byte (37) block. This
exercises the GCM tag path on zero data; the decrypt path handles it symmetrically.
Test 16 covers this edge case.

### Memory Security

- DEK copies in per-backend memory are `OPENSSL_cleanse`d before `pfree`.
- Plaintext `HeapTuple` intermediates are `OPENSSL_cleanse`d after encryption.
- Per-backend EVP contexts are freed via `on_proc_exit()` callbacks
  (`tde_iam_ctx_cleanup` for AES-SIV; analogous cleanup for GCM contexts).
- Shared-memory DEK is `OPENSSL_cleanse`d during rotation before the new key
  is written.

---

## Performance

### Per-Backend EVP Contexts Keyed by (relid, generation)

Two costs hide on the per-tuple crypto path: allocating an `EVP_CIPHER_CTX`
(a heap malloc) and installing the AES-256 **key schedule**
(`EVP_EncryptInit_ex2` with the DEK). A naive implementation pays both on every
tuple. pg_vault_tde caches each context together with the key it is keyed for:

```c
typedef struct TdeCipherSlot {
    EVP_CIPHER_CTX *ctx;
    Oid             relid;
    uint64          generation;
} TdeCipherSlot;

static TdeCipherSlot tde_enc = { NULL, InvalidOid, 0 };  /* encrypt direction */
static TdeCipherSlot tde_dec = { NULL, InvalidOid, 0 };  /* decrypt direction */
```

Each context is allocated once per backend (`EVP_CIPHER_CTX_new()` on first
use). The expensive key-schedule install runs **only when the slot's cached
`(relid, generation)` differs** from the current operation — i.e. on the first
tuple of a relation and again after a key rotation. For every other tuple the
installed schedule is reused and only the per-tuple IV is rearmed with
`EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL)`. Consecutive tuples of the same
relation (the common bulk-INSERT / sequential-scan case) therefore skip the
key schedule entirely.

On decrypt the slot is keyed by the **stored** generation read from the wire
trailer, so old-generation rows decrypted via `prev_dek` during the rotation
window get their own cached schedule without thrashing the current-generation
one.

On any fatal OpenSSL error `tde_crypto_ctx_cleanup()` frees and NULL-outs both
contexts (and resets their `relid` to `InvalidOid`) so the next call
re-allocates and re-keys cleanly. Both contexts are freed in the
`on_proc_exit()` callback `tde_crypto_ctx_cleanup()`, which also wipes the IV
batch. The same allocate-once pattern is applied to the IAM: a single per-backend
AES-256-SIV context, re-keyed only when the `(idx_oid, generation)` pair changes
(`tde_iam_ctx_prepare`), freed by `tde_iam_ctx_cleanup()`.

### IV Batch Generation

`pg_strong_random()` is a syscall to `/dev/urandom` or `getrandom(2)`. A
non-batched implementation would pay one syscall per encrypted tuple. Instead,
pg_vault_tde batches 256 IVs per `pg_strong_random()` call:

```c
#define TDE_IV_BATCH_SIZE   256
#define TDE_IV_BATCH_BYTES  (TDE_IV_BATCH_SIZE * TDE_GCM_IV_LEN)
static char  iv_batch[TDE_IV_BATCH_BYTES];
static int   iv_batch_pos = TDE_IV_BATCH_SIZE;  /* start empty */

static void tde_next_iv(unsigned char *iv_out)
{
    if (iv_batch_pos >= TDE_IV_BATCH_SIZE)
    {
        if (!pg_strong_random(iv_batch, TDE_IV_BATCH_BYTES))
            ereport(ERROR, (errmsg("[CRYPTO] pg_strong_random failed")));
        iv_batch_pos = 0;
    }
    memcpy(iv_out, iv_batch + iv_batch_pos * TDE_GCM_IV_LEN, TDE_GCM_IV_LEN);
    iv_batch_pos++;
}
```

The buffer is wiped with `OPENSSL_cleanse()` in the backend-exit cleanup.

This amortises the syscall cost across 256 tuples.

### Benchmark

Run the included benchmark against a live container:

```bash
bash bench_tde.sh 100000
```

The script runs INSERT, SELECT, UPDATE, index scan, and TABLESAMPLE workloads
on `plain_heap` vs `encrypted_heap`, and prints a comparison table with
overhead percentages. Use `pg_vault_tde.enabled = off` (requires a server
restart — the GUC is `PGC_POSTMASTER`) to isolate pure TAM overhead (no
crypto) from actual encryption cost. See the warning in README.md before
toggling this on any database with existing `encrypted_heap` data.

```
┌────────────────────────────────────────────────────┐
│  Shared memory                                     │
│  ──────────────────────────────────────────────────│
│  LWLock (embedded by value)                        │
│  HTAB (TdeRelDekMap)                               │
│    ├─ relid: Oid         (key)                     │
│    ├─ dek[32]: char      (current DEK)             │
│    ├─ prev_dek[32]: char (rotation window)         │
│    ├─ generation: uint64                           │
│    └─ dek_valid / prev_dek_valid: bool             │
└────────────────────────────────────────────────────┘
               ▲ pg_vault_tde_kms_get_rel_dek(relid)
               │  fast path:  LW_SHARED cache hit
               │  slow path:  catalog read → KMS unwrap → cache insert
┌────────────────────────────────────────────────────┐
│  pg_vault_tde_catalog  (on-disk system table)      │
│  ──────────────────────────────────────────────────│
│  relid, generation,                                │
│  wrapped_dek, kms_provider, created_at, updated_at │
└────────────────────────────────────────────────────┘
```

1. Every encrypt/decrypt call fetches the DEK with
   `pg_vault_tde_kms_get_rel_dek()`: `hash_search(HASH_FIND)` under `LW_SHARED`,
   `memcpy` into a stack buffer, release. The buffer is `OPENSSL_cleanse`d after
   use (caller responsibility).
2. On a cache miss (first access after startup, or after the entry was evicted
   by rotation), the slow path reads `pg_vault_tde_catalog.wrapped_dek`, unwraps
   it via the active KMS provider, and inserts the entry under `LW_EXCLUSIVE`.
3. Cross-call key-schedule reuse lives in the **crypto layer**, not here: the
   `TdeCipherSlot` EVP contexts cache the installed AES schedule keyed by
   `(relid, generation)` (see [Per-Backend EVP Contexts](#per-backend-evp-contexts-keyed-by-relid-generation)),
   so re-fetching the DEK bytes per call is cheap and the expensive schedule
   install is amortised.

### Generation-Epoch Rotation

Key rotation is now **per-relation** via `pg_vault_tde_rotate_online(relname, batch_size)`.
For each encrypted relation `pg_vault_tde_catalog_zero_rel_dek()`:
1. Acquires `LW_EXCLUSIVE` on the single `rel_dek_lock` guarding the HTAB and
   looks the entry up with `hash_search(HASH_FIND)`.
2. Promotes the current DEK to `prev_dek` then `OPENSSL_cleanse`s `dek[32]` for the rotation window.
3. Increments the per-relation `generation` counter.
4. Sets `dek_valid = false` (triggers a catalog read + KMS unwrap on next access).
5. Releases lock.

Each backend detects the mismatch lazily on the next encrypt/decrypt call for that
relation. Old-generation rows can still be read via `prev_dek` during the rotation
window; after `pg_vault_tde_reencrypt_table()` completes the window closes.

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
| Column support | Varlena `bytea`/`text`/`numeric` (`tde_*_ops`) and fixed-size `int4`/`int8`/`uuid`/`date`/`timestamptz` (`tde_*_enc_ops`, default since v1.7). All index keys are AES-256-SIV encrypted. |

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
indexed column datum via `tde_iam_encrypt_index_datum()` (which dispatches to
`tde_iam_encrypt_fixed_type_datum()` for fixed-size types and the varlena path
otherwise, both AES-256-SIV), then spools it into the btree sort buffer. After
the heap scan, `_bt_leafbuild()` writes all encrypted entries to the index pages
in sorted order.

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

`CREATE EXTENSION` registers two families of operator classes:

- **Varlena classes** — `tde_bytea_ops`, `tde_text_ops`, `tde_numeric_ops` (DEFAULT for
  their types). The varlena datum is encrypted with AES-256-SIV and stored as `bytea`.
- **Fixed-size `enc_ops` classes** (v1.7) — `tde_int4_enc_ops`, `tde_int8_enc_ops`,
  `tde_uuid_enc_ops`, `tde_date_enc_ops`, `tde_timestamptz_enc_ops`, all in the
  `tde_enc_ops_family` with `STORAGE bytea` and **DEFAULT** for their types. They expose
  only `OPERATOR 3 (=)` — equality is the only meaningful predicate on SIV ciphertext.
  The legacy non-encrypted classes (`tde_int4_ops`, `tde_int8_ops`, `tde_uuid_ops`,
  `tde_date_ops`, `tde_timestamptz_ops`) are retained but **not** default; prefer the
  `enc_ops` classes so index keys are encrypted.

### Index-Only Scans

Index-only scans are **not supported** on `tde_btree` indexes by design. PostgreSQL
index-only scans return column values directly from the index pages without visiting
the heap. Since `tde_btree` stores AES-256-SIV ciphertexts as index keys, returning
those values directly would expose raw ciphertext to the client with no decryption.

All decryption happens in the TAM layer (`decode_slot`) when the heap tuple is
fetched. The planner is prevented from choosing an index-only scan path on
`tde_btree` indexes; it always fetches the tuple from the `encrypted_heap` table.

Range scans on `tde_btree` columns return empty results by design — AES-256-SIV
does not preserve ordering regardless of column type.

### Usage Example

```sql
-- Create an encrypted table
CREATE TABLE employees (
    id        int4,
    username  text,
    salary    numeric
) USING encrypted_heap;

-- Create tde_btree indexes on multiple column types. The opclass is optional:
-- the encrypted-key classes are the DEFAULT for each type since v1.7, so
-- `USING tde_btree (id)` picks tde_int4_enc_ops automatically.
CREATE INDEX employees_id_idx       ON employees USING tde_btree (id tde_int4_enc_ops);
CREATE INDEX employees_username_idx ON employees USING tde_btree (username tde_text_ops);

-- Equality lookups use the encrypted index
INSERT INTO employees VALUES (1, 'alice', 90000);
INSERT INTO employees VALUES (2, 'bob',   85000);

SELECT salary FROM employees WHERE id = 1;       -- uses index
SELECT id     FROM employees WHERE username = 'alice';  -- uses index

-- Range predicates fall back to sequential scan (index returns empty by design)
SELECT * FROM employees WHERE id > 1;            -- seq scan, not index scan

-- Index-only scans are not supported and never chosen by the planner;
-- the heap tuple is always fetched to decrypt column values.
```

---

## Logical Decoding and Replication

`pg_vault_tde` ships a logical decoding output plugin (`pg_vault_tde_pgoutput`)
so that `encrypted_heap` tables can be published to logical replication
subscribers **in plaintext**, even though their on-disk tuples — and their WAL —
are ciphertext.

### Why a plugin is needed

The TAM decrypt-on-read callbacks run in the query executor, not in the WAL
sender. A logical decoder reads raw WAL records whose tuple bodies are
ciphertext, so without intervention a subscriber receives encrypted garbage.

### Non-TOAST tables — pgoutput wrapper

`_PG_output_plugin_init` loads the built-in `pgoutput` via
`load_external_function()`, lets it populate every callback, then overrides the
change callbacks with thin wrappers that decrypt the tuple **in place** (via
`tde_decrypt_heap_tuple`) before delegating back to `pgoutput` for the actual
serialization. Because the emitted wire format is exactly the `pgoutput`
protocol, this works with `pg_recvlogical` and with a native `CREATE
SUBSCRIPTION` pointed at a slot created with this plugin. (Same wrapping
technique as Citus's CDC decoder.)

### TOAST columns — custom WAL resource manager

Externally-TOASTed columns need more than in-place decryption: the core reorder
buffer reassembles a TOAST value by `heap_deform_tuple()`-ing the chunks and the
main tuple **before any output-plugin callback runs**, and on an encrypted tuple
that crashes (`got sequence entry … for toast chunk`). There is no extension
hook earlier than that point.

The lever that does exist is a **custom WAL resource manager**, gated by the GUC
`pg_vault_tde.toast_custom_rmgr` (PGC_POSTMASTER, default **off**; requires
`pg_vault_tde` in `shared_preload_libraries`). When enabled:

1. **Write path** — `tde_toast_wal_insert()` (a faithful clone of `heap_insert`)
   logs encrypted TOAST chunks under `TDE_RMGR_ID` instead of `RM_HEAP_ID`. The
   WAL record is byte-identical to heap's except for the resource manager id, so
   crash recovery is unaffected (`rm_redo` delegates to `heap_redo`).
2. **Decode** — routing the chunks to our `rm_decode` keeps them out of the
   reorder buffer's `toast_hash`, so the core never deforms the still-encrypted
   main tuple. `rm_decode` captures the raw encrypted chunks per transaction
   (no catalog access during decode).
3. **Stitch** — `tde_toast_stitch()`, called from the plugin's change callback
   after the main tuple has been decrypted, decrypts the captured chunks,
   reconstructs the plaintext value, and rewrites the external on-disk TOAST
   pointers into in-memory indirect pointers — a faithful analogue of core's
   `ReorderBufferToastReplace()`. `pgoutput` then serializes the full plaintext.

### Requirements and supported operations

| Operation | Requirement |
|-----------|-------------|
| INSERT (inline, TOAST, bursts) | `toast_custom_rmgr = on` for TOAST columns |
| Initial table sync (COPY) | works via the TAM read path (decrypt-on-read) |
| UPDATE / DELETE | **`REPLICA IDENTITY FULL` + a primary key** |

`REPLICA IDENTITY FULL` is mandatory for UPDATE/DELETE: with `DEFAULT` the core
derives the replica identity by reading the **encrypted** old tuple as if it
were the key, producing a constant garbage key — the subscriber then silently
targets the wrong row. Tables without a primary key are likewise unsupported for
UPDATE/DELETE (no key to match on). These are documented limitations, not bugs:
they follow from the tuple being an opaque ciphertext blob to the core.

### Structural limitations

- **`heap_insert` clone maintenance** — `tde_toast_wal_insert()` mirrors
  `heap_insert()` and must be re-synced on each major PostgreSQL release; it is
  version-audited against the upstream function (see the comment in
  `src/logical/pg_vault_tde_rmgr.c`).
- **Reorder-buffer coupling** — the stitch path mirrors internal contracts of
  `ReorderBufferToastReplace` (buffer copy-back, memory context) that are not a
  stable public API.
- **Aborted-transaction capture** — a TOAST-writing transaction that reaches a
  full snapshot and then aborts *without being streamed* leaves its captured
  chunks in memory until the decoding process exits (there is no output-plugin
  hook for non-streamed aborts; it is a slow, per-abort leak, not per-row).
- **Resource manager id** — the experimental id `RM_EXPERIMENTAL_ID` (128) is
  used for now; a stable custom rmid will be reserved and registered on the
  PostgreSQL community wiki before GA.

This ciphertext-as-opaque-blob conflict — every place the core reads a single
column (e.g. replica identity) sees ciphertext — is the motivation for the
column-level encryption alternative on the v1.8 roadmap.

---

## PKCS#11 / HSM Provider

The `pkcs11` KMS provider (v1.7, `src/kms/pg_vault_tde_kms_pkcs11.c`) keeps
the KEK inside a hardware security module. It talks the Cryptoki API
directly: the vendor's PKCS#11 module (`pg_vault_tde.pkcs11_library`) is
`dlopen()`ed at runtime and every DEK is wrapped/unwrapped with
`C_WrapKey`/`C_UnwrapKey` using `CKM_AES_KEY_WRAP` (RFC 3394, the same
algorithm the local wallet provider uses in software), with a runtime
fallback to `CKM_AES_KEY_WRAP_PAD`. No OpenSSL involvement and no
build/runtime dependency: the OASIS interface headers are vendored under
`src/include/pkcs11/` (include them only through
`src/include/pg_vault_tde_cryptoki.h`).

### Key Hierarchy and Threat Model

```
HSM token (user PIN via env var)
  └── KEK: AES-256, CKO_SECRET_KEY, CKA_SENSITIVE, CKA_EXTRACTABLE=FALSE
        └── C_WrapKey (CKM_AES_KEY_WRAP) → per-table DEK  (40-byte blob
              │                             in pg_vault_tde_catalog)
              └── encrypts tuple data (AES-256-GCM, in-process)
```

Only the **KEK** is confined to the HSM: tuple crypto runs in-process, so
the plaintext DEK necessarily transits backend memory (stack buffers,
`OPENSSL_cleanse`d after use) — the same model as the Vault Transit
provider. An attacker with the disk (or a catalog dump) holds only
DEKs wrapped by a key that exists exclusively inside the device.

### Setup

1. `pg_vault_tde.kms_provider = 'pkcs11'`, `pkcs11_library`, and
   `pkcs11_token_label` (preferred; `pkcs11_slot_id` is the fallback —
   slot IDs are not stable across restarts on some modules).
2. Export the token user PIN in the environment variable named by
   `pkcs11_pin_env` (default `PG_TDE_PKCS11_PIN`) before starting
   PostgreSQL. The GUC holds the env var *name* — never put the PIN in
   `postgresql.conf`.
3. `SELECT pg_vault_tde_pkcs11_keygen();` (superuser, once) generates the
   AES-256 KEK on the token under `pkcs11_key_label`. It refuses to
   overwrite an existing key. Alternatively provision the key with the HSM
   tooling (`CKA_WRAP`, `CKA_UNWRAP`, `CKA_EXTRACTABLE=FALSE`).

Per-database HSM isolation works like every other provider: all `pkcs11_*`
GUCs are `PGC_SUSET`, so different databases can use different tokens or
key labels via `ALTER DATABASE ... SET`.

### Process Model and Fork Safety

PKCS#11 (§6.6 of the spec) makes Cryptoki state unusable across `fork()`.
Because every PostgreSQL backend is forked from the postmaster:

- `C_Initialize` is **never** called in the postmaster — `init()` there
  only validates the GUCs;
- each backend attaches lazily on first use (dlopen → `C_Initialize` →
  slot discovery → `C_OpenSession` → `C_Login` → KEK lookup), and a
  `getpid()` guard discards any state inherited across fork without
  calling into the module;
- on session/device loss (`CKR_SESSION_HANDLE_INVALID`,
  `CKR_DEVICE_ERROR`, ...) operations retry exactly once through a fresh
  session;
- the vendor module is never `dlclose()`d (many modules crash on unload).

### KEK Rotation

Each KEK generation lives forever under its own immutable token label
`<label>.v<N>` (N monotonically increasing) — rotation never renames or
destroys a key. "Current" is simply the highest `N` found on the token, and
every wrapped DEK stored in the catalog carries a 4-byte version tag
identifying exactly which `<label>.v<N>` produced it. Unwrap always looks
up that exact version, regardless of which one is "current" at the time.

`SELECT pg_vault_tde_rotate_kek();` drives:

1. **prepare** — generates a fresh KEK as `<label>.v<current+1>`;
2. **rewrap** — every catalog DEK is unwrapped with the KEK version tagged
   in its own blob and re-wrapped with the new version, tagging the new
   blob accordingly (transactional catalog UPDATEs);
3. **commit** — purely an in-backend cache update (the new version is
   already durably on the token and every rewrapped row already carries its
   own version tag), so there is nothing left to make durable and no
   crash window: whatever the catalog transaction ends up committing is
   self-describing and always resolves to the right KEK.

Because no KEK generation is ever renamed or destroyed, a crash or a rolled
back rotation at any point simply leaves an unused `<label>.v<N+1>` key on
the token (harmless — the next rotation attempt reuses or supersedes it)
with the catalog untouched, still tagged with the old version and still
fully readable.

**Cross-backend propagation.** `commit_kek_rotation` only updates the
cache of the ONE backend that ran `pg_vault_tde_rotate_kek()`. Without more,
every OTHER already-connected backend would keep wrapping new DEKs under
the pre-rotation KEK indefinitely. A small shared-memory beacon (one
`LWLock` + a `uint32` KEK version, same dynamic-tranche pattern as the
Vault token cache) fixes this: `commit_kek_rotation` (and the initial
keygen) publish the new version there; every backend checks it
opportunistically on its own next wrap/unwrap/rewrap call and, if stale,
resolves its own `CK_OBJECT_HANDLE` locally via a label lookup. Only the
version NUMBER crosses the process boundary — never the object handle
itself, which PKCS#11 only guarantees meaningful within the session that
resolved it. Staleness for an already-attached backend is therefore bounded
by "its own next operation", not by wall-clock time or a reconnect.

### Testing with SoftHSM2

`tap/16_pkcs11.t` is fully self-contained: it provisions a throwaway
SoftHSM2 token in a tempdir (`SOFTHSM2_CONF` + `softhsm2-util
--init-token`, no root needed) and exercises keygen, round-trip, on-disk
ciphertext, restart, health check, KEK rotation, cross-backend rotation
propagation (a long-lived session picking up a rotation committed by a
different connection, via `background_psql`), and clean failure paths
(wrong token label, wrong PIN, unprovisioned key label, invalid
`pkcs11_library` path) — 19 assertions in total.
Run it via `make ci-pkcs11` (containerized) or `prove tap/16_pkcs11.t`
where the `softhsm2` package is installed; it skips itself otherwise.
`pkcs11-tool` (package `opensc`) is handy for inspecting the token:
`pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --list-objects`.

### Limitations

- The standalone backup tools (`pg_dump_tde`/`pg_restore_tde`) do not
  support `kms_provider = 'pkcs11'` yet; they exit with a clear error.
- `health_check()` may exceed its usual latency budget on first touch of
  a *network* HSM (the lazy attach performs the full login sequence).
- PKCS#11 labels are not unique: keep exactly one KEK under
  `pkcs11_key_label` (the provider warns and picks the first match).

---

## Known Limitations

### Current Limitations (v1.7 — Current Release)

| # | Limitation | Fix Version |
|---|-----------|-------------|
| 1 | **TOAST chunk-level storage encryption** — ✅ **Resolved in v1.6**: large values round-trip fully encrypted via `pg_vault_tde_toast_am` returning `encrypted_heap` AM. Disable with `pg_vault_tde.toast_encryption = off` for legacy behaviour. | v1.6 ✅ |
| 2 | **tde_btree fixed-size types plaintext index keys** — ✅ **Resolved in v1.7**: `int4`, `int8`, `uuid`, `date`, `timestamptz` btree index keys are now encrypted with AES-256-SIV, matching varlena type behaviour. | v1.7 ✅ |
| 3 | **Logical replication of TOAST columns** — ✅ **Resolved in v1.7** via the custom WAL resource manager (enable `pg_vault_tde.toast_custom_rmgr`). UPDATE/DELETE require `REPLICA IDENTITY FULL` + a primary key; `REPLICA IDENTITY DEFAULT` and PK-less tables remain unsupported. See [Logical Decoding and Replication](#logical-decoding-and-replication). | v1.7 ✅ |
| 4 | **WAL unencrypted** — requires `XLogInsert()` hook unavailable in extension API | Permanently deferred |
| 5 | **All-or-nothing table encryption** — no per-column granularity | v1.8 |
| 6 | **Range scans on tde_btree** — `WHERE col > x` returns empty (AES-SIV not order-preserving) | By design, permanent |
| 7 | **BRIN on encrypted columns** — min/max of AES-SIV ciphertexts is meaningless | By design, permanent |
| 8 | **HOT updates disabled** — `heap_update` reject to use HOT updates because the wire format portion considerd by TupDesc for the comparison between old and new tuple is non-deterministic aka changes at every encryption | v1.8 ⚠️ |
| 9 | **`WITH HOLD` cursor plaintext temp file** — a held cursor's result set is materialized into a tuplestore at `COMMIT` and spills to a plain temp file on disk past `work_mem`, bypassing the TAM entirely; no extension hook exists anywhere in the `WITH HOLD` cursor lifecycle to intercept it. See README.md § Limitations item 6. | Permanently deferred |

### HOT updates are disabled by design (v4 IV-first wire format)

On an `encrypted_heap` table, `heap_update` never chooses a HOT (heap-only tuple)
update: every UPDATE writes new index entries. This is **intentional** and is what
keeps `tde_btree` indexes coherent across UPDATEs of indexed columns — the index always
follows the row to its new key, with no `REINDEX` needed.

**Mechanism.** `heap_update` decides whether an update can be HOT by comparing the
indexed columns byte-for-byte between the old and new tuple image. On an `encrypted_heap`
table both images are the encrypted wire format. The v4 layout (see
[Wire Format per Encrypted Region](#wire-format-per-encrypted-region)) is **IV-first**:
it begins with the random GCM IV, which is freshly generated on every encryption. The
encrypted image therefore differs from **byte 0** for any re-encryption — including when
the plaintext is unchanged — so `heap_update` always sees the indexed column as modified
and skips the HOT path. The constant `[VERSION | GENERATION]` bytes were moved to the
**end** of the blob precisely so they fall outside the comparison window.

> **Historical note (v3 bug, fixed in v4).** The previous v3 format placed a constant
> `[VERSION(1)=0x03 | GENERATION(8)]` prefix *first*. An indexed column whose datum landed
> inside that 9-byte prefix — typically a leading fixed-width `int4`/`int8` key — looked
> *unchanged* to `heap_update`, which then chose a HOT update and silently skipped the
> index maintenance, leaving the index pointing at the old key. Moving the constant bytes
> to the trailer removed the byte-stable region and resolved the bug structurally; the
> workarounds that v3 required (`REINDEX`, or arranging the indexed column past the first
> 9 bytes) are no longer needed.

### Historical Limitations (v1.0) — Many Resolved Since

1. **TOAST encryption** (ticket #1) — ✅ **Resolved in 6**  
   `pg_vault_tde_toast_am` now returns `encrypted_heap` AM when
   `pg_vault_tde.toast_encryption = on` (default). Every TOAST chunk is
   encrypted individually using the parent relation's DEK.  The v1.0 behaviour
   (forced `HEAP_TABLE_AM_OID`) is available via `toast_encryption = off`.

2. **Row re-encryption after rotation** (ticket #2) — ✅ **Resolved**  
   `pg_vault_tde_rotate_online(relname, batch_size)` promotes the current DEK to
   `prev_dek` and bumps the per-relation generation; old-generation rows stay readable
   via `prev_dek` during the rotation window. `pg_vault_tde_reencrypt_table(regclass
   [, batch_size])` (implemented in `src/tam/pg_vault_tde_tam.c`) then rewrites every
   row to the new generation in batches, closing the window. A rotation background
   worker (`src/kms/pg_vault_tde_rotation_bgw.c`) can drive this automatically.

3. **Vault HTTP connector** (ticket #3) — ✅ **Resolved**  
   The libcurl-based Vault/OpenBao Transit integration is fully implemented in
   `src/kms/pg_vault_tde_kms.c` (`vault_provider_wrap_dek()` /
   `vault_provider_unwrap_dek()` / `vault_provider_rewrap_dek()`, synchronous via
   `vault_transit_request()`). Supports token, AppRole, and Kubernetes JWT auth.

4. **multi_insert / COPY throughput** (ticket #4)
   The `multi_insert` callback encrypts per-slot and calls `heap_insert`
   in a loop, forfeiting WAL-batching optimizations. This degrades COPY
   workloads by roughly the single-insert overhead multiplied by batch size.
   Batch-encrypted `heap_multi_insert` is targeted for v1.1.

5. **Logical replication** (ticket #5) — ✅ **Resolved** (non-TOAST in v1.2,
   TOAST columns in v1.7)  
   The `pg_vault_tde_pgoutput` plugin decrypts tuples before publishing to
   subscribers; the custom WAL resource manager
   (`pg_vault_tde.toast_custom_rmgr`) extends this to externally-TOASTed
   columns. See [Logical Decoding and Replication](#logical-decoding-and-replication).

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
| `pg_vault_tde_rotate_online()` | Per-relation shmem DEK `OPENSSL_cleanse`d; generation incremented |
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
│                                                                    │
│  ┌─────────────────────────────┬─────────────────────────────────┐ │
│  │  HeapTupleHeaderData        │IV(12)│CT│TAG(16)│VER(1)│GEN(8)│ │
│  │  (t_hoff bytes, PLAINTEXT)  │                                 │ │
│  └─────────────────────────────┴─────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

### Constants

| Constant | Value | Defined in |
|---|---|---|
| `TDE_GCM_IV_LEN` | 12 | `pg_vault_tde_crypto.h` |
| `TDE_GCM_TAG_LEN` | 16 | `pg_vault_tde_crypto.h` |
| `TDE_V4_VERSION_BYTE` | `0x04` | `pg_vault_tde_crypto.h` |
| `TDE_V4_GEN_LEN` | 8 | `pg_vault_tde_crypto.h` |
| `TDE_V4_AAD_LEN` | 16 | `pg_vault_tde_crypto.h` (`dboid` + `relid` + `generation`) |
| `TDE_V4_OVERHEAD` | 37 | `pg_vault_tde_crypto.h` (= 12 + 16 + 1 + 8) |
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

### GUC Parameters

All parameters are in the `pg_vault_tde` namespace and are registered in
`_PG_init` via `DefineCustomXxxVariable`.

**Context**: all KMS-related parameters are `PGC_SUSET` — superusers can set
  them at session level or scope them to individual databases with
  `ALTER DATABASE SET` / `ALTER ROLE SET`.  No server restart is needed.
  The exceptions are `max_encrypted_relations` (controls shared-memory
  sizing, `PGC_POSTMASTER`), `crypto_provider` (OpenSSL provider selection,
  `PGC_POSTMASTER`), and `enabled` (master crypto switch, `PGC_POSTMASTER` —
  its value is baked into the on-disk wire format, so it cannot be toggled
  without risking silent plaintext/ciphertext mismatches; see the `enabled`
  row below).


#### Per-Database KMS Configuration

Because all GUCs are `PGC_SUSET`, each database in the same PostgreSQL cluster
can independently select its KMS backend and credentials.  This is the primary
mechanism for multi-tenant key isolation:

```sql
-- cluster-wide default (postgresql.conf or ALTER SYSTEM)
-- pg_vault_tde.kms_provider = 'vault'

-- tenant_a: dedicated Transit key, no change to other settings
ALTER DATABASE tenant_a SET pg_vault_tde.vault_key_name     = 'tde-dek-a';
ALTER DATABASE tenant_a SET pg_vault_tde.vault_transit_mount = 'transit-tenants';

-- tenant_b: offline local wallet, completely different backend
ALTER DATABASE tenant_b SET pg_vault_tde.kms_provider          = 'local';
ALTER DATABASE tenant_b SET pg_vault_tde.wallet_passphrase_env  = 'TDE_WALLET_B';

-- verify effective configuration
\connect tenant_b
SHOW pg_vault_tde.kms_provider;   -- 'local'
SELECT * FROM pg_vault_tde_health_check();
```

Settings applied with `ALTER DATABASE SET` take effect for new connections to
that database.  The provider is selected per-connection from the effective GUC
value; no shared state is changed.

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `kms_provider` | string | `''` (unset — must be configured) | suset | Active KMS backend: `vault`, `local` (v1.6). Settable per-database. |
| `vault_url` | string | `''` | suset | Vault / OpenBao base URL |
| `vault_namespace` | string | `''` | suset | Vault namespace (enterprise; empty for community) |
| `vault_auth_method` | string | `token` | suset | Vault auth method: `token`, `approle`, or `kubernetes` |
| `vault_token` | string | `''` | suset | Auth token — hidden from `pg_settings` (`GUC_NOT_IN_SAMPLE`) |
| `vault_role_id` | string | `''` | suset | AppRole role_id UUID — hidden from `pg_settings` |
| `vault_secret_id` | string | `''` | suset | AppRole secret_id — hidden from `pg_settings` |
| `vault_role_name` | string | `''` | suset | AppRole role name for secret_id rotation **(v1.4)** — calls `secret-id/destroy` after login |
| `vault_k8s_role` | string | `''` | suset | Kubernetes JWT auth role name |
| `vault_k8s_mount` | string | `kubernetes` | suset | Kubernetes auth engine mount path |
| `vault_transit_mount` | string | `transit` | suset | Transit secrets engine mount path |
| `vault_key_name` | string | `pg-tde-dek` | suset | Transit key name for DEK wrapping. Override per-database to isolate tenant keys. |
| `vault_ca_cert` | string | `''` | suset | Path to CA bundle for Vault TLS (`CURLOPT_CAINFO`) |
| `vault_timeout_ms` | integer | `5000` | suset | Vault HTTP timeout in ms (0 = no timeout; range 0–300000) |
| `wallet_path` | string | `/var/lib/pg_vault_tde/<OID>/wallet.p12` | suset | Local wallet PKCS#12 path (`kms_provider = 'local'`) |
| `wallet_passphrase_env` | string | `''` | suset | Env var NAME holding the wallet passphrase |
| `wallet_passphrase_file` | string | `''` | suset | File path containing the wallet passphrase (mode 0400 enforced) |
| `wallet_passphrase_command` | string | `''` | suset | Shell command whose stdout is the passphrase (highest priority) |
| `wallet_auto_open` | boolean | `on` | suset | Auto-open wallet at startup if passphrase env var is set |
| `dev_mode` | boolean | `off` | suset | Enable development-only conveniences (insecure in production) |
| `wallet_dev_mode_passphrase` | string | `''` | suset | Inline dev passphrase, used only when `dev_mode = on`; emits a `WARNING` on every use — hidden from `pg_settings` |
| `dek_cache_ttl` | integer | `0` | suset | Per-backend DEK cache TTL in seconds (0 = no expiry; range 0–86400). When > 0, each backend re-reads the DEK from shmem after this interval even without rotation |
| `toast_encryption` | boolean | `on` | suset | Encrypt TOAST chunks with the parent relation's DEK |
| `bgw_enabled` | boolean | `off` | suset | Enable background worker for automatic token renewal. **Requires cluster restart**: the BGW is registered via `RegisterBackgroundWorker()` at postmaster startup; changing via `pg_reload_conf()` updates the value but does not start/stop the worker dynamically. |
| `token_renewal_interval` | integer | `3600` | suset | Token renewal interval in seconds (60–86400) |
| `enabled` | boolean | `on` | postmaster | Master switch: `off` disables crypto for benchmarking overhead. Fixed at server startup |
| `max_encrypted_relations` | integer | `1024` | postmaster | Max per-table DEK entries in shmem (64–65536). **Requires restart** — controls shared-memory allocation. |
| `crypto_provider` | string | `''` | postmaster | OpenSSL 3.x provider name (`qatprovider`, `fips`; empty = built-in dispatch). **Requires restart**. |

All variables are declared `extern` in `src/include/pg_vault_tde_guc.h`
and included by any translation unit that needs them (`tam.c`, `kms.c`).

---

## Extension Initialization

### _PG_init Sequence

```
_PG_init()
  ├── DefineCustomStringVariable("pg_vault_tde.vault_url", ...)      [PGC_SUSET]
  ├── DefineCustomStringVariable("pg_vault_tde.vault_token", ...)    [PGC_SUSET, GUC_NOT_IN_SAMPLE]
  ├── ... ~20 more GUC parameters (all PGC_SUSET except max_encrypted_relations/crypto_provider/enabled) ...
  ├── install shmem_request_hook  → pg_vault_tde_shmem_request()
  │       ├── pg_vault_tde_kms_shmem_request()
  │       │       └── RequestAddinShmemSpace(sizeof(pg_vault_tde_kms_cache))
  │       └── pg_vault_tde_catalog_shmem_request()
  │               ├── RequestAddinShmemSpace(tde_rel_dek_cache_size(capacity))
  │               └── RequestNamedLWLockTranche("TdeRelDekMap", 1)
  ├── install shmem_startup_hook  → pg_vault_tde_shmem_startup()
  │       ├── pg_vault_tde_kms_shmem_init()       (Vault-token cache)
  │       │       ├── ShmemInitStruct("pg_vault_tde_kms_cache", ..., &found)
  │       │       └── if !found: LWLockNewTrancheId() + LWLockInitialize()
  │       │                      ← dynamic tranche; requires shmem to be up!
  │       ├── pg_vault_tde_catalog_shmem_init()   (per-relation DEK cache)
  │       │       ├── ShmemInitHash("TdeRelDekMap", capacity, capacity, ...)
  │       │       └── rel_dek_lock = &GetNamedLWLockTranche("TdeRelDekMap")[0].lock
  │       └── tde_shmem_started = true; tde_active_kms_provider->init()
  ├── pg_vault_tde_tam_init()
  │       └── memcpy(&tde_methods, GetHeapamTableAmRoutine(), sizeof(TableAmRoutine))
  │           + install 5 write + 8 read + 2 visibility/build + 2 rewrite AM wrappers
  └── register on_proc_exit(tde_backend_cleanup)
          ├── tde_crypto_ctx_cleanup()   ← EVP_CIPHER_CTX_free + OPENSSL_cleanse iv_batch
          └── tde_iam_ctx_cleanup()      ← EVP_CIPHER_CTX_free SIV enc/dec context
```

#### Critical: Why LWLockNewTrancheId cannot be called from _PG_init

In PostgreSQL 17+, `LWLockNewTrancheId()` acquires
`WaitEventCustomCounterLock`, a spinlock stored **in shared memory**.
Shared memory does not exist at `_PG_init` time, so calling
`LWLockNewTrancheId()` from `_PG_init` causes an immediate segfault. The two
shmem structs use two different (both correct) tranche strategies:

- **`pg_vault_tde_kms_cache`** (dynamic tranche): `RequestAddinShmemSpace()`
  in `shmem_request_hook`; `LWLockNewTrancheId()` + `LWLockInitialize()` in the
  `shmem_startup_hook` `!found` branch.
- **`TdeRelDekMap`** (named tranche): `RequestAddinShmemSpace()` **and**
  `RequestNamedLWLockTranche("TdeRelDekMap", 1)` in `shmem_request_hook`
  (named-tranche *requests* are allowed there — only `LWLockNewTrancheId()` is
  not), then `GetNamedLWLockTranche("TdeRelDekMap")` in `shmem_startup_hook`
  (the HTAB and its lock are created by `ShmemInitHash` / picked up from the
  tranche; no `LWLockInitialize()` needed for a named-tranche lock).

This is the correct pattern for all PG17+ / PG18 extensions that need a
dynamic LWLock tranche.

---

## Testing Strategy

### Regression Tests

`make ci-regress` (driven by `ci/scripts/run-regress.sh`) runs four SQL files in
sequence, gated on the live extension version:

| File | Tests | Scope |
|---|---|---|
| `sql/regression_test.sql` | 1–52 | v1.0–v1.4 baseline: crypto, TAM, TOAST, tde_btree |
| `sql/regression_test_v15.sql` | 53–72 | v1.5: per-table DEK, online rotation, AAD |
| `sql/regression_test_v16.sql` | 73–109 | v1.6: local wallet KMS |
| `sql/regression_test_v17.sql` | 111–134 | v1.7: `enc_ops` indexes, partition trees, HOT/REINDEX, FK lifecycle, TidRangeScan|

Test 110 (`WITH HOLD` cursor spill) is permanently deferred. The full suite is therefore
**134 tests**. The table below details the v1.0–v1.4 baseline file:

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

### Pre-installation requirement: wallet base directory

Before the extension can initialise a local wallet, the base directory
`/var/lib/pg_vault_tde/` must exist and be owned by the OS user that runs
PostgreSQL (typically `postgres`).  The directory must **not** be inside
`PGDATA` — see [Security Considerations](#security-considerations).

The package installers (postinst / %pre) create it automatically.  For
bare source builds or container images, run once as root:

```bash
mkdir -p /var/lib/pg_vault_tde
chown postgres:postgres /var/lib/pg_vault_tde
chmod 0700 /var/lib/pg_vault_tde
```

`pg_vault_tde_wallet_init()` creates the per-database subdirectory
(`/var/lib/pg_vault_tde/<db_oid>/`) at runtime; it does **not** create
the base directory.  If the base directory is missing the function fails
with an actionable error and hint.

### DEB (Debian / Ubuntu)

```bash
# Build
bash packaging/build_deb.sh --no-sign

# Install (creates /var/lib/pg_vault_tde via postinst)
dpkg -i ../postgresql-18-pg-vault-tde_1.0-1_amd64.deb

# Verify
dpkg -l | grep pg-vault-tde
```

### RPM (RHEL / Rocky / Fedora)

```bash
# Build
bash packaging/build_rpm.sh

# Install (creates /var/lib/pg_vault_tde via %pre scriptlet)
dnf install ~/rpmbuild/RPMS/x86_64/postgresql18-pg_vault_tde-1.0-1.*.rpm

# Verify
rpm -qi postgresql18-pg_vault_tde
```

### Hardware Acceleration

There is a single build/package — no `TDE_TARGET_ARCH` variant. Hardware-
accelerated AES dispatch (AES-NI, VAES, ARM CE, SVE2) is provided by
OpenSSL's EVP layer automatically at runtime on this one build; see
"Hardware acceleration" above and `src/crypto/pg_vault_tde_hw_accel.c`.
A previous version of this codebase shipped `TDE_TARGET_ARCH`-selected
compiler flags and matching `-aesni`/`-vaes`/`-armce` package variants, but
none of the corresponding preprocessor defines (`TDE_HW_AES_NI`,
`TDE_HW_VAES`, `TDE_HW_ARM_CE`, `TDE_HW_ARM_SVE2`) were ever referenced by
any `#ifdef`/`#if defined` in `src/`, so those variants never produced a
measurably faster `.so` — they were removed.

### Version Matrix

| pg_vault_tde | PostgreSQL | OpenSSL | Status |
|---|---|---|---|
| 1.6.x | 17.x, 18.x | 3.x | ✅ Completed |
| 1.7.x | 17.x, 18.x | 3.x | 🔄 Current |
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
| **v1.6** | Local Wallet KMS (production-ready) | ✅ Completed | 109 |
| **v1.7** | Per-database KMS + pg_restore_tde + PGC_SUSET + enc_ops indexes | 🔄 Current | 127 |
| **v1.8** | TOAST Chunks + HSM + Audit | 📋 Q4 2027 | ~100 |
| **v1.9** | KMIP + Column-Level + HA | 📋 Q2 2028 | ~130 |

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
- Pass the full 127-test regression suite (`make ci-regress`)
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
