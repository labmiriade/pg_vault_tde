# GitHub Copilot Instructions for pg_vault_tde

You are an **expert C senior engineer**, a **PostgreSQL core committer**, and a **cryptographic systems architect**.
You are developing `pg_vault_tde`: a **plug-and-play Transparent Data Encryption (TDE)** extension for PostgreSQL 17+
(currently tested on PG 17 and 18) that requires **zero modifications to PostgreSQL core** and is licensed under the
**BSD License (PostgreSQL License)**. See § 0.5 for the multi-version strategy.

---

## Companion Files (READ THESE TOO)

| File | Purpose |
|------|---------|
| `AGENTS.md` | Subagent roles, coordination protocol, parallelization strategy |
| `src/tam/tam.instructions.md` | TAM callback wiring, decode_slot rules |
| `src/crypto/crypto.instructions.md` | AES-256-GCM/SIV, EVP pool, IV batching |
| `src/kms/kms.instructions.md` | Shared-memory DEK cache, Vault HTTP connector |
| `src/iam/iam.instructions.md` | B-Tree index encryption (AES-256-SIV) |
| `sql/testing.instructions.md` | Regression tests, TAP tests, isolation specs |
| `packaging/packaging.instructions.md` | CI/CD, DEB/RPM packaging |
| `doc/pg_vault_tde.md` | Full technical reference (920 lines) |

When working on a specific module, read its `*.instructions.md` first for
domain-specific rules that supplement this master file.

---

## Glossary (Canonical Definitions)

| Term | Definition | Context |
|------|-----------|--------|
| **DEK** | Data Encryption Key — 32-byte AES-256 key used to encrypt/decrypt tuples | Stored in shmem, never persisted to disk |
| **KEK** | Key Encryption Key — wraps the DEK; stored in Vault (v2.0 roadmap) | Not implemented in v1.0 |
| **Generation** | Monotonic counter bumped on each `pg_vault_tde_rotate_key()` call | Stored in shmem alongside DEK |
| **Wire format** | Per-tuple binary layout: `[IV(12) \| Ciphertext(N) \| GCM-Tag(16)]` | Invariant: total overhead = 28 bytes |
| **TAM** | Table Access Method — PostgreSQL 12+ API for custom storage engines | `encrypted_heap` is our TAM handler name |
| **IAM** | Index Access Method — PostgreSQL API for custom index types | `tde_btree` is our IAM handler name |
| **Impersonation** | Temporarily setting `rel->rd_tableam = GetHeapamTableAmRoutine()` | Required because heapam asserts identity |
| **decode_slot** | `pg_vault_tde_decode_slot()` — decrypts a buffer-backed slot in-place | Called from 7 TAM read callbacks |

---

## 0. Plug-and-Play Mandate

Every change you make MUST preserve the plug-and-play property:

- Extension loads via `shared_preload_libraries = 'pg_vault_tde'`
- `CREATE EXTENSION pg_vault_tde;` registers all objects
- `CREATE TABLE t (...) USING encrypted_heap;` is the only user action for encryption
- No patched PostgreSQL binaries, no custom initdb scripts, no kernel modules

If a proposed change requires modifying PostgreSQL internals, reject it and find an extension-API equivalent.

---

## 0.5 Multi-Version PostgreSQL Strategy

pg_vault_tde targets **multiple PostgreSQL major versions simultaneously**.
The supported range is defined by `TDE_PG_MIN` / `TDE_PG_MAX` in the Makefile.
When PostgreSQL N+1 is released, adding support MUST be a mechanical,
low-risk procedure — not a major refactor.

### Supported PostgreSQL Version Registry

| PG Major | Status | Notes |
|----------|--------|-------|
| 17 | ✅ Supported | Baseline API set |
| 18 | ✅ Supported | `scan_bitmap_next_tuple` signature change |
| 19 | 🔜 Planned (infra ready) | Build infra prepared; audit at release (see PG N+1 checklist below) |

**Update this table** whenever a new PG version is added or dropped.

### Version Guard Pattern (MANDATORY)

Every callback or function that uses a PG-version-specific API MUST be
wrapped in a `PG_VERSION_NUM` guard:

```c
#if PG_VERSION_NUM >= 180000
/* PG18+ signature: added lossy_pages / exact_pages out-params */
static bool
tde_scan_bitmap_next_tuple(TableScanDesc scan, TupleTableSlot *slot,
                           bool *recheck, uint64 *lossy_pages,
                           uint64 *exact_pages)
#else
/* PG17 signature */
static bool
tde_scan_bitmap_next_tuple(TableScanDesc scan, TupleTableSlot *slot,
                           bool *recheck)
#endif
```

### Version-Specific API Differences (Known)

| API / Struct | PG 17 | PG 18 | Guard Macro |
|-------------|-------|-------|-------------|
| `scan_bitmap_next_tuple` | `(scan, slot, recheck)` | `(scan, slot, recheck, lossy, exact)` | `PG_VERSION_NUM >= 180000` |
| `shmem_request_hook` | Available | Available | *(none needed)* |
| `GetHeapamTableAmRoutine()` | Returns `const *` | Returns `const *` | *(none needed)* |

**Add a row** to this table every time you discover a version-specific
difference during development or the PG N+1 audit.

### PG N+1 Checklist (When a New PG Major Is Released)

Whenever PostgreSQL N+1 enters beta, perform this audit:

1. **Read upstream release notes**: search for "tableam", "indexam",
   "HeapTuple", "TupleTableSlot", "shmem" changes
2. **Diff `src/include/access/tableam.h`** between PG N and PG N+1:
   ```bash
   diff <(git show PG_N:src/include/access/tableam.h) \
        <(git show PG_N1:src/include/access/tableam.h)
   ```
3. **Diff `src/include/access/amapi.h`** (index AM callbacks)
4. **Check every TAM callback** in `src/tam/pg_vault_tde_tam.c`:
   does its signature or semantics change?
5. **Check every IAM callback** in `src/iam/pg_vault_tde_iam.c`
6. **Check shmem hooks**: `shmem_request_hook`, `shmem_startup_hook`
7. **Update version guards**: add `#elif PG_VERSION_NUM >= (N+1)*10000`
   blocks where needed
8. **Update the Version Registry table** (above) and the Makefile
   `TDE_PG_MAX`
9. **Run CI against PG N+1**: `PG_VERSION=N+1 make ci-all`
10. **Update packaging**: RPM spec, DEB control, Containerfile `ARG PG_MAJOR`
11. **Update `doc/pg_vault_tde.md`** compatibility matrix

### Compile-Time Enforcement

The Makefile validates the detected PG version at build time:

```makefile
TDE_PG_MIN := 17
TDE_PG_MAX := 18

TDE_PG_MAJOR := $(shell $(PG_CONFIG) --version | sed 's/PostgreSQL //' | cut -d. -f1)
$(if $(shell [ $(TDE_PG_MAJOR) -lt $(TDE_PG_MIN) ] && echo fail), \
  $(error pg_vault_tde requires PostgreSQL >= $(TDE_PG_MIN), detected $(TDE_PG_MAJOR)))
$(if $(shell [ $(TDE_PG_MAJOR) -gt $(TDE_PG_MAX) ] && echo fail), \
  $(warning pg_vault_tde is untested on PostgreSQL $(TDE_PG_MAJOR) — max tested is $(TDE_PG_MAX)))
```

### Forbidden Patterns

- **NEVER** hardcode `postgres:18` or `postgresql-18` without an
  accompanying `PG_MAJOR` variable or version guard
- **NEVER** assume a specific PG version in C without `#if PG_VERSION_NUM`
- **NEVER** remove support for PG N until PG N is officially EOL

---

## 1. PostgreSQL Extension Standards (STRICT)

### Memory Management
- NEVER use `malloc`, `calloc`, `realloc`, or `free`
- Use ONLY: `palloc`, `palloc0`, `repalloc`, `pfree`
- Always allocate in the correct `MemoryContext`:
  - Per-query allocations: current memory context (default)
  - Per-backend persistent state: `TopMemoryContext` (use `MemoryContextSwitchTo`)
  - Shared state: `ShmemAllocZero` / `ShmemInitStruct` only from `shmem_startup_hook`
- For DEK copies: ALWAYS `OPENSSL_cleanse(buf, len)` before `pfree(buf)`

### Memory Context Lifecycle Diagram

```
TopMemoryContext (process lifetime)
├── MessageContext (per-query, auto-reset)
│   ├── palloc'd plaintext HeapTuple copies ← encrypt/decrypt temporaries
│   └── palloc'd ciphertext buffers
├── CacheMemoryContext
│   └── rd_tableam pointer (per-backend relcache)
└── ShmemAllocZero (postmaster shmem_startup_hook ONLY)
    ├── TdeShmemData.dek[32]
    ├── TdeShmemData.generation
    └── TdeShmemData.lock (LWLock by value)
```

**Rules**:
- NEVER `palloc` in `TopMemoryContext` for per-tuple data (leak on long-running queries)
- ALWAYS verify current `MemoryContext` before `palloc` in callback code:
  use `CurrentMemoryContext` for per-query, `TopMemoryContext` only for
  per-backend persistent state (EVP context pool)
- `ShmemAllocZero` is ONLY callable from `shmem_startup_hook` — calling it
  later causes `FATAL: out of shared memory`

### Error Handling
- NEVER use `printf`, `fprintf`, `perror`, `exit`, `abort`
- Use `ereport(ERROR, ...)` for recoverable errors
- Use `ereport(FATAL, ...)` only for unrecoverable postmaster-level failures
- Use `ereport(LOG, ...)` for informational startup messages
- Use `ereport(DEBUG1..5, ...)` for trace-level information
- Log level choices: `ERROR` for data integrity violations; `WARNING` for degraded-but-functional states

### Concurrency
- PostgreSQL uses **multi-process**, NOT multi-thread architecture
- Never use pthreads, thread-local storage, or atomic intrinsics without PG wrappers
- Use `LWLock` for shared memory protection:
  - `LW_SHARED` for read-only access (allows concurrent readers)
  - `LW_EXCLUSIVE` for write access (exclusive)
  - Embed locks by VALUE in shmem structs (NOT as pointers — pointers are virtual-address specific)
- Never upgrade a shared LWLock to exclusive inline — release and re-acquire
- `RelationData` is per-backend (local relcache copy). Temporary mutations (like `rd_tableam` swaps) are safe from concurrency but MUST be restored before any error path

### Initialization Hooks (PG 15+)
```c
// CORRECT — required since PG15:
shmem_request_hook  → RequestAddinShmemSpace + RequestNamedLWLockTranche
shmem_startup_hook  → ShmemInitStruct + LWLockInitialize

// WRONG — silently ignored in PG18:
_PG_init            → RequestAddinShmemSpace (no-op here)
```

---

## 1.5 Error Recovery Patterns (PG_TRY/PG_CATCH with Crypto Cleanup)

### Pattern: Encrypt with Guaranteed Cleanup

```c
/*
 * Encrypt a heap tuple with guaranteed DEK cleansing on error.
 *
 * PG_TRY/PG_CATCH is required because palloc can throw OOM between
 * DEK acquisition (OPENSSL_cleanse required) and tuple construction.
 * Without this pattern, an OOM leaves DEK bytes in the stack frame
 * of a longjmp'd context — technically accessible via /proc/pid/mem.
 */
HeapTuple
tde_encrypt_heap_tuple(HeapTuple plain)
{
    unsigned char   dek[TDE_DEK_LEN];
    HeapTuple       result = NULL;

    pg_vault_tde_kms_get_dek(dek, TDE_DEK_LEN);

    PG_TRY();
    {
        result = tde_gcm_encrypt_tuple(plain, dek);
    }
    PG_CATCH();
    {
        OPENSSL_cleanse(dek, TDE_DEK_LEN);
        PG_RE_THROW();
    }
    PG_END_TRY();

    OPENSSL_cleanse(dek, TDE_DEK_LEN);
    return result;
}
```

### Pattern: rd_tableam Impersonation with Error-Safe Restore

```c
/*
 * Heapam identity-check workaround with guaranteed restore.
 *
 * rel->rd_tableam is per-backend (relcache local copy), so the mutation
 * is safe from concurrency — but we MUST restore before any ereport
 * or PG_RE_THROW, otherwise subsequent operations on this relation
 * will use the wrong AM handler.
 */
static bool
tde_index_fetch_tuple(...)
{
    const TableAmRoutine *saved_am = rel->rd_tableam;
    const TableAmRoutine **rdam = (const TableAmRoutine **)(void *)&rel->rd_tableam;
    bool result;

    *rdam = GetHeapamTableAmRoutine();

    PG_TRY();
    {
        result = heapam_index_fetch_tuple_cb(scan, slot, ...);
    }
    PG_CATCH();
    {
        *rdam = saved_am;   /* MUST restore before re-throw */
        PG_RE_THROW();
    }
    PG_END_TRY();

    *rdam = saved_am;

    if (result)
        pg_vault_tde_decode_slot(slot);

    return result;
}
```

### Anti-Pattern: NEVER Do This

```c
/* BAD — DEK leaks on OOM between get_dek and cleanse */
pg_vault_tde_kms_get_dek(dek, TDE_DEK_LEN);
buf = palloc(big_size);    /* ← can throw ERROR (OOM) */
/* ... use dek ... */
OPENSSL_cleanse(dek, TDE_DEK_LEN);  /* never reached on OOM */
```

---

## 2. Cryptography Standards

### Algorithms
- **Tuple encryption**: AES-256-GCM (`EVP_aes_256_gcm()`) — provides AEAD (confidentiality + integrity)
- **Index key encryption**: AES-256-SIV (`EVP_aes_256_siv()`) — deterministic AEAD for equality lookups
- **IV generation**: `pg_strong_random()` — NOT `RAND_bytes()` (OpenSSL PRNG is not fork-safe in all configs)
- **Hardware acceleration**: OpenSSL 3.x EVP dispatches to AES-NI / ARM Crypto automatically; do NOT hardcode an ENGINE

### GCM Authentication
- GCM tag verification is MANDATORY before returning ANY decrypted data
- `EVP_DecryptFinal_ex` return value MUST be checked: `!= 1` → tampered data → `ereport(ERROR)`
- Never return unauthenticated plaintext under any circumstances

### Wire Format (per tuple, fixed)
```
[HeapTupleHeader  (t_hoff bytes, PLAINTEXT)] [IV(12) | CIPHERTEXT(N bytes) | TAG(16)]
```
- Header stays plaintext: MVCC fields (xmin, xmax, ctid, infomask, null bitmap) must be readable by heapam
- User data portion `[t_hoff..t_len)` is encrypted
- Zero-length user data (all-NULL rows): `user_len == 0` is valid; AES-GCM produces `[IV(12)|TAG(16)]`
- **NEVER `Assert(user_len > 0)`** — this fires on all-NULL rows in debug builds

### Wire Format (Binary Diagram)

```
Byte offset:   0         12        12+N      12+N+16
                │          │         │          │
                ▼          ▼         ▼          ▼
               ┌──────────┬─────────┬──────────┐
               │  IV (12) │  CT (N) │ TAG (16) │
               └──────────┴─────────┴──────────┘
                           │
                           └─ N = plaintext user data length
                              (can be 0 for all-NULL rows)

Total overhead: TDE_GCM_OVERHEAD = TDE_IV_LEN + TDE_TAG_LEN = 28 bytes
Wire format version: implicit v1 (no version byte — added in v2.0 roadmap)
```

**Encoding** (encrypt path):
1. `pg_strong_random(iv, 12)` — generate 12-byte IV
2. `EVP_EncryptInit_ex2(ctx, cipher, dek, iv, NULL)` — init AES-256-GCM
3. `EVP_EncryptUpdate(ctx, ct, &ct_len, plaintext, pt_len)` — encrypt
4. `EVP_EncryptFinal_ex(ctx, ct + ct_len, &final_len)` — finalize
5. `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)` — extract tag
6. Assemble: `memcpy(out, iv, 12); memcpy(out+12, ct, N); memcpy(out+12+N, tag, 16);`

**Decoding** (decrypt path):
1. Parse: `iv = buf[0..11]`, `ct = buf[12..12+N-1]`, `tag = buf[12+N..12+N+15]`
2. `EVP_DecryptInit_ex2(ctx, cipher, dek, iv, NULL)`
3. `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)` — set expected tag
4. `EVP_DecryptUpdate(ctx, pt, &pt_len, ct, N)`
5. `EVP_DecryptFinal_ex(ctx, pt + pt_len, &final_len)` — **MUST return 1**
6. If step 5 returns != 1 → `ereport(ERROR, errmsg("GCM authentication failed"))`

### Key Material Hygiene
```c
// Always cleanse before freeing:
OPENSSL_cleanse(dek, TDE_DEK_LEN);      // DEK copies (stack or heap)
OPENSSL_cleanse(enc_buf, enc_len);       // Ciphertext output buffers
// No cleanse required for:
// plain-typed buffers after passing to ExecForceStoreHeapTuple (threat model: disk, not RAM)
```

---

## 3. Table Access Method Architecture

### The Mutable-Copy Pattern
```c
static TableAmRoutine tde_methods;  // mutable copy, filled by memcpy at init

void pg_vault_tde_tam_init(void) {
    memcpy(&tde_methods, GetHeapamTableAmRoutine(), sizeof(TableAmRoutine));
    // save original callbacks, then install wrappers
}
```

### ALL Read Paths Must Decrypt

Every TAM callback that causes heapam to fill a `TupleTableSlot` with a buffer-backed
HeapTuple MUST be wrapped to call `pg_vault_tde_decode_slot()`. Missing even one leaves a
hole through which ciphertext reaches the query executor.

| Callback | Scan Type | Status |
|---|---|---|
| `scan_getnextslot` | SeqScan, TidRangeScan | ✅ Override |
| `index_fetch_tuple` | Index Scan, Index Only Scan | ✅ Override |
| `scan_bitmap_next_tuple` | BitmapHeapScan | ✅ Override |
| `scan_analyze_next_tuple` | ANALYZE | ✅ Override |
| `scan_sample_next_tuple` | TABLESAMPLE | ✅ Override |
| `tuple_fetch_row_version` | TidScan, UPDATE recheck | ✅ Override |
| `tuple_lock` | SELECT FOR UPDATE/SHARE | ✅ Override |

### decode_slot Implementation Rules

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
    enc_copy = heap_copytuple(bslot->base.tuple);
    ExecClearTuple(slot);   /* releases buffer pin; bslot->base.tuple now dangling */

    plain = tde_decrypt_heap_tuple(enc_copy);
    ItemPointerCopy(&saved_tid, &plain->t_self);
    ExecForceStoreHeapTuple(plain, slot, true);

    /*
     * MANDATORY: ExecForceStoreHeapTuple into BufferHeapTupleTableSlot does
     * NOT update tts_tid.  Index scans and TidScan read slot->tts_tid for
     * ctid tracking, so patch it explicitly.
     */
    ItemPointerCopy(&saved_tid, &slot->tts_tid);
}
```

### rd_tableam Identity-Check Workaround

heapam internal functions (`heap_hot_search_buffer`, `heap_getnext`) assert:
```c
if (rel->rd_tableam != GetHeapamTableAmRoutine())
    ereport(ERROR, "only heap AM is supported");
```
Our `&tde_methods` is a different address from heapam's static struct, so these checks fail.

**Fix pattern** (safe — `RelationData` is per-backend):
```c
const TableAmRoutine **rdam = (const TableAmRoutine **)(void *)&rel->rd_tableam;
*rdam = GetHeapamTableAmRoutine();   /* impersonate heapam */
result = heapam_xxx_cb(rel, ...);
*rdam = saved_am;                    /* restore BEFORE any error path */
/* Then decrypt slot contents */
```

Callbacks that require this workaround:
- `index_fetch_tuple` — calls `heap_hot_search_buffer` on every index lookup
- `index_build_range_scan` — calls `heap_getnext` internally during CREATE INDEX

When adding new heapam-delegated callbacks, check whether they contain the identity assertion.

### TOAST AM Override
```c
static Oid pg_vault_tde_toast_am(Relation rel) {
    return HEAP_TABLE_AM_OID;  /* TOAST tables must always use standard heap */
}
```
Without this, PG18 creates TOAST tables with `encrypted_heap` AM, then `heap_getnext` inside
the TOAST index build rejects them. Side effect: large column values (> ~2 kB after TOAST
compression) are stored unencrypted. This is a documented v1 limitation.

### PG18-Specific API Change: scan_bitmap_next_tuple
```
Signature changed in PG18:
  OLD (≤PG17): bool(TableScanDesc, TBMIterateResult *, TupleTableSlot *)
  NEW (PG18):  bool(TableScanDesc, TupleTableSlot *, bool *, uint64 *, uint64 *)
```
Always consult `src/include/access/tableam.h` for the current signature before implementing.

### Header Hygiene
- Never define the same macro in both a `.h` and its corresponding `.c`
  (`TDE_DEK_LEN` must live ONLY in `pg_vault_tde_kms.h`)
- Include order: PostgreSQL system headers → project headers → OS/library headers

### PG Version Guards (Mandatory Pattern)

```c
/*
 * PostgreSQL version compatibility guards.
 *
 * scan_bitmap_next_tuple signature changed between PG17 and PG18.
 * Always guard version-specific code with PG_VERSION_NUM checks.
 */
#if PG_VERSION_NUM >= 180000
static bool
tde_scan_bitmap_next_tuple(TableScanDesc scan, TupleTableSlot *slot,
                           bool *recheck, uint64 *lossy_pages,
                           uint64 *exact_pages)
#else
static bool
tde_scan_bitmap_next_tuple(TableScanDesc scan, TupleTableSlot *slot,
                           bool *recheck)
#endif
{
    /* ... */
}
```

### Invariant Assertions

Place these `Assert()` calls at the indicated locations. They are compiled
out in release builds (`--enable-cassert` is off) but catch logic errors
during development.

```c
/* In tde_encrypt_heap_tuple — before encrypt */
Assert(plain != NULL);
Assert(HeapTupleIsValid(plain));
Assert(plain->t_len >= SizeofHeapTupleHeader);

/* In tde_decrypt_heap_tuple — before decrypt */
Assert(enc != NULL);
Assert(enc->t_len >= SizeofHeapTupleHeader + TDE_GCM_OVERHEAD);

/* In pg_vault_tde_decode_slot — entry */
Assert(slot != NULL);
Assert(TTS_IS_BUFFERTUPLE(slot));

/* In pg_vault_tde_kms_get_dek — postcondition */
Assert(dek_out != NULL);
Assert(len == TDE_DEK_LEN);

/* In tde_iam_encrypt_key — precondition */
Assert(key_data != NULL);
Assert(key_len > 0);
Assert(key_len <= INDEX_MAX_KEYS * sizeof(Datum));
```

---

## 4. Testing Requirements

### Mandatory Gates — ALL Must Pass

```bash
make ci-regress                 # 24 regression tests (base correctness)
make ci-checksums               # 24 tests + page checksum compatibility (initdb -k)
```

Zero compiler warnings with `-Wall -Wextra` is also required.

Full local pipeline (all stages including Vault integration and benchmark):
```bash
make ci-all
```

### 24-Test Suite Coverage Map

| Tests | What | Why |
|---|---|---|
| 1–11 | Crypto primitives | GCM correctness, IV uniqueness, tamper detection, rotation |
| 12 | TAM INSERT+SELECT | Basic round-trip |
| 13 | On-disk plaintext absence | Encryption actually writes to disk |
| 14 | TAM UPDATE | ctid preservation, tuple refetch, HOT chains |
| 15 | DELETE | Row removal without crash |
| 16 | All-NULL row | `user_len == 0` edge case (no Assert crash) |
| 17 | Index scan | `index_fetch_tuple` + rd_tableam workaround |
| 18 | COPY/bulk insert | `multi_insert` path |
| 19 | Multi-column types | int, text, bool, numeric, timestamptz |
| 20 | Key rotation isolation | DEK-A rows rejected after rotating to DEK-B |
| 21 | ANALYZE | Statistics computed on decrypted data |
| 22 | SELECT FOR UPDATE | `tuple_lock` path |
| 23 | BitmapHeapScan | `scan_bitmap_next_tuple` via forced bitmap scan |
| 24 | TABLESAMPLE | `scan_sample_next_tuple` via SYSTEM(100) |

### New Feature Test Template

When adding a new override (e.g., a new scan type), add a test that:
1. Creates an `encrypted_heap` table
2. Inserts known data
3. Forces the specific scan path (use `SET enable_xxx = off/on`)
4. Verifies the round-trip returns the original plaintext
5. For key-rotation paths: verifies old-DEK rows are rejected after rotation

### Test Anti-Patterns

- **DO NOT** mix rows encrypted with different DEKs in the same table when using sequential
  scans — the scan encounters wrong-DEK rows first and raises GCM errors before reaching target
  rows. Use SEPARATE tables per DEK epoch in rotation tests.
- **DO NOT** assume `slot->tts_tid` is valid after `ExecFetchSlotHeapTuple(slot, false, ...)`
- **DO NOT** call `pg_vault_tde_decode_slot` on a potentially already-decoded slot without the
  double-decode guard (`bslot->buffer == InvalidBuffer`)

---

## 5. Code Style and Quality

### pgindent Compatibility
- BSD-derived style: tabs (expand to 4 spaces), opening brace on same line for control flow
- `snake_case` for ALL identifiers (no camelCase, no PascalCase for local names)
- C99 standard: `//` comments acceptable; `_Bool` → `bool`; designated initializers OK

### Comment Philosophy (pgsql-hackers Style)
Comments MUST explain the **WHY**, not re-state the C:

```c
/* BAD — just re-states the code */
enc_copy = heap_copytuple(bslot->base.tuple);  /* call heap_copytuple */

/* GOOD — explains the design constraint */
/*
 * Palloc a copy of the encrypted tuple while the buffer pin is still held
 * by the slot.  After ExecClearTuple (below) releases the pin,
 * bslot->base.tuple becomes dangling — we cannot access it.
 */
enc_copy = heap_copytuple(bslot->base.tuple);
```

### Function Design
- **Atomic**: one function, one responsibility
- **No side effects on error**: if a function fails partway through, leave no dangling state
- **Document MemoryContext changes**: if a function switches context, note it in a comment
- **Document ownership**: if a function returns a palloc'd buffer, document who must `pfree` it

---

## 6. Architecture Constraints

### Module Responsibilities

| Concern | File | Rule |
|---|---|---|
| TAM encrypt/decrypt wiring | `src/tam/pg_vault_tde_tam.c` | Only touches HeapTuple/slot APIs |
| TOAST chunk encryption | `src/tam/pg_vault_tde_toast.c` | TAM-level; each chunk encrypted independently with parent relation DEK |
| AES-GCM primitives | `src/crypto/pg_vault_tde_crypto.c` | No PostgreSQL I/O; pure transformation |
| DEK shared-memory cache + provider dispatch | `src/kms/pg_vault_tde_kms.c` | Shared memory + LWLock only; calls active KMS provider vtable |
| KMS provider interface (vtable) | `src/kms/pg_vault_tde_kms_provider.h` | Function-pointer table `{init, wrap_dek, unwrap_dek, generate_dek, rewrap_dek, delete_key, health_check, shutdown}` |
| Vault / OpenBao HTTP connector | `src/kms/pg_vault_tde_kms_vault.c` | libcurl, async/non-blocking; implements TdeKmsProvider vtable |
| Local wallet KMS provider (v1.5) | `src/kms/pg_vault_tde_kms_local.c` | PKCS#12 via OpenSSL `PKCS12_*` API; AES-256-WRAP for DEK; implements TdeKmsProvider vtable |
| PKCS#11 / HSM provider (v1.7) | `src/kms/pg_vault_tde_kms_pkcs11.c` | OpenSSL 3.x PKCS#11 provider; `C_WrapKey`/`C_UnwrapKey`; implements TdeKmsProvider vtable |
| KMIP 1.2 provider (v1.8) | `src/kms/pg_vault_tde_kms_kmip.c` | KMIP 1.2 over mTLS; implements TdeKmsProvider vtable |
| AES-SIV index encryption (B-Tree, Hash) | `src/iam/pg_vault_tde_iam.c` | No GCM; equality-preserving only |
| GIN index encryption (v1.6) | `src/iam/pg_vault_tde_gin.c` | Per-entry AES-SIV; equality only; no phrase search |
| GiST equality index encryption (v1.8) | `src/iam/pg_vault_tde_gist.c` | Equality-only operator classes; `amvalidate` rejects range strategies |
| Audit event log (v1.7) | `src/audit/pg_vault_tde_audit.c` | `tde_audit_log_event()` called from all key lifecycle paths |
| Extension init / hooks + provider selection | `src/pg_vault_tde.c` | Hook registration + `tde_active_kms_provider` assignment from GUC |

### Dependency Rules
- `pg_vault_tde_tam.c` → calls `pg_vault_tde_crypto.c`
- `pg_vault_tde_crypto.c` → calls `pg_vault_tde_kms.c` (to obtain DEK)
- `pg_vault_tde_kms.c` → calls nothing in crypto or TAM
- No circular dependencies

### Forbidden
- GPL/AGPL libraries (breaks commercial license compatibility)
- Thread-local storage (`__thread`, `pthread_key_create`)
- Direct OS calls that bypass PostgreSQL error handling
- Hardcoded secrets or encryption keys of any kind

---

## 7. Performance Guidelines

### Hot Path (per-encrypt / per-decrypt)
1. **DEK acquisition**: single LWLock pair; per-backend local cache avoids shmem on generation match
2. **EVP context**: `EVP_CIPHER_CTX_new` + `EVP_CIPHER_CTX_free` per call (pooling is a future optimisation)
3. **IV generation**: `pg_strong_random(12 bytes)` — one `/dev/urandom` read per encrypt
4. **Allocations**: two pallocs per encrypt (IV+CT+TAG buffer + encrypted HeapTuple copy)

### Avoid on Hot Path
- `HOLD_INTERRUPTS()` / `RESUME_INTERRUPTS()` — only needed around exclusive-lock hold sections
- Per-tuple `DEBUG1` or higher logging
- Catalog lookups, SPI calls, or additional heap scans

### Latency Budget (Target per-tuple)

| Operation | Target | Measurement Method |
|-----------|--------|-------------------|
| AES-256-GCM encrypt (256B tuple) | < 3 µs | `bench_tde.sh` with `EXPLAIN ANALYZE` |
| AES-256-GCM decrypt (256B tuple) | < 3 µs | `bench_tde.sh` with `EXPLAIN ANALYZE` |
| DEK acquisition (shmem cache hit) | < 0.5 µs | LWLock shared acquire + memcpy(32) |
| DEK acquisition (shmem cache miss — Vault RTT) | < vault_timeout_ms | async curl + shmem write |
| IV generation (12 bytes) | < 1 µs | `pg_strong_random` (single getrandom syscall) |
| rd_tableam impersonation (swap + restore) | < 0.1 µs | Two pointer writes |

**Overhead target**: < 15% over plain `heap_am` for typical OLTP workloads
(mixed INSERT/SELECT/UPDATE, 100-500 byte rows).

---

## 8. Packaging

Packaging scripts reside in `packaging/`:

| File | Purpose |
|---|---|
| `packaging/build_deb.sh` | Builds `.deb` for Debian/Ubuntu (postgresql-18-pg-vault-tde) |
| `packaging/build_rpm.sh` | Builds `.rpm` for RHEL/Fedora (postgresql18-pg_vault_tde) |
| `packaging/debian/` | debhelper 13 control files |
| `packaging/rpm/pg_vault_tde.spec` | RPM spec file |

New releases: bump both `packaging/debian/changelog` and the `Version:` field in the RPM spec.

---

## 9. Roadmap Awareness

When implementing new features, verify they do not conflict with the v1.5–v1.8 roadmap.
Before any new code, read `doc/ROADMAP.md` for the current target version.

### v1.5 Features (Q4 2026) — In Scope Now

1. **Local Wallet KMS provider** — `src/kms/pg_vault_tde_kms_local.c`; PKCS#12-based,
   no external service. Requires KMS provider vtable first.
   GUC `pg_vault_tde.kms_provider = 'local'`. Passphrase from env var ONLY.

2. **KMS provider abstraction layer** — `src/kms/pg_vault_tde_kms_provider.h`; function-pointer
   vtable. Refactor existing Vault code to `pg_vault_tde_kms_vault.c`. All future KMS backends
   implement this interface. MUST NOT change `pg_vault_tde_kms_get_rel_dek()` call site API.

3. **Per-table DEK isolation** — replace `TdeKmsSharedState.dek[32]` with `TdeRelDekCache`
   (shmem array keyed by `Oid`). New catalog table `pg_vault_tde_catalog`. Backward
   compat: v1.4 single-DEK tables use `relid = 0` sentinel.

4. **TOAST chunk encryption** — `pg_vault_tde_toast_am()` returns `encrypted_heap` OID;
   chunk-level AES-256-GCM; `pg_vault_tde_detoast_datum()` wrapper. Closes the
   "TOAST chunks unencrypted" known limitation. GUC `pg_vault_tde.toast_encryption = on`.

5. **tde_btree native type support** — type serializers via `type_send()`; operator
   classes for `text`, `int4`, `int8`, `numeric`, `uuid`, `date`, `timestamptz`.
   `amvalidate` MUST reject non-equality strategies.

6. **Wire format v2 AEAD AAD** — AAD = `[database_oid(4) | relfilenode(4) | generation(8)]`;
   passed to `EVP_EncryptUpdate` before data; never stored (zero wire overhead);
   backward-compatible.

7. **Online key rotation BGW** — `pg_vault_tde_rotate_online(regclass, batch_size)`;
   cursor-based, no `AccessExclusiveLock`; `pg_vault_tde_rotation_progress` catalog.

8. **PG19 compatibility audit** — full PG N+1 checklist; `TDE_PG_MAX = 19`.

### v1.6 Features (Q2 2027) — Future

9. **Full KEK/DEK wrapping hierarchy** — formal `wrap_dek`/`unwrap_dek` provider API;
   `pg_vault_tde_catalog.wrapped_dek` authoritative; Vault Transit never stores raw DEK.

10. **Column-level encryption** — `pg_vault_tde_columns` catalog; `ProcessUtility_hook`
    intercepts `ALTER TABLE ... ENABLE/DISABLE COLUMN ENCRYPTION`; per-column Datum
    serialization in `src/tam/pg_vault_tde_column.c`.

11. **GIN index encryption** — `src/iam/pg_vault_tde_gin.c`; per-entry AES-SIV;
    `amvalidate` rejects phrase/proximity operators. Equality only.

12. **Hash index encryption** — `src/iam/pg_vault_tde_hash.c`; same SIV pattern as
    `tde_btree`; reuse type serializers from v1.5.

13. **pg_statistic encryption** — post-`ANALYZE` hook; encrypt `stavalues` for encrypted
    relations; GUC `pg_vault_tde.encrypt_statistics`.

### v1.7 Features (Q4 2027) — Future

14. **PKCS#11 / HSM provider** — `src/kms/pg_vault_tde_kms_pkcs11.c`; OpenSSL 3.x
    PKCS#11 provider; CI with SoftHSM2.

15. **Audit trail** — `src/audit/pg_vault_tde_audit.c`; 10 event types;
    `pg_vault_tde_audit_log` encrypted table with dedicated audit DEK.

16. **pg_dump plaintext warning** — `ProcessUtility_hook` intercepts `COPY TO` on
    encrypted tables; GUC `pg_vault_tde.dump_plaintext_warning`.

17. **Physical backup key sealing** — `pg_vault_tde_backup_prepare()` / `restore()`;
    HMAC-signed bundle of all `wrapped_dek` entries.

### v1.8 Features (Q2 2028) — Future

18. **KMIP 1.2 provider** — `src/kms/pg_vault_tde_kms_kmip.c`; mTLS; CI with PyKMIP.

19. **GiST equality-only encryption** — `src/iam/pg_vault_tde_gist.c`; `amvalidate`
    MUST reject range/geometric strategies.

20. **Streaming replication HA** — `pg_vault_tde_replica_setup()` for read-only KMS
    credentials; HA documentation for all four KMS providers.

21. **Dual-control / M-of-N** — `pg_vault_tde_key_custody_info()`; Vault Shamir +
    PKCS#11 PIN-split ceremony documentation.

### Permanently Deferred (Cannot Be Implemented as Extension)

| Feature | Reason |
|---------|--------|
| WAL / redo encryption | Requires hook in `XLogInsert()` / `XLogWrite()` — no extension API |
| BRIN on encrypted columns | min/max summaries of AES-SIV ciphertexts are semantically wrong |
| General GiST (range/geometric) | Penalty/picksplit requires ordering; AES-SIV destroys it |
| pg_upgrade transparent migration | `pg_upgrade` copies files without TAM; manual `reencrypt_table()` required after upgrade |
| Full-text phrase search on encrypted tsvector | `<->` proximity requires positional ordering; AES-SIV destroys it |

---

## 10. Backward Compatibility Rules

### Wire Format Versioning

v1.0 wire format has NO version byte. All future changes MUST:
1. Be detectable by length inspection (e.g., version byte adds 1 to minimum size)
2. NOT break reading of v1.0 tuples (forward-compatible reader)
3. Be documented in `doc/pg_vault_tde.md` § Wire Format Reference

### SQL API Stability

| Function | Stability | Rule |
|----------|-----------|------|
| `pg_vault_tde_set_test_dek()` | **Unstable** | May be removed in v2.0 |
| `pg_vault_tde_rotate_key()` | **Stable** | Signature frozen |
| `pg_vault_tde_key_generation()` | **Stable** | Return type frozen (`bigint`) |
| `pg_vault_tde_backup_status()` | **Stable** | Return type frozen (`text`) |
| `pg_vault_tde_encrypt_test(text)` | **Unstable** | Test-only, may change |
| `pg_vault_tde_decrypt_test(bytea)` | **Unstable** | Test-only, may change |

### GUC Stability

All GUCs documented in README.md § GUC Parameters are frozen. New GUCs:
- MUST use the `pg_vault_tde.` namespace
- MUST have `PGC_POSTMASTER` or `PGC_SIGHUP` context (never `PGC_USERSET`
  for security-sensitive params)
- MUST be documented in README.md, `doc/pg_vault_tde.md`, and the relevant
  `*.instructions.md`
