# Logical Decoding Output Plugin for pg_vault_tde — Technical Research Report

**Date**: 2026-02-28
**Author**: @Architect / @SecurityKMS research
**Status**: Research complete, ready for implementation

---

## 1. Executive Summary

The WAL sender process reads raw WAL records (`xl_heap_insert`, `xl_heap_update`,
`xl_heap_delete`) which contain the **on-disk tuple representation** — ciphertext
for `encrypted_heap` tables. The Table Access Method callbacks are **never invoked**
in the logical decoding path. A custom **output plugin** is required to intercept
tuples before they are sent to subscribers and decrypt them in-place.

**Key finding**: The output plugin API is **identical between PG17 and PG18** —
no version guards needed for logical decoding code.

---

## 2. Output Plugin API — Exact Signatures

### 2.1 Entry Point

The plugin entry point is `_PG_output_plugin_init`, looked up via `load_external_function()`:

```c
/*
 * From src/include/replication/output_plugin.h:
 *
 * Type of the shared library symbol _PG_output_plugin_init that is
 * looked up when loading an output plugin shared library.
 */
typedef void (*LogicalOutputPluginInit)(struct OutputPluginCallbacks *cb);

extern PGDLLEXPORT void _PG_output_plugin_init(struct OutputPluginCallbacks *cb);
```

The loading mechanism (`logical.c:LoadOutputPlugin`):
```c
static void
LoadOutputPlugin(OutputPluginCallbacks *callbacks, const char *plugin)
{
    LogicalOutputPluginInit plugin_init;

    plugin_init = (LogicalOutputPluginInit)
        load_external_function(plugin, "_PG_output_plugin_init", false, NULL);

    if (plugin_init == NULL)
        elog(ERROR, "output plugins have to declare the _PG_output_plugin_init symbol");

    plugin_init(callbacks);

    /* These 3 callbacks are MANDATORY: */
    if (callbacks->begin_cb == NULL)
        elog(ERROR, "output plugins have to register a begin callback");
    if (callbacks->change_cb == NULL)
        elog(ERROR, "output plugins have to register a change callback");
    if (callbacks->commit_cb == NULL)
        elog(ERROR, "output plugins have to register a commit callback");
}
```

### 2.2 OutputPluginCallbacks Struct (PG17 & PG18 — identical)

```c
typedef struct OutputPluginCallbacks
{
    /* MANDATORY — must be non-NULL */
    LogicalDecodeStartupCB       startup_cb;          /* optional but strongly recommended */
    LogicalDecodeBeginCB         begin_cb;             /* MANDATORY */
    LogicalDecodeChangeCB        change_cb;            /* MANDATORY */
    LogicalDecodeTruncateCB      truncate_cb;          /* optional */
    LogicalDecodeCommitCB        commit_cb;            /* MANDATORY */
    LogicalDecodeMessageCB       message_cb;           /* optional */
    LogicalDecodeFilterByOriginCB filter_by_origin_cb; /* optional */
    LogicalDecodeShutdownCB      shutdown_cb;          /* optional but recommended */

    /* Two-phase commit support (optional) */
    LogicalDecodeFilterPrepareCB     filter_prepare_cb;
    LogicalDecodeBeginPrepareCB      begin_prepare_cb;
    LogicalDecodePrepareCB           prepare_cb;
    LogicalDecodeCommitPreparedCB    commit_prepared_cb;
    LogicalDecodeRollbackPreparedCB  rollback_prepared_cb;

    /* Streaming of in-progress transactions (optional) */
    LogicalDecodeStreamStartCB       stream_start_cb;
    LogicalDecodeStreamStopCB        stream_stop_cb;
    LogicalDecodeStreamAbortCB       stream_abort_cb;
    LogicalDecodeStreamPrepareCB     stream_prepare_cb;
    LogicalDecodeStreamCommitCB      stream_commit_cb;
    LogicalDecodeStreamChangeCB      stream_change_cb;
    LogicalDecodeStreamMessageCB     stream_message_cb;
    LogicalDecodeStreamTruncateCB    stream_truncate_cb;
} OutputPluginCallbacks;
```

### 2.3 Required Callback Signatures

```c
/* Startup: called when the replication slot is created or reused */
typedef void (*LogicalDecodeStartupCB)(
    struct LogicalDecodingContext *ctx,
    OutputPluginOptions *options,    /* set options->output_type here */
    bool is_init);                  /* true = slot just created */

/* BEGIN transaction */
typedef void (*LogicalDecodeBeginCB)(
    struct LogicalDecodingContext *ctx,
    ReorderBufferTXN *txn);

/* Per-row change — THIS IS WHERE DECRYPTION HAPPENS */
typedef void (*LogicalDecodeChangeCB)(
    struct LogicalDecodingContext *ctx,
    ReorderBufferTXN *txn,
    Relation relation,               /* fully opened Relation handle */
    ReorderBufferChange *change);

/* COMMIT transaction */
typedef void (*LogicalDecodeCommitCB)(
    struct LogicalDecodingContext *ctx,
    ReorderBufferTXN *txn,
    XLogRecPtr commit_lsn);

/* Shutdown: cleanup */
typedef void (*LogicalDecodeShutdownCB)(
    struct LogicalDecodingContext *ctx);

/* TRUNCATE (optional but recommended) */
typedef void (*LogicalDecodeTruncateCB)(
    struct LogicalDecodingContext *ctx,
    ReorderBufferTXN *txn,
    int nrelations,
    Relation relations[],
    ReorderBufferChange *change);
```

---

## 3. ReorderBufferChange — Tuple Access

### 3.1 Struct Layout (PG17 & PG18 — identical)

```c
typedef struct ReorderBufferChange
{
    XLogRecPtr      lsn;
    ReorderBufferChangeType action;  /* INSERT, UPDATE, DELETE, TRUNCATE, ... */
    struct ReorderBufferTXN *txn;
    RepOriginId     origin_id;

    union
    {
        /* For INSERT, UPDATE, DELETE: */
        struct
        {
            RelFileLocator rlocator;       /* physical storage location */
            bool           clear_toast_afterwards;
            HeapTuple      oldtuple;       /* valid for DELETE, UPDATE (replica identity) */
            HeapTuple      newtuple;       /* valid for INSERT, UPDATE */
        } tp;

        /* For TRUNCATE: */
        struct { Size nrelids; bool cascade; bool restart_seqs; Oid *relids; } truncate;

        /* For MESSAGE: */
        struct { char *prefix; Size message_size; char *message; } msg;

        /* Internal types omitted */
    } data;

    dlist_node node;
} ReorderBufferChange;
```

### 3.2 Critical Detail: Tuples Are Direct HeapTuple

In **both PG17 and PG18**, `change->data.tp.oldtuple` and `change->data.tp.newtuple`
are **`HeapTuple`** (i.e., `HeapTupleData *`), NOT the old `ReorderBufferTupleBuf *`
from PG ≤ 16.

Verified from actual installed headers:
- `/usr/include/postgresql/17/server/replication/reorderbuffer.h:99`:  `HeapTuple oldtuple;`
- `/usr/include/postgresql/17/server/replication/reorderbuffer.h:101`: `HeapTuple newtuple;`
- `/usr/include/postgresql/18/server/replication/reorderbuffer.h:104`: `HeapTuple oldtuple;`
- `/usr/include/postgresql/18/server/replication/reorderbuffer.h:106`: `HeapTuple newtuple;`

**No casting needed** — these are ready-to-use HeapTuple pointers.

The HeapTuple `t_data` pointer is valid and points to in-memory data (not a buffer
page). The tuple layout is: `[HeapTupleHeader (t_hoff bytes)] [user data]`.

For `encrypted_heap` tables, the user data portion `[t_hoff..t_len)` contains
the wire format: `[IV(12) | CIPHERTEXT(N) | GCM-TAG(16)]`.

### 3.3 How pgoutput Accesses Tuples

From `pgoutput.c` (the built-in output plugin):
```c
/* Store into a TupleTableSlot for column-level processing */
if (change->data.tp.oldtuple)
{
    old_slot = relentry->old_slot;
    ExecStoreHeapTuple(change->data.tp.oldtuple, old_slot, false);
}

if (change->data.tp.newtuple)
{
    new_slot = relentry->new_slot;
    ExecStoreHeapTuple(change->data.tp.newtuple, new_slot, false);
}
```

For our plugin, we can work directly with the HeapTuple without going through
slots, since we just need to decrypt the user data in-place.

---

## 4. Detecting encrypted_heap Tables

### 4.1 Using relation->rd_rel->relam

The `change_cb` callback receives a fully opened `Relation` handle. The AM is
stored in `relation->rd_rel->relam` (type `Oid`).

From `/usr/include/postgresql/18/server/catalog/pg_class.h:53`:
```c
Oid relam BKI_DEFAULT(heap) BKI_LOOKUP_OPT(pg_am);
```

### 4.2 Looking Up the encrypted_heap AM OID

```c
#include "commands/defrem.h"   /* get_table_am_oid() */

/* At startup_cb time, resolve OID once: */
Oid encrypted_heap_am_oid = get_table_am_oid("encrypted_heap", true);
/* missing_ok=true: returns InvalidOid if extension not installed */

/* In change_cb, check each relation: */
static inline bool
relation_uses_encrypted_heap(Relation relation)
{
    return OidIsValid(encrypted_heap_am_oid) &&
           relation->rd_rel->relam == encrypted_heap_am_oid;
}
```

### 4.3 Alternative: Compare rd_tableam Pointer

We could compare `relation->rd_tableam == pg_vault_tde_get_tableam_routine()`,
but this is fragile because the WAL sender's relcache may not have loaded
our AM handler yet. The OID comparison is more robust.

---

## 5. Execution Environment

### 5.1 WAL Sender Process

The output plugin runs in the **WAL sender process**, which is:
- A regular PostgreSQL backend process forked from the postmaster
- Has **full access to shared memory** (inherits shmem from postmaster)
- Has a valid `MemoryContext` hierarchy
- Can call all PostgreSQL backend functions (palloc, ereport, catalog lookups)
- Has the relcache available (can do `RelationIdGetRelation`, etc.)

### 5.2 Shared Memory & DEK Access

Since `pg_vault_tde` is loaded via `shared_preload_libraries`:
1. The postmaster runs `_PG_init()` which chains `shmem_request_hook` and `shmem_startup_hook`
2. Shared memory (DEK cache, LWLock) is initialized before any backend forks
3. The WAL sender **inherits** the shared memory mappings
4. `pg_vault_tde_kms_get_dek()` works correctly in the WAL sender context
5. The per-backend EVP context pool and IV batch are initialized per-process
6. `on_proc_exit(tde_backend_cleanup, ...)` is also inherited and will fire on WAL sender exit

**Conclusion**: The DEK is accessible. The crypto functions work. No special
initialization needed beyond what `_PG_init` already does.

---

## 6. PG17 vs PG18 API Differences

### 6.1 Logical Decoding: NO Differences

Verified by diffing the actual installed headers:
- `output_plugin.h`: **Identical** (only copyright year changed)
- `logical.h`: **Identical** (only copyright year changed)
- `reorderbuffer.h`: Minor changes in RBTXN flags and prepare status macros;
  **no changes to `ReorderBufferChange`** struct layout or tuple types

### 6.2 ReorderBuffer API Function Names (Minor Difference)

| API | PG17 | PG18 |
|-----|------|------|
| Allocate tuple buffer | `ReorderBufferGetTupleBuf()` | `ReorderBufferAllocTupleBuf()` |
| Free tuple buffer | `ReorderBufferReturnTupleBuf()` | `ReorderBufferFreeTupleBuf()` |

These are **not used by output plugins** (only by the decoder internals), so
they are irrelevant for our implementation.

**Result**: No `#if PG_VERSION_NUM` guards needed for the output plugin code.

---

## 7. Architecture Decision: Same .so vs Separate .so

### 7.1 Recommendation: Same .so (`pg_vault_tde.so`)

**Both** `_PG_init` and `_PG_output_plugin_init` can coexist in the same shared
library. The `test_decoding` contrib module does exactly this:

```c
/* test_decoding.c */
void _PG_init(void) { /* ... */ }

void _PG_output_plugin_init(OutputPluginCallbacks *cb)
{
    cb->startup_cb = pg_decode_startup;
    cb->change_cb = pg_decode_change;
    /* ... */
}
```

**Advantages of same .so**:
1. Direct access to `tde_decrypt_heap_tuple()` (static in tam.c — would need
   to be made non-static or a wrapper exposed)
2. Direct access to `tde_gcm_decrypt()` and `pg_vault_tde_kms_get_dek()`
3. No additional build artifacts or packaging complexity
4. The library is already loaded via `shared_preload_libraries` — `dlopen()`
   just increments the refcount and finds the symbol

**Usage**:
```sql
-- Create a logical replication slot using our plugin:
SELECT pg_create_logical_replication_slot('tde_slot', 'pg_vault_tde');

-- Or with pg_recvlogical:
pg_recvlogical --plugin=pg_vault_tde --slot=tde_slot --start
```

### 7.2 What Needs to Change

1. `tde_decrypt_heap_tuple()` is currently `static` in `pg_vault_tde_tam.c`.
   Either:
   - **(Preferred)** Create a new wrapper in a separate file (`src/logicaldec/`)
     that calls `tde_gcm_decrypt()` directly (same logic, fewer dependencies)
   - Or expose `tde_decrypt_heap_tuple()` via `pg_vault_tde_tam.h`

2. Add `_PG_output_plugin_init` to `src/pg_vault_tde.c` alongside the existing
   `_PG_init`

3. **No new OBJS needed** if we add the output plugin code inline in
   `pg_vault_tde.c`, or add one new `.o` to the Makefile OBJS list

---

## 8. Concrete Implementation Skeleton

```c
/*
 * pg_vault_tde_logicaldec.c — Logical decoding output plugin
 *
 * Decrypts tuples from encrypted_heap tables before sending them
 * to logical replication subscribers or pg_recvlogical consumers.
 *
 * The WAL sender reads raw WAL records (xl_heap_insert etc.) which
 * contain ciphertext — the TAM callbacks are never invoked.  This
 * output plugin intercepts the change_cb and transparently replaces
 * encrypted HeapTuples with their decrypted equivalents.
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup_details.h"
#include "catalog/pg_class.h"
#include "commands/defrem.h"          /* get_table_am_oid */
#include "fmgr.h"
#include "replication/logical.h"
#include "replication/output_plugin.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"

#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_kms.h"

/*
 * Per-plugin private state, stored in ctx->output_plugin_private.
 */
typedef struct TdeOutputPluginState
{
    MemoryContext context;             /* private transient memory context */
    Oid           encrypted_heap_oid;  /* cached OID of encrypted_heap AM */
    bool          text_mode;           /* true = textual output, false = binary */
} TdeOutputPluginState;


/* ----------------------------------------------------------------
 * Helper: Decrypt a HeapTuple from an encrypted_heap table
 *
 * Takes a HeapTuple whose user-data region [t_hoff .. t_len) contains
 * [IV(12) | CIPHERTEXT | TAG(16)] and returns a palloc'd HeapTuple
 * with plaintext user data.
 *
 * This duplicates the logic of tde_decrypt_heap_tuple() from tam.c
 * to avoid making that static function externally visible.
 * ----------------------------------------------------------------
 */
static HeapTuple
tde_logicaldec_decrypt_tuple(HeapTuple enc)
{
    Size        hdr_len   = enc->t_data->t_hoff;
    char       *enc_data  = (char *) enc->t_data + hdr_len;
    Size        enc_len   = enc->t_len - hdr_len;
    Size        pt_len    = 0;
    char       *pt_buf;
    HeapTuple   plain;

    if (enc_len < (Size) TDE_GCM_OVERHEAD)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("pg_vault_tde: logical decoding: encrypted tuple "
                        "too short (%zu bytes)", enc_len)));

    pt_buf = tde_gcm_decrypt(enc_data, enc_len, &pt_len);

    plain = (HeapTuple) palloc0(HEAPTUPLESIZE + hdr_len + pt_len);
    plain->t_len      = (uint32) (hdr_len + pt_len);
    plain->t_self     = enc->t_self;
    plain->t_tableOid = enc->t_tableOid;
    plain->t_data     = (HeapTupleHeader) ((char *) plain + HEAPTUPLESIZE);

    memcpy(plain->t_data, enc->t_data, hdr_len);                  /* header verbatim */
    memcpy((char *) plain->t_data + hdr_len, pt_buf, pt_len);     /* decrypted payload */

    OPENSSL_cleanse(pt_buf, pt_len);
    pfree(pt_buf);

    return plain;
}


/* ----------------------------------------------------------------
 * Helper: decrypt a tuple in-place inside a ReorderBufferChange,
 * replacing the ciphertext HeapTuple with a plaintext HeapTuple.
 * ----------------------------------------------------------------
 */
static void
tde_logicaldec_decrypt_change(ReorderBufferChange *change, Relation relation,
                              Oid encrypted_heap_oid)
{
    HeapTuple   plain;

    /* Only process tables using encrypted_heap AM */
    if (!OidIsValid(encrypted_heap_oid) ||
        relation->rd_rel->relam != encrypted_heap_oid)
        return;

    /*
     * Decrypt newtuple (INSERT, UPDATE).
     *
     * The HeapTuple in the ReorderBuffer is palloc'd in the reorder
     * buffer's memory context.  We allocate a new plaintext tuple and
     * swap it in, freeing the encrypted original.
     */
    if (change->data.tp.newtuple != NULL)
    {
        plain = tde_logicaldec_decrypt_tuple(change->data.tp.newtuple);
        /* The original encrypted tuple is owned by the ReorderBuffer;
         * we can free it here because the RB won't access it again
         * after handing it to the change_cb.
         * Note: ReorderBufferFreeTupleBuf / ReorderBufferReturnTupleBuf
         * is the proper API but it's not accessible here.  Since these
         * tuples are palloc'd, pfree suffices.
         */
        pfree(change->data.tp.newtuple);
        change->data.tp.newtuple = plain;
    }

    /*
     * Decrypt oldtuple (UPDATE with replica identity, DELETE).
     *
     * The old tuple contains only replica-identity columns, which are
     * also encrypted in the WAL record.
     */
    if (change->data.tp.oldtuple != NULL)
    {
        plain = tde_logicaldec_decrypt_tuple(change->data.tp.oldtuple);
        pfree(change->data.tp.oldtuple);
        change->data.tp.oldtuple = plain;
    }
}


/* ================================================================
 * Output Plugin Callbacks
 * ================================================================ */

/*
 * Startup callback — called when the replication slot is created or reused.
 */
static void
tde_decode_startup(LogicalDecodingContext *ctx, OutputPluginOptions *opt,
                   bool is_init)
{
    TdeOutputPluginState *state;

    state = palloc0(sizeof(TdeOutputPluginState));
    state->context = AllocSetContextCreate(ctx->context,
                                           "pg_vault_tde logical decoding",
                                           ALLOCSET_DEFAULT_SIZES);

    /*
     * Cache the encrypted_heap AM OID once at startup.
     * missing_ok=true: if the extension isn't installed in this DB
     * (shouldn't happen, since we're loaded in shared_preload_libraries),
     * we get InvalidOid and skip all decryption.
     */
    state->encrypted_heap_oid = get_table_am_oid("encrypted_heap", true);

    ctx->output_plugin_private = state;

    /* Use textual output by default (like test_decoding).
     * A production version may want to use binary for efficiency. */
    opt->output_type = OUTPUT_PLUGIN_TEXTUAL_OUTPUT;
    /* Don't need rewrites (DDL rewriting during initial snapshot) */
    opt->receive_rewrites = false;

    if (!OidIsValid(state->encrypted_heap_oid))
        ereport(LOG,
                (errmsg("pg_vault_tde: logical decoding plugin active, "
                        "but encrypted_heap AM not found in this database")));
    else
        ereport(LOG,
                (errmsg("pg_vault_tde: logical decoding plugin active, "
                        "encrypted_heap AM OID = %u",
                        state->encrypted_heap_oid)));
}


/*
 * BEGIN callback.
 */
static void
tde_decode_begin_txn(LogicalDecodingContext *ctx, ReorderBufferTXN *txn)
{
    OutputPluginPrepareWrite(ctx, true);
    appendStringInfo(ctx->out, "BEGIN %u", txn->xid);
    OutputPluginWrite(ctx, true);
}


/*
 * COMMIT callback.
 */
static void
tde_decode_commit_txn(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                      XLogRecPtr commit_lsn)
{
    OutputPluginPrepareWrite(ctx, true);
    appendStringInfo(ctx->out, "COMMIT %u", txn->xid);
    OutputPluginWrite(ctx, true);
}


/*
 * CHANGE callback — the core of the output plugin.
 *
 * For encrypted_heap tables, we decrypt the tuple data before
 * outputting it.  For standard heap tables, we pass through unchanged.
 */
static void
tde_decode_change(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                  Relation relation, ReorderBufferChange *change)
{
    TdeOutputPluginState *state = ctx->output_plugin_private;
    Form_pg_class class_form = RelationGetForm(relation);
    TupleDesc tupdesc = RelationGetDescr(relation);
    MemoryContext old;

    old = MemoryContextSwitchTo(state->context);

    /*
     * Decrypt encrypted_heap tuples before any output processing.
     *
     * After this call, change->data.tp.newtuple and .oldtuple
     * contain plaintext HeapTuples (or are unchanged for non-encrypted
     * tables).
     */
    tde_logicaldec_decrypt_change(change, relation, state->encrypted_heap_oid);

    OutputPluginPrepareWrite(ctx, true);

    appendStringInfoString(ctx->out, "table ");
    appendStringInfoString(ctx->out,
        quote_qualified_identifier(
            get_namespace_name(RelationGetNamespace(relation)),
            NameStr(class_form->relname)));
    appendStringInfoChar(ctx->out, ':');

    switch (change->action)
    {
        case REORDER_BUFFER_CHANGE_INSERT:
            appendStringInfoString(ctx->out, " INSERT:");
            if (change->data.tp.newtuple != NULL)
            {
                /* TODO: format the decrypted tuple for output */
                appendStringInfoString(ctx->out, " (decrypted tuple data)");
            }
            break;

        case REORDER_BUFFER_CHANGE_UPDATE:
            appendStringInfoString(ctx->out, " UPDATE:");
            if (change->data.tp.oldtuple != NULL)
                appendStringInfoString(ctx->out, " old-key: (decrypted)");
            if (change->data.tp.newtuple != NULL)
                appendStringInfoString(ctx->out, " new-tuple: (decrypted)");
            break;

        case REORDER_BUFFER_CHANGE_DELETE:
            appendStringInfoString(ctx->out, " DELETE:");
            if (change->data.tp.oldtuple != NULL)
                appendStringInfoString(ctx->out, " (decrypted old-key)");
            else
                appendStringInfoString(ctx->out, " (no tuple data)");
            break;

        default:
            Assert(false);
    }

    OutputPluginWrite(ctx, true);

    MemoryContextSwitchTo(old);
    MemoryContextReset(state->context);
}


/*
 * TRUNCATE callback — pass through, no decryption needed.
 */
static void
tde_decode_truncate(LogicalDecodingContext *ctx, ReorderBufferTXN *txn,
                    int nrelations, Relation relations[],
                    ReorderBufferChange *change)
{
    OutputPluginPrepareWrite(ctx, true);
    appendStringInfoString(ctx->out, "TRUNCATE (pass-through)");
    OutputPluginWrite(ctx, true);
}


/*
 * Shutdown callback — cleanup.
 */
static void
tde_decode_shutdown(LogicalDecodingContext *ctx)
{
    TdeOutputPluginState *state = ctx->output_plugin_private;

    if (state != NULL)
        MemoryContextDelete(state->context);
}


/* ================================================================
 * Plugin Registration
 *
 * This function is looked up by name when the replication slot is
 * created with:  SELECT pg_create_logical_replication_slot('s', 'pg_vault_tde');
 *
 * It coexists with _PG_init in the same .so — both are valid
 * simultaneously.  PostgreSQL uses _PG_init for shared_preload_libraries
 * and _PG_output_plugin_init for logical decoding plugin loading.
 * ================================================================
 */
void
_PG_output_plugin_init(OutputPluginCallbacks *cb)
{
    cb->startup_cb  = tde_decode_startup;
    cb->begin_cb    = tde_decode_begin_txn;
    cb->change_cb   = tde_decode_change;
    cb->truncate_cb = tde_decode_truncate;
    cb->commit_cb   = tde_decode_commit_txn;
    cb->shutdown_cb = tde_decode_shutdown;
}
```

---

## 9. Build Integration

### 9.1 Same .so Approach (Recommended)

Add the new source file to the existing `OBJS` in the Makefile:

```makefile
OBJS = \
    src/pg_vault_tde.o \
    src/kms/pg_vault_tde_kms.o \
    src/crypto/pg_vault_tde_crypto.o \
    src/crypto/pg_vault_tde_hw_accel.o \
    src/tam/pg_vault_tde_tam.o \
    src/tam/pg_vault_tde_toast.o \
    src/iam/pg_vault_tde_iam.o \
    src/backup/pg_vault_tde_backup.o \
    src/logicaldec/pg_vault_tde_logicaldec.o    # NEW
```

The `_PG_output_plugin_init` symbol is exported via `PGDLLEXPORT` (the function
is declared `extern` in `output_plugin.h`).

### 9.2 No Separate _PG_init Needed

The output plugin **shares** the same `.so` as the extension. When PostgreSQL
loads it via `load_external_function("pg_vault_tde", "_PG_output_plugin_init", ...)`:

1. Since `pg_vault_tde` is in `shared_preload_libraries`, the `.so` is **already
   loaded** in every backend (including the WAL sender).
2. `dlopen()` returns the already-loaded handle; `dlsym()` finds the symbol.
3. `_PG_init` has **already run** — shmem hooks are chained, DEK cache is live,
   EVP contexts are available.
4. No second `_PG_init` call happens (the dynamic linker's `dlopen` with
   `RTLD_NOW` on an already-opened library just bumps the refcount).

### 9.3 Directory Structure

```
src/
  logicaldec/
    logicaldec.instructions.md    # module-specific instructions
    pg_vault_tde_logicaldec.c     # output plugin implementation
src/include/
    pg_vault_tde_logicaldec.h     # (optional) header for any shared declarations
```

---

## 10. Key Implementation Considerations

### 10.1 Memory Ownership of Decrypted Tuples

The `change->data.tp.newtuple` and `.oldtuple` are allocated by the
ReorderBuffer in its own memory context. When we replace them with decrypted
copies, we must:
1. `pfree()` the original encrypted HeapTuple (it's palloc'd, not buffer-backed)
2. Allocate the decrypted tuple in the same memory context
3. The ReorderBuffer will free our replacement tuple when it cleans up the change

### 10.2 TOAST Handling

The ReorderBuffer **reassembles TOAST values** before calling `change_cb`.
This means:
- External TOAST chunks are already detoasted and assembled inline
- For `encrypted_heap` tables with the TOAST AM override (`HEAP_TABLE_AM_OID`),
  TOAST data is stored **unencrypted** (documented v1 limitation)
- The inline (compressed/plain) portion of the tuple IS encrypted
- After TOAST reassembly, the tuple's user data portion is a mix of:
  - Encrypted inline columns
  - Unencrypted TOAST-fetched columns (already reassembled)

**Issue**: If the TOAST reassembly inserts plain varlena data into an
otherwise-encrypted tuple body, the wire format `[IV|CT|TAG]` is disrupted.

**Resolution**: Since TOAST tables use `HEAP_TABLE_AM_OID` (not `encrypted_heap`),
the TOAST chunks themselves are stored as plaintext. The main tuple's inline
data is encrypted. The ReorderBuffer's `ReorderBufferToastReplace()` function
deforms the tuple using `heap_deform_tuple()` — this will **fail** on an
encrypted tuple because the datum boundaries are encrypted.

**This is a critical design issue**. Two possible solutions:
1. **Decrypt before TOAST reassembly**: Hook into the ReorderBuffer's toast
   processing (not possible via the output plugin API alone)
2. **Ensure TOAST columns are always external**: For `encrypted_heap` tables,
   the encrypted user data portion is opaque; column-level TOAST compression
   cannot work. This means tables with large columns must rely on the TOAST
   AM override to store values externally (unencrypted).

**Practical impact**: For rows where ALL column data fits inline (< ~2 kB after
header), no TOAST is involved and decryption-in-output-plugin works perfectly.
For rows with large columns, the v1 TOAST limitation (unencrypted external
storage) means TOAST reassembly receives the detoasted value from the
unencrypted TOAST table, and the inline data is the encrypted portion.

**Further investigation needed**: We must verify how `ReorderBufferToastReplace()`
interacts with encrypted inline data. If it calls `heap_deform_tuple()` on the
encrypted tuple, it will read garbage for attribute boundaries. This may
require the decryption to happen at the ReorderBuffer level, not the output
plugin level.

### 10.3 DEK Security in WAL Sender

- The WAL sender has shared memory access → can read the DEK
- `OPENSSL_cleanse` is called on all DEK copies (existing pattern)
- The `on_proc_exit(tde_backend_cleanup, ...)` handler fires on WAL sender exit
- EVP contexts are per-process → the WAL sender gets its own pool

### 10.4 Key Rotation During Logical Decoding

If a key rotation happens while the WAL sender is streaming:
- Old tuples in the WAL still use the old DEK
- `tde_gcm_decrypt()` already handles prev_dek fallback (see `crypto.c`)
- The decryption function tries the current DEK first, then falls back to
  prev_dek if GCM authentication fails
- This is safe for logical decoding

### 10.5 Replica Identity Interaction

For `UPDATE` and `DELETE`, PostgreSQL logs the **old tuple** (or replica identity
columns) in the WAL. For `encrypted_heap` tables:
- The old tuple's user data is also encrypted (it's part of the heap page)
- Both `oldtuple` and `newtuple` need decryption
- The replica identity is a subset of columns, but the WAL record contains the
  full encrypted user data portion from `t_hoff` onwards
- After decryption, column extraction works normally

---

## 11. PG Version Compatibility Summary

| Component | PG17 | PG18 | Guard Needed? |
|-----------|------|------|---------------|
| `OutputPluginCallbacks` struct | Identical | Identical | No |
| `_PG_output_plugin_init` entry point | Same | Same | No |
| `ReorderBufferChange.data.tp.{old,new}tuple` | `HeapTuple` | `HeapTuple` | No |
| `LogicalDecodingContext` struct | Identical | Identical | No |
| `OutputPluginPrepareWrite` / `OutputPluginWrite` | Same | Same | No |
| `get_table_am_oid()` | Available | Available | No |
| `relation->rd_rel->relam` | Available | Available | No |
| `ReorderBufferAllocTupleBuf` name | `ReorderBufferGetTupleBuf` | `ReorderBufferAllocTupleBuf` | No (not used by plugins) |

**Conclusion**: Zero `#if PG_VERSION_NUM` guards required for logical decoding code.

---

## 12. Open Questions / Further Research

1. **TOAST interaction**: Must verify whether `ReorderBufferToastReplace()` calls
   `heap_deform_tuple()` on the still-encrypted tuple. If so, the output plugin
   approach is insufficient — decryption must happen earlier in the pipeline
   (possibly by hooking into the ReorderBuffer layer, which would require a
   different architectural approach).

2. **Binary protocol**: For production logical replication (not just test
   output), the plugin should support `OUTPUT_PLUGIN_BINARY_OUTPUT` and use
   `logicalrep_write_*` functions from `replication/logicalproto.h`.

3. **Initial table sync**: The subscriber's initial COPY uses `table_scan_getnextslot`
   which DOES invoke the TAM (correctly decrypts). No output plugin involvement
   needed for initial sync.

4. **Streaming transactions**: For large transactions that stream changes before
   COMMIT, the `stream_change_cb` also needs decryption. This is the same
   decrypt logic but registered on a different callback.

5. **ALTER TABLE ... SET ACCESS METHOD**: If a table is changed from
   `encrypted_heap` to `heap` (or vice versa), the cached AM OID check
   remains correct because we check `relation->rd_rel->relam` per-change,
   which reflects the relation's state at the time the WAL record was written.

---

## 13. References

| File | Location | Purpose |
|------|----------|---------|
| `output_plugin.h` | `/usr/include/postgresql/{17,18}/server/replication/output_plugin.h` | Callback typedefs and OutputPluginCallbacks struct |
| `logical.h` | `/usr/include/postgresql/{17,18}/server/replication/logical.h` | LogicalDecodingContext struct |
| `reorderbuffer.h` | `/usr/include/postgresql/{17,18}/server/replication/reorderbuffer.h` | ReorderBufferChange, HeapTuple in data.tp |
| `pgoutput.c` | `src/backend/replication/pgoutput/pgoutput.c` (PG source) | Reference implementation of a production output plugin |
| `test_decoding.c` | `contrib/test_decoding/test_decoding.c` (PG source) | Simple reference for output plugin + `_PG_init` coexistence |
| `decode.c` | `src/backend/replication/logical/decode.c` (PG source) | WAL record → ReorderBufferChange conversion |
| `defrem.h` | `/usr/include/postgresql/18/server/commands/defrem.h` | `get_table_am_oid()` declaration |
| `pg_class.h` | `/usr/include/postgresql/18/server/catalog/pg_class.h` | `relam` field definition |
