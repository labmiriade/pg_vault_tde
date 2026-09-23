/*
 * pg_vault_tde_iam.c - Index Access Method (IAM) handler for pg_vault_tde
 *
 * Copyright (c) 2026 Miriade S.r.l.  
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * Encrypting B-Tree index keys presents a fundamental problem: the B-Tree
 * algorithm requires a total ordering of keys (for comparisons and range
 * scans) that probabilistic encryption (e.g. AES-256-GCM with random IV)
 * completely destroys.
 *
 * We use AES-256-SIV (RFC 5297, "Synthetic IV") for index key encryption.
 * AES-SIV is deterministic authenticated encryption: given the same DEK
 * and plaintext, it always produces the same ciphertext.  This preserves
 * equality semantics (equal plaintexts → equal ciphertexts), which is
 * sufficient for B-Tree equality lookups.
 *
 * CONSEQUENCE: tde_btree answers equality (=, IN, = ANY) and nothing else.
 * Range predicates, ORDER BY, min()/max() and merge joins are never served
 * from it — they run as sequential scans and stay correct — and a plan forced
 * onto it for a range fails with an error rather than return wrong rows.  See
 * "PLANNER: EQUALITY ONLY" below.  This trade-off is inherent to
 * deterministic encryption, not specific to this implementation.
 *
 * AES-SIV is available in OpenSSL 3.x via EVP_aes_256_siv().  It provides:
 *  - Deterministic encryption (same key + plaintext → same ciphertext)
 *  - Authenticated encryption (built-in integrity check, no separate HMAC)
 *  - No IV required from the caller; the "synthetic" IV is derived from
 *    the plaintext and an optional set of "associated data" headers.
 */
#include "postgres.h"
#include "access/amapi.h"
#include "access/genam.h"
#include "access/nbtree.h"
#include "access/tableam.h"    /* table_index_build_scan, IndexBuildCallback */
#include "nodes/execnodes.h"   /* IndexInfo full struct definition */
#include "utils/fmgroids.h"     /* F_BTHANDLER */
#include "utils/memutils.h"
#include "utils/syscache.h"     /* SearchSysCache1, ReleaseSysCache, CLAOID */
#include "utils/uuid.h"         /* DatumGetUUIDP, pg_uuid_t */
#include "catalog/pg_opclass.h" /* Form_pg_opclass */
#include "catalog/pg_index.h"   /* Anum_pg_index_indclass */
#include "catalog/pg_am_d.h"    /* BTREE_AM_OID */
#include "nodes/pathnodes.h"    /* IndexOptInfo, IndexPath, IndexClause */
#include "utils/lsyscache.h"    /* get_op_opfamily_strategy, get_collation_isdeterministic */
#include "storage/lwlock.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>

/*
 * Index build strategy: ambuildempty + per-row aminsert
 *
 * tde_btree's CREATE INDEX does NOT use the private btree sort API
 * (_bt_spoolinit / _bt_spool / _bt_leafbuild / _bt_spoolfreeall).  Those
 * symbols are defined as "static" in PostgreSQL's nbtsort.c and are therefore
 * NOT exported from the postgres binary on any platform — linking against them
 * produces an undefined-symbol FATAL at load time on debian/ubuntu packages.
 *
 * Instead, we use the public IndexAmRoutine callbacks:
 *   1. saved_btree_methods.ambuildempty(index) — creates a valid empty btree
 *      (metapage + empty root page) via WAL-safe btree initialisation.
 *   2. table_index_build_scan() with tde_build_callback() — visits each
 *      heap tuple, encrypts the key datums, and calls aminsert() one-by-one.
 *
 * Trade-off: slightly more page splits than the sorted bulk-load path
 * (O(n) sequential writes vs O(n log n) sorted writes), but fully portable
 * and correct.  For CREATE INDEX on an empty table the cost is zero.
 *
 * PKCS5_PBKDF2_HMAC is declared in openssl/evp.h (included above).
 */
#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_iam.h"
#include "src/include/pg_vault_tde_hw_accel.h"
#include "src/include/pg_vault_tde_guc.h"   /* pg_vault_tde_allow_plaintext_index */

/* AES-SIV produces a 16-byte synthetic IV prepended to ciphertext. */
#define TDE_SIV_OVERHEAD 16

/*
 * Per-backend AES-256-SIV context, re-keyed only when (idx_oid, generation)
 * changes — same caching strategy as the GCM slots in crypto.c.
 *
 * One difference forced by the algorithm: GCM rearms only the IV per message
 * (keyless), but AES-SIV has no IV and OpenSSL requires the key to be re-fed
 * for every message (verified empirically: a keyless rearm corrupts the tag
 * on the 2nd message).  So we keep the derived key cached in the slot and the
 * per-message rearm re-supplies it via EVP_CipherInit_ex(ctx, NULL, ..., key);
 * the cipher fetch and PBKDF2 derivation still happen only on (oid, gen) change.
 */
typedef struct TdeCipherSlot
{
    EVP_CIPHER_CTX *ctx;
    Oid             idx_oid;        /* InvalidOid = ctx not yet keyed */
    uint64          generation;
    unsigned char   siv_key[64];    /* cached derived key; re-armed per message */
} TdeCipherSlot;

static TdeCipherSlot idx_enc = {NULL, InvalidOid, 0, {0}};

/* Free a slot and wipe its cached key (shared by cleanup and error paths). */
static void
tde_iam_ctx_drop(TdeCipherSlot *slot)
{
    if (slot->ctx != NULL)
    {
        EVP_CIPHER_CTX_free(slot->ctx);
        slot->ctx = NULL;
    }
    OPENSSL_cleanse(slot->siv_key, sizeof(slot->siv_key));
    slot->idx_oid    = InvalidOid;
    slot->generation = 0;
}

/*
 * tde_iam_ctx_cleanup -- free cached SIV contexts.
 * Called from tde_crypto_ctx_cleanup() registered via on_proc_exit().
 */
void
tde_iam_ctx_cleanup(void)
{
    tde_iam_ctx_drop(&idx_enc);
}

/*
 * tde_iam_ctx_prepare -- return a per-backend AES-256-SIV context ready for one
 * message.  enc: 1 = encrypt, 0 = decrypt.  Raises ERROR on failure.
 *
 * On (idx_oid, generation) change the SIV key is re-derived from `dek` and the
 * cipher + key installed; otherwise only the cached key is re-armed.
 */
static EVP_CIPHER_CTX *
tde_iam_ctx_prepare(TdeCipherSlot *slot, Oid idx_oid,
                    const unsigned char *dek, int dek_len, int enc)
{
    uint64 gen = pg_vault_tde_catalog_get_rel_generation(idx_oid);

    /* Allocate once per backend in TopMemoryContext (survives per-tuple resets). */
    if (slot->ctx == NULL)
    {
        MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);
        slot->ctx = EVP_CIPHER_CTX_new();
        MemoryContextSwitchTo(old);
        if (slot->ctx == NULL)
            ereport(ERROR,
                    (errmsg("[IAM] Failed to create EVP_CIPHER_CTX for AES-SIV")));
        slot->idx_oid = InvalidOid;     /* force the re-key path below */
    }

    if (slot->idx_oid != idx_oid || slot->generation != gen)
    {
        /* Cache miss: derive the SIV key and install cipher + key. */
        const EVP_CIPHER *siv_cipher;
        EVP_CIPHER       *fetched = NULL;
        int               ok;

        /* 64-byte SIV key (two 256-bit keys) from the DEK; 1 PBKDF2 round. */
        if (PKCS5_PBKDF2_HMAC((const char *) dek, dek_len,
                              (const unsigned char *) "tde-siv", 7,
                              1, EVP_sha256(), 64, slot->siv_key) != 1)
        {
            tde_iam_ctx_drop(slot);
            ereport(ERROR, (errmsg("[IAM] PBKDF2 SIV key derivation failed")));
        }

        siv_cipher = tde_hw_accel_siv_cipher();
        if (siv_cipher == NULL)
            siv_cipher = fetched = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
        if (siv_cipher == NULL)
        {
            tde_iam_ctx_drop(slot);
            ereport(ERROR,
                    (errmsg("[IAM] AES-256-SIV cipher unavailable; requires "
                            "OpenSSL 3.x with the default provider")));
        }

        /* enc flows straight into the OpenSSL primitive: no ternary dispatch. */
        ok = EVP_CipherInit_ex(slot->ctx, siv_cipher, NULL, slot->siv_key, NULL, enc);
        if (fetched)
            EVP_CIPHER_free(fetched);
        if (ok != 1)
        {
            tde_iam_ctx_drop(slot);
            ereport(ERROR, (errmsg("[IAM] AES-256-SIV CipherInit failed")));
        }

        slot->idx_oid    = idx_oid;
        slot->generation = gen;
    }
    else
    {
        /* Cache hit: re-arm the per-message SIV state with the cached key. */
        if (EVP_CipherInit_ex(slot->ctx, NULL, NULL, slot->siv_key, NULL, enc) != 1)
        {
            tde_iam_ctx_drop(slot);
            ereport(ERROR, (errmsg("[IAM] AES-256-SIV re-arm failed")));
        }
    }

    return slot->ctx;
}

/*
 * tde_iam_encrypt_key
 *
 * Encrypts a B-Tree index key datum using AES-256-SIV.
 * Returns a palloc'd buffer containing [SIV-tag (16 bytes) | ciphertext].
 * The caller MUST OPENSSL_cleanse + pfree the returned buffer after use.
 *
 * @param plaintext     raw key bytes
 * @param plaintext_len length of plaintext in bytes
 * @param out_len       set to total encrypted length on success
 * @returns             palloc'd encrypted buffer, or NULL on DEK miss
 *
 * Side effects: reads DEK from shared-memory KMS cache under shared LWLock.
 */
char *
tde_iam_encrypt_key(Oid idx_oid, const char* dek, int dek_len,
                    const char *plaintext, Size plaintext_len, Size *out_len)
{
    EVP_CIPHER_CTX *ctx;
    char           *out_buf;
    int             olen1 = 0,
                    olen2 = 0;

    Assert(plaintext != NULL);
    Assert(out_len != NULL);

    out_buf = (char *) palloc0(plaintext_len + TDE_SIV_OVERHEAD);
    ctx = tde_iam_ctx_prepare(&idx_enc, idx_oid, (const unsigned char *) dek, dek_len, 1);

    /*
     * AES-256-SIV: no IV (synthetic IV derived internally).  The 16-byte SIV
     * tag is fetched after Final into out_buf[0..15]: [SIV-tag(16) | CT(N)].
     */
    if (EVP_EncryptUpdate(ctx,
                          (unsigned char *) out_buf + TDE_SIV_OVERHEAD, &olen1,
                          (const unsigned char *) plaintext,
                          (int) plaintext_len) != 1 ||
        EVP_EncryptFinal_ex(ctx,
                            (unsigned char *) out_buf + TDE_SIV_OVERHEAD + olen1,
                            &olen2) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            TDE_SIV_OVERHEAD, out_buf) != 1)
    {
        OPENSSL_cleanse(out_buf, plaintext_len + TDE_SIV_OVERHEAD);
        pfree(out_buf);
        tde_iam_ctx_drop(&idx_enc);
        ereport(ERROR,
                (errmsg("[IAM] AES-256-SIV EncryptUpdate/Final/GetTag failed")));
    }

    *out_len = (Size)(TDE_SIV_OVERHEAD + olen1 + olen2);
    return out_buf;
}

/*
 * ================================================================
 * tde_btree full wiring (v1.4)
 *
 * Architecture
 * -----------
 * tde_btree wraps the standard btree AM.  At _PG_init() time,
 * tde_iam_init() copies the btree IndexAmRoutine into a mutable struct
 * (tde_btree_methods) and overrides the four key-touching callbacks:
 *
 *   ambuild     — scan heap, AES-SIV encrypt each indexed datum, spool
 *                 into btree's sorted bulk-loader
 *   aminsert    — encrypt values[] datums before delegating to btree
 *   ambeginscan — delegate to btree (no crypto at scan-open time)
 *   amrescan    — encrypt equality scan keys (BTEqualStrategyNumber=3)
 *                 before delegating to btree; range keys pass through
 *                 unchanged (range scans produce incomplete results —
 *                 documented limitation)
 *
 * v1.4 supports bytea-typed index columns only (or expression indexes
 * that return bytea).  The operator class tde_bytea_ops is registered
 * as the default for type bytea using tde_btree (see pg_vault_tde--1.0.sql).
 *
 * Index build uses ambuildempty + per-row aminsert (portable; see the
 * build strategy comment near the top of this file for rationale).
 * ================================================================
 */

/* Forward declaration: identity-checked against index_rel->rd_indam->ambuild
 * by tde_iam_is_tde_btree_index, defined further down in this file. */
static IndexBuildResult *pg_vault_tde_ambuild(Relation heap, Relation index,
                                               IndexInfo *index_info);

/* Mutable copy of the btree AM routine, patched with our overrides */
static IndexAmRoutine  tde_btree_methods;

/*
 * Original (unmodified) btree AM — saved as a STATIC copy for delegation.
 *
 * Previously this was a POINTER (saved_btree_am) to a palloc'd struct
 * from _PG_init() in the POSTMASTER.  That pointer became stale in forked
 * backends because the heap block could be freed/overwritten by later
 * allocations, causing SIGSEGV when pg_vault_tde_ambuild tried to call
 * saved_btree_am->ambuild.
 *
 * Storing the full struct in BSS ensures all function pointers are
 * reliably inherited by forked backends (COW pages never change for
 * a static that is only written during _PG_init).
 */
static IndexAmRoutine  saved_btree_methods;
static bool            saved_btree_methods_valid = false;

/*
 * tde_iam_is_tde_btree_index (see pg_vault_tde_iam.h for the full rationale).
 *
 * index_rel->rd_indam is populated per-backend from the catalog's amhandler
 * for this index (pg_vault_tde_get_iam_routine, below), which always sets
 * ->ambuild = pg_vault_tde_ambuild for a tde_btree index — so the identity
 * check below holds in the leader AND in every parallel build worker.
 */
bool
tde_iam_is_tde_btree_index(Relation index_rel)
{
    return index_rel->rd_indam != NULL &&
           index_rel->rd_indam->ambuild == pg_vault_tde_ambuild;
}

/*
 * tde_iam_serialize_fixed_type
 *
 * Writes the canonical big-endian byte representation of `datum` for
 * the given `typoid` into `buf` (caller-supplied, must be ≥ 16 bytes).
 * Returns the number of bytes written, or 0 if typoid is unknown.
 *
 * Big-endian is used for int4/int8/date/timestamptz to guarantee
 * identical serialisation across x86 (little-endian) and aarch64 (BE/LE).
 * UUID is treated as a 16-byte opaque byte array (RFC 4122 representation).
 *
 * MUST NOT palloc — called from tight index-build loops.
 */
static Size
tde_iam_serialize_fixed_type(Datum datum, Oid typoid, uint8 *buf)
{
    switch (typoid)
    {
        case INT4OID:
        case DATEOID:
        {
            /* DateADT is typedef int32 — same serialisation as int4 */
            uint32 v = pg_hton32((uint32) DatumGetInt32(datum));
            memcpy(buf, &v, 4);
            return 4;
        }
        case INT8OID:
        case TIMESTAMPTZOID:
        {
            /* TimestampTz is typedef int64 — same serialisation as int8 */
            uint64 v = pg_hton64((uint64) DatumGetInt64(datum));
            memcpy(buf, &v, 8);
            return 8;
        }
        case UUIDOID:
        {
            /*
             * DatumGetUUIDP returns a pointer to pg_uuid_t whose 'data'
             * field is the 16 raw UUID bytes in RFC 4122 network byte order
             * (already big-endian for every field).
             */
            pg_uuid_t *uid = DatumGetUUIDP(datum);
            memcpy(buf, uid->data, 16);
            return 16;
        }
        default:
            return 0;   /* caller falls back to the varlena path */
    }
}

/*
 * tde_iam_type_is_serializable — does tde_iam_serialize_fixed_type() above
 * handle this type, or does it fall through to `return 0`?
 *
 * This must list exactly the typoids that switch accepts.  The scan-key
 * lifetime logic below decides whether a datum left behind in scan->keyData
 * was allocated here, and freeing one that was not is a wild pfree: when the
 * serializer declines, tde_iam_encrypt_fixed_type_datum() hands the caller's
 * own datum straight back, and for a by-value type that "pointer" is the
 * value itself.
 */
static bool
tde_iam_type_is_serializable(Oid typoid)
{
    switch (typoid)
    {
        case INT4OID:
        case DATEOID:
        case INT8OID:
        case TIMESTAMPTZOID:
        case UUIDOID:
            return true;
        default:
            return false;
    }
}

/*
 * tde_iam_owns_scan_key — would the encrypt path have allocated for this
 * column, rather than returning its input unchanged?
 */
static bool
tde_iam_owns_scan_key(Relation index, int col)
{
    Form_pg_attribute att;

    if (col < 0 || col >= index->rd_att->natts)
        return false;

    if (TDE_IS_ENC_OPS_COL(index, col))
        return tde_iam_type_is_serializable(index->rd_opcintype[col]);

    att = TupleDescAttr(index->rd_att, col);
    return att->attlen == -1 || att->attlen == -2;
}

/*
 * tde_iam_release_scan_key — free the encrypted key slot i was given earlier.
 *
 * The keys cannot be released where they are built: btrescan() memmoves the
 * ScanKeyData into scan->keyData and reads the datum for the whole scan, so
 * the earliest safe moment is the next rescan — or amendscan for the last set.
 * Without this a nested loop pays one encrypted key per outer row and keeps
 * every one of them.
 *
 * Ownership is not guessed from the pointer: it is recomputed from the index
 * and the key, which cannot change between rescans of one scan.  The NULL test
 * is what makes the first rescan safe, and it only works because
 * pg_vault_tde_ambeginscan() zeroes keyData — RelationGetIndexScan() allocates
 * it with palloc(), not palloc0(), so it arrives full of garbage that would
 * otherwise be pfree'd as if it were ours.
 */
static void
tde_iam_release_scan_key(IndexScanDesc scan, int i)
{
    if (scan->keyData == NULL || i < 0 || i >= scan->numberOfKeys)
        return;
    if (DatumGetPointer(scan->keyData[i].sk_argument) == NULL)
        return;
    if ((scan->keyData[i].sk_flags & SK_ISNULL) != 0)
        return;
    if (scan->keyData[i].sk_strategy != BTEqualStrategyNumber)
        return;
    if (!tde_iam_owns_scan_key(scan->indexRelation, scan->keyData[i].sk_attno - 1))
        return;

    pfree(DatumGetPointer(scan->keyData[i].sk_argument));
    scan->keyData[i].sk_argument = (Datum) 0;
}

/*
 * tde_iam_encrypt_fixed_type_datum
 *
 * Encrypts a fixed-size typed Datum using AES-256-SIV.
 * Called from aminsert, amrescan, and index_build_range_scan when an
 * index attribute uses a tde_*_enc_ops operator class (detected by
 * rd_att[i].atttypid == BYTEAOID && rd_opcintype[i] != BYTEAOID).
 *
 * Returns a palloc'd bytea Datum ready for btree storage.
 * On DEK unavailability, emits a WARNING and returns the original datum
 * unchanged (index key stored unencrypted; heap still TAM-encrypted).
 *
 * The 16-byte stack buffer `plain_buf` is cleansed before return.
 */
Datum
tde_iam_encrypt_fixed_type_datum(Relation index_rel, Datum datum, Oid typoid)
{
    uint8   plain_buf[16];   /* max 16 bytes for uuid */
    Size volatile plain_len;   /* live across the PG_TRY sigsetjmp */
    Size    enc_len    = 0;
    char   *encrypted;
    bytea  *enc_bytea  = NULL;

    unsigned char dek[TDE_DEK_LEN];

    plain_len = tde_iam_serialize_fixed_type(datum, typoid, plain_buf);

    if (plain_len == 0)
    {
        ereport(WARNING,
                (errmsg("[IAM] tde_iam_encrypt_fixed_type_datum: "
                        "unknown typoid %u, skipping encryption", typoid)));
        return datum;
    }

    if(!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
    {
        ereport(ERROR, 
                (errmsg("[IAM] tde_iam_encrypt_fixed_type_datum: "
                        "DEK unavailable for index rel: %u", RelationGetRelid(index_rel))));
    }

    /*
     * PG_TRY wipes the DEK even if tde_iam_encrypt_key raises ERROR — the
     * longjmp would otherwise skip the cleanse on the success path below.
     */
    PG_TRY();
    {
        encrypted = tde_iam_encrypt_key(RelationGetRelid(index_rel),
                                        (const char *) dek, sizeof(dek),
                                        (const char *) plain_buf, plain_len, &enc_len);
        OPENSSL_cleanse(plain_buf, sizeof(plain_buf));

        enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
        SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
        memcpy(VARDATA(enc_bytea), encrypted, enc_len);
        OPENSSL_cleanse(encrypted, enc_len);
        pfree(encrypted);
    }
    PG_CATCH();
    {
        OPENSSL_cleanse(plain_buf, sizeof(plain_buf));
        OPENSSL_cleanse(dek, sizeof(dek));
        PG_RE_THROW();
    }
    PG_END_TRY();

    OPENSSL_cleanse(dek, sizeof(dek));

    /*
     * The intermediate buffer is released here, not left to a context reset:
     * aminsert runs in ExecutorState, which lives for the whole statement, not
     * in ecxt_per_tuple_memory.  Measured on a single 8M-row INSERT before this
     * pfree: ExecutorState held 34 MB against 0.7 MB for the same INSERT into a
     * plain heap with a plain btree.  enc_bytea is the return value and is
     * freed by the caller once the index tuple has copied it.
     */
    return PointerGetDatum(enc_bytea);
}

/*
 * tde_iam_encrypt_index_datum
 *
 * Encrypts a typed Datum using AES-256-SIV.
 * Returns a new palloc'd bytea Datum with the encrypted content,
 * or the original Datum unchanged if DEK is unavailable (degraded mode).
 *
 * typbyval / typlen must come from the relevant Form_pg_attribute so that
 * pass-by-value types (int4, int8, date, timestamptz, bool) are serialised
 * from the Datum scalar — NOT detoasted as varlena, which would SIGSEGV on
 * small fixed-size types because the datum value is not a pointer.
 *
 * Called from pg_vault_tde_index_build_range_scan (tam.c) for tde_btree
 * index builds, and from pg_vault_tde_aminsert / pg_vault_tde_amrescan for
 * individual INSERTs and index scans.
 *
 * Caller is responsible for pfree'ing the result when done.
 */
Datum
tde_iam_encrypt_index_datum(Relation index_rel, Datum datum, bool typbyval, int16 typlen)
{

    /*
     * Serialise the Datum to a byte array according to type storage class:
     *
     * typbyval=true, typlen>0 — pass-by-value scalar (int4, int8, bool …).
     *   btree stores these directly by value (4 or 8 bytes in the IndexTuple).
     *   We CANNOT substitute a bytea Datum because btree's heap_form_tuple
     *   logic would store the lower N bytes of the bytea POINTER, not the
     *   ciphertext bytes.  Index keys for these types are stored UNENCRYPTED;
     *   the heap tuple itself is always encrypted by the TAM layer.
     *
     * typbyval=false, typlen>0 — fixed-length pass-by-reference (e.g. uuid).
     *   Same constraint: btree copies exactly typlen bytes from DatumGetPointer.
     *   We cannot change the stored size, so index keys are stored UNENCRYPTED.
     *
     * typbyval=false, typlen=-1 — variable-length varlena (text, numeric …).
     *   btree stores the full varlena inline.  We can substitute an enc_bytea
     *   varlena of different size.  AES-SIV is deterministic, so equal
     *   plaintexts → equal ciphertexts → equality comparison still works.
     *   THIS IS THE ONLY PATH THAT ENCRYPTS INDEX KEYS.
     *
     * typbyval=false, typlen=-2 — C string.  Same varlena-like treatment.
     *
     * Known limitation (v1.5): tde_int4_ops, tde_int8_ops, tde_uuid_ops,
     * tde_date_ops, tde_timestamptz_ops store index keys in plaintext.
     * The heap tuples are always encrypted by the TAM.  This limitation
     * will be addressed in v1.6 using a separate per-column encrypted
     * index type with CAST(int4 → bytea) at the access-method level.
     */
    if (typlen != -1 && typlen != -2)
    {
        /*
         * Fixed-size or pass-by-value type: cannot change the wire format.
         * Return the datum unchanged; the heap is still TAM-encrypted.
         */
        ereport(DEBUG2,
                (errmsg("[IAM] Skipping index key encryption for "
                        "fixed-size column (typlen=%d, typbyval=%s); "
                        "heap tuple is still encrypted by the TAM.",
                        (int) typlen, typbyval ? "true" : "false")));
        return datum;
    }

    /* varlena (or C-string) path — full AES-256-SIV encryption below */
    {
        bytea      *bval       = NULL;
        const char *plain;
        Size        plen;
        Size        enc_len    = 0;
        char       *encrypted;
        bytea      *enc_bytea  = NULL;
        unsigned char dek[TDE_DEK_LEN];

        if (typlen == -1)
        {
            /*
             * PG_DETOAST_DATUM_COPY allocates a private palloc'd copy in
             * CurrentMemoryContext.  Using COPY (not DatumGetByteaPP)
             * prevents use-after-free if the calling context is reset
             * between iterations.  The copy is reclaimed by context reset.
             */
            bval  = (bytea *) PG_DETOAST_DATUM_COPY(datum);
            plain = VARDATA_ANY(bval);
            plen  = VARSIZE_ANY_EXHDR(bval);
        }
        else
        {
            /* typlen == -2: C string */
            plain = DatumGetCString(datum);
            plen  = strlen(plain) + 1;   /* include null terminator */
        }   

        if(!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
        {
            ereport(ERROR, 
                    errmsg("[IAM] tde_iam_encrypt_index_datum: "
                           "DEK unavailable for index relid %u", RelationGetRelid(index_rel)));
        }
        /*
         * PG_TRY wipes the DEK even if tde_iam_encrypt_key raises ERROR — the
         * longjmp would otherwise skip the cleanse on the success path below.
         */
        PG_TRY();
        {
            encrypted = tde_iam_encrypt_key(RelationGetRelid(index_rel),
                                            (const char *) dek, sizeof(dek),
                                            plain, plen, &enc_len);

            enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
            SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
            memcpy(VARDATA(enc_bytea), encrypted, enc_len);
            OPENSSL_cleanse(encrypted, enc_len);
            pfree(encrypted);
        }
        PG_CATCH();
        {
            OPENSSL_cleanse(dek, sizeof(dek));
            PG_RE_THROW();
        }
        PG_END_TRY();

        OPENSSL_cleanse(dek, sizeof(dek));

        /*
         * Both intermediates go back now — see the note in
         * tde_iam_encrypt_fixed_type_datum(): the caller is in ExecutorState,
         * which is reset once per statement, not once per tuple.  `plain`
         * points inside bval, so this has to come after the encrypt call.
         */
        if (bval != NULL)
            pfree(bval);

        return PointerGetDatum(enc_bytea);
    }
}

/* ── BUILD CALLBACK ─────────────────────────────────────────────────────── */

/* ── AMBUILD ────────────────────────────────────────────────────────────── */

/*
 * pg_vault_tde_ambuild
 *
 * Delegates entirely to btree's ambuild. pg_vault_tde_index_build_range_scan
 * (tam.c) recognises this index via tde_iam_is_tde_btree_index() and
 * encrypts index key values before passing them to btbuildCallback.
 *
 * This approach avoids the private btree spool API (_bt_spoolinit, etc.) and
 * the single-row aminsert approach (which does not work correctly because
 * btbuildempty only initialises the INIT fork, leaving MAIN fork pages
 * absent when btinsert tries to locate the index metapage).
 *
 * Flow:
 *   pg_vault_tde_ambuild
 *     → saved_btree_methods.ambuild (= btbuild)
 *       → table_index_build_scan(heap, index, ..., btbuildCallback, ...)
 *         → pg_vault_tde_index_build_range_scan (via heap's TableAmRoutine)
 *           → [for each tuple] encrypt values[], then btbuildCallback(...)
 *
 * Parallel build is disabled (amcanbuildparallel = false, set in
 * tde_iam_init, see https://www.postgresql.org/docs/current/index-functions.html ):
 * the relam impersonation below only mutates this backend's
 * in-memory Relation, but a real parallel worker opens its own fresh copy
 * of the index relation and hits core code (sortsupport.c's
 * PrepareSortSupportFromIndexRel) that unconditionally errors out on a
 * non-btree relam. Forcing a single-process build keeps every scan/sort
 * call inside this (correctly impersonated) backend.
 */
/*
 * tde_assert_not_impersonated
 *
 * pg_vault_tde_ambuild and pg_vault_tde_aminsert temporarily set
 * rd_rel->relam = BTREE_AM_OID around their delegation to nbtree, and must
 * restore it on every exit path including the error one.
 *
 * A leaked impersonation is invisible to every checking stage we run: a stale
 * relam is not invalid memory (valgrind), not undefined behaviour (UBSan), not
 * an unreachable branch (scan-build), and not something PostgreSQL itself
 * asserts on (cassert).  It is simply wrong, and it persists in the backend's
 * relcache until an unrelated invalidation happens to heal it.  The only way
 * to make that class visible is to state the invariant ourselves.
 *
 * The invariant needs no oid lookup: tde_btree_methods is returned by our
 * handler alone, which is registered for the tde_btree access method, so every
 * relation reaching these callbacks must still carry tde_btree's oid.  If one
 * carries btree's, an earlier delegated call leaked out of its window.
 *
 * Compiles to nothing without --enable-cassert; see make ci-cassert.
 */
static inline void
tde_assert_not_impersonated(Relation index)
{
    Assert(index->rd_rel->relam != BTREE_AM_OID);
}

static IndexBuildResult *
pg_vault_tde_ambuild(Relation heap, Relation index, IndexInfo *index_info)
{
    IndexBuildResult *result;
    Oid               saved_relam = index->rd_rel->relam;

    Assert(saved_btree_methods_valid);
    tde_assert_not_impersonated(index);
    
    /*
     * nbtree reads BTGetFillFactor/BTGetTargetPageFreeSpace/BTGetDeduplicateItems
     * (nbtree.h), macros whose AssertMacro requires rd_rel->relam == BTREE_AM_OID.
     * On the build path they expand at nbtsort.c:667 and :1154.  PG17 also
     * asserted in tuplesort_begin_index_btree().  Both reasons are live; 
     * do not drop this swap on the assumption that PG18 relaxed it.
     */
    index->rd_rel->relam = BTREE_AM_OID;

    /* PG_TRY ensures relam is restored even if btbuild raises an error. */
    PG_TRY();
    {
        result = saved_btree_methods.ambuild(heap, index, index_info);
    }
    PG_CATCH();
    {
        index->rd_rel->relam = saved_relam;
        PG_RE_THROW();
    }
    PG_END_TRY();
    index->rd_rel->relam = saved_relam;

    return result;
}

/* ── AMINSERT ───────────────────────────────────────────────────────────── */

static bool
pg_vault_tde_aminsert(Relation index, Datum *values, bool *isnull,
                      ItemPointer heap_tid, Relation heap,
                      IndexUniqueCheck check_unique,
                      bool index_unchanged,
                      IndexInfo *index_info)
{
    Datum   enc_values[INDEX_MAX_KEYS];
    bool    enc_isnull[INDEX_MAX_KEYS];
    int     ncols = index_info->ii_NumIndexAttrs;
    int     i;
    bool    result;
    Oid     saved_relam;

    Assert(saved_btree_methods_valid);
    tde_assert_not_impersonated(index);

    memcpy(enc_isnull, isnull, ncols * sizeof(bool));

    /* Encrypt each non-null indexed column */
    for (i = 0; i < ncols; i++)
    {
        if (isnull[i])
        {
            enc_values[i] = (Datum) 0;
        }
        else if (TDE_IS_ENC_OPS_COL(index, i))
        {
            enc_values[i] = tde_iam_encrypt_fixed_type_datum(
                                index,
                                values[i],
                                index->rd_opcintype[i]);
        }
        else
        {
            Form_pg_attribute att = TupleDescAttr(index->rd_att, i);

            enc_values[i] = tde_iam_encrypt_index_datum(index,
                                                        values[i],
                                                         att->attbyval,
                                                         att->attlen);
        }
    }

    /*
     * nbtree reads BTGetDeduplicateItems (nbtinsert.c:2779, the dedup /
     * bottom-up delete pass) and BTGetFillFactor (nbtsplitloc.c:172, via
     * _bt_split), macros in nbtree.h whose AssertMacro requires
     * rd_rel->relam == BTREE_AM_OID.  tde_btree registers its own AM oid, so
     * impersonate btree for the delegated call — same pattern as
     * pg_vault_tde_ambuild above and rd_tableam in
     * pg_vault_tde_relation_copy_for_cluster (tam.c).  RelationData is a
     * per-backend relcache copy, so the swap is invisible to other backends.
     *
     * Neither macro is reached until a leaf page fills, which is why a single
     * INSERT never trips the assert and only a bulk load catches a regression.
     *
     * The swap sits AFTER the encryption loop on purpose: tde_iam_encrypt_*
     * can ereport(ERROR), and an error thrown before the swap has nothing to
     * restore.  Widening this window would leave relam impersonated in the
     * relcache for the rest of the session — a corruption no assert, no
     * sanitizer and no memory checker can see.
     *
     * PG_TRY restores relam even if the delegated aminsert raises.
     */
    saved_relam = index->rd_rel->relam;
    index->rd_rel->relam = BTREE_AM_OID;

    
    PG_TRY();
    { 
        result = saved_btree_methods.aminsert(index, enc_values, enc_isnull,
                                    heap_tid, heap,
                                    check_unique, index_unchanged,
                                    index_info);
    }
    PG_CATCH();
    {
        index->rd_rel->relam = saved_relam;
        PG_RE_THROW();
    }
    PG_END_TRY();

    index->rd_rel->relam = saved_relam;

    /*
     * btinsert has copied the key into an IndexTuple of its own, so the bytea
     * this function produced per column is dead.  Releasing it here matters
     * because aminsert runs in ExecutorState — reset once per statement, not
     * once per tuple — so on a bulk load these accumulate for the whole
     * INSERT.  A datum that came back unchanged was never ours: tde_btree
     * stores fixed-size keys without an enc_ops opclass in plaintext, and
     * tde_iam_encrypt_fixed_type_datum returns its input on an unknown typoid.
     */
    for (i = 0; i < ncols; i++)
    {
        if (!isnull[i] && DatumGetPointer(enc_values[i]) != DatumGetPointer(values[i]))
            pfree(DatumGetPointer(enc_values[i]));
    }

    return result;
}

/* ── AMBEGINSCAN ────────────────────────────────────────────────────────── */

static IndexScanDesc
pg_vault_tde_ambeginscan(Relation index, int nkeys, int norderbys)
{
    tde_assert_not_impersonated(index);
    /*
     * Delegate entirely to btree.  The ScanKey encryption happens in
     * amrescan, called immediately after by the executor.
     */
    Assert(saved_btree_methods_valid);
    {
        IndexScanDesc scan = saved_btree_methods.ambeginscan(index, nkeys, norderbys);

        /*
         * RelationGetIndexScan() allocates keyData with palloc(), not
         * palloc0(), and nothing reads it until btrescan() overwrites it
         * wholesale.  Zeroing it here buys the one piece of per-scan state the
         * key lifetime logic needs: on the first rescan an empty slot is
         * reliably NULL instead of garbage that looks like a pointer.
         */
        if (scan->keyData != NULL && scan->numberOfKeys > 0)
            memset(scan->keyData, 0, scan->numberOfKeys * sizeof(ScanKeyData));

        return scan;
    }
}

/* ── AMRESCAN ───────────────────────────────────────────────────────────── */

static void
pg_vault_tde_amrescan(IndexScanDesc scan, ScanKey keys, int nkeys,
                      ScanKey orderbys, int norderbys)
{
    int i;

    tde_assert_not_impersonated(scan->indexRelation);

    Assert(saved_btree_methods_valid);

    /*
     * tde_btree answers equality only.  AES-SIV preserves equality and
     * nothing else, so a range key walked against the ciphertext order
     * returns wrong rows without any error.  The planner never builds such a
     * scan on its own — pg_vault_tde_amcostestimate() prices it out and
     * tde_iam_get_relation_info() strips the index of its sort order — so a
     * key reaching this point means the plan was forced.  Fail it here,
     * before anything is encrypted, rather than return wrong rows.
     *
     * An array key cannot reach us either: amsearcharray is off, so the
     * executor expands IN / = ANY into one scalar rescan per element.  If one
     * ever does, encrypting it as a scalar would hand btree an array header
     * made of ciphertext.
     */
    for (i = 0; keys != NULL && i < nkeys; i++)
    {
        if ((keys[i].sk_flags & SK_ISNULL) != 0)
            continue;           /* IS NULL / IS NOT NULL: no value compared */

        if ((keys[i].sk_flags & SK_SEARCHARRAY) != 0)
            elog(ERROR, "tde_btree received an array scan key although amsearcharray is off");

        if (keys[i].sk_strategy != BTEqualStrategyNumber)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("pg_vault_tde: tde_btree index \"%s\" supports only equality lookups",
                            RelationGetRelationName(scan->indexRelation)),
                     errdetail("Index keys are encrypted with AES-SIV, which preserves equality "
                               "but not order: a range comparison through this index would "
                               "return wrong rows."),
                     errhint("The planner avoids tde_btree for such conditions unless the plan "
                             "is forced; check enable_seqscan and enable_bitmapscan.")));
    }

    /*
     * Release what the previous rescan built, before btrescan() overwrites the
     * pointers with this round's keys and they become unreachable.
     */
    for (i = 0; i < scan->numberOfKeys; i++)
        tde_iam_release_scan_key(scan, i);

    if (keys != NULL)
    {
        for (i = 0; i < nkeys; i++)
        {
            if ((keys[i].sk_flags & SK_ISNULL) == 0 &&
                keys[i].sk_strategy == BTEqualStrategyNumber)
            {
                int col = keys[i].sk_attno - 1;

                if (TDE_IS_ENC_OPS_COL(scan->indexRelation, col))
                {
                    keys[i].sk_argument =
                        tde_iam_encrypt_fixed_type_datum(scan->indexRelation, keys[i].sk_argument, scan->indexRelation->rd_opcintype[col]);

                    /* Set the sk_func (boolean cmp function for rd_opcintype) to the bytea one*/
                    fmgr_info(F_BYTEAEQ, &keys[i].sk_func); 
                }
                else
                {
                    Form_pg_attribute att = TupleDescAttr(scan->indexRelation->rd_att, col);
                    keys[i].sk_argument =
                        tde_iam_encrypt_index_datum(scan->indexRelation,
                                                    keys[i].sk_argument,
                                                    att->attbyval,
                                                    att->attlen);
                }
            }
        }
    }

    saved_btree_methods.amrescan(scan, keys, nkeys, orderbys, norderbys);
}

/* ── AMENDSCAN ──────────────────────────────────────────────────────────── */

static void
pg_vault_tde_amendscan(IndexScanDesc scan)
{
    int i;

    Assert(saved_btree_methods_valid);

    /* The set the last rescan built has no next rescan to release it. */
    for (i = 0; i < scan->numberOfKeys; i++)
        tde_iam_release_scan_key(scan, i);

    saved_btree_methods.amendscan(scan);
}

/* ── AMVALIDATE ─────────────────────────────────────────────────────────── */

/*
 * pg_vault_tde_amvalidate
 *
 * Validates an operator class.  For standard tde_*_ops classes (no STORAGE
 * override) this delegates to btvalidate.  For tde_*_enc_ops classes
 * (opckeytype = BYTEAOID, opcintype ≠ BYTEAOID) we return true directly:
 * those classes register strategy operators with the original column type
 * (e.g. int4 = int4) instead of (bytea = bytea), so btvalidate would reject
 * them, but they are correct by construction.
 */
static bool
pg_vault_tde_amvalidate(Oid opclassoid)
{
    HeapTuple       classtup;
    Form_pg_opclass classform;
    bool            is_enc_ops;

    Assert(saved_btree_methods_valid);

    /*
     * enc_ops operator classes (tde_int4_enc_ops, tde_int8_enc_ops, etc.)
     * register their strategy operators with the original column type
     * (int4, int8, …) so the planner can match equality clauses against
     * the index.  btvalidate, however, expects operator types to equal
     * opckeytype (BYTEAOID) when STORAGE bytea is set and would emit
     * warnings and return false.  Skip btvalidate for these classes; they
     * are valid by construction.
     *
     * Detection: enc_ops classes have opckeytype = BYTEAOID and
     * opcintype ≠ BYTEAOID.  Plain tde_*_ops and tde_text_ops have
     * opckeytype = InvalidOid (same as opcintype), so they delegate
     * normally.
     */
    classtup = SearchSysCache1(CLAOID, ObjectIdGetDatum(opclassoid));
    if (!HeapTupleIsValid(classtup))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("cache lookup failed for operator class %u",
                        opclassoid)));

    classform = (Form_pg_opclass) GETSTRUCT(classtup);
    is_enc_ops = (OidIsValid(classform->opckeytype) &&
                  classform->opckeytype == BYTEAOID &&
                  classform->opcintype  != BYTEAOID);
    ReleaseSysCache(classtup);

    if (is_enc_ops)
        return true;

    return saved_btree_methods.amvalidate(opclassoid);
}

/* ── PLANNER: EQUALITY ONLY ──────────────────────────────────────────────── */

/*
 * What the planner may ask of a tde_btree index, and why nothing else.
 *
 * AES-SIV maps equal plaintexts to equal ciphertexts and preserves nothing
 * else, so an equality lookup is the only question the tree can answer.
 * The v1.5 operator classes tde_text_ops, tde_bytea_ops and tde_numeric_ops
 * nevertheless declare < <= >= > as well, and the planner believed them:
 * range predicates, ORDER BY ... LIMIT, min()/max() and merge joins read the
 * index in ciphertext order and returned wrong rows without any error.  The
 * operator classes cannot be amended in place (ALTER OPERATOR FAMILY ... DROP
 * OPERATOR is refused while the class exists), so the rule is enforced here,
 * where the planner meets the index:
 *
 *   - tde_iam_get_relation_info() takes the sort order away from every
 *     tde_btree index, which removes ORDER BY, min()/max() and merge-join
 *     uses, and drops the indexes that cannot even answer equality;
 *   - pg_vault_tde_amcostestimate() prices out any path whose index clauses
 *     are not all equality, so range predicates go to a sequential scan;
 *   - pg_vault_tde_amrescan() fails a range key that reaches it anyway,
 *     which only a forced plan can do.
 *
 * AM-level amcanorder = false would be the obvious lever and is not an
 * option: PrepareSortSupportFromIndexRel() rejects a non-amcanorder index
 * during the btree-impersonated build (see pg_vault_tde_ambuild()).
 */

/* Added to both cost figures of a path that tde_btree must not serve. */
#define TDE_IAM_NON_EQUALITY_COST   1.0e10

/*
 * v1.5 operator classes for fixed-size types.  Their keys are stored in
 * plaintext (tde_iam_encrypt_index_datum() cannot widen a fixed-length key),
 * and v1.7 replaced them with the tde_*_enc_ops defaults.  Kept only so that
 * indexes built on them keep working; new indexes may not use them.
 */
static const char *const tde_iam_legacy_opclasses[] = {
    "tde_int4_ops", "tde_int8_ops", "tde_uuid_ops",
    "tde_date_ops", "tde_timestamptz_ops"
};

/*
 * tde_iam_path_is_equality_only — would this index path ask the tree
 * anything but "which entries equal these values"?
 */
static bool
tde_iam_path_is_equality_only(IndexPath *path)
{
    ListCell   *lc;

    /* No ordered use.  tde_iam_get_relation_info() already prevents it. */
    if (path->path.pathkeys != NIL || path->indexorderbys != NIL)
        return false;

    foreach(lc, path->indexclauses)
    {
        IndexClause *iclause = lfirst_node(IndexClause, lc);
        Oid          opfamily = path->indexinfo->opfamily[iclause->indexcol];
        ListCell    *lc2;

        foreach(lc2, iclause->indexquals)
        {
            Node   *clause = (Node *) lfirst_node(RestrictInfo, lc2)->clause;
            Oid     opno;

            if (IsA(clause, NullTest))
                continue;
            else if (IsA(clause, OpExpr))
                opno = ((OpExpr *) clause)->opno;
            else if (IsA(clause, ScalarArrayOpExpr))
                opno = ((ScalarArrayOpExpr *) clause)->opno;
            else
                return false;   /* RowCompareExpr, or anything unforeseen */

            if (get_op_opfamily_strategy(opno, opfamily) != BTEqualStrategyNumber)
                return false;
        }
    }

    return true;
}

/*
 * pg_vault_tde_amcostestimate — btree's estimate, plus a prohibitive cost
 * for any path that is not equality-only.  Pricing rather than removing the
 * path keeps the planner's search intact: a sequential scan always exists,
 * and it wins.
 */
static void
pg_vault_tde_amcostestimate(PlannerInfo *root, IndexPath *path, double loop_count,
                            Cost *indexStartupCost, Cost *indexTotalCost,
                            Selectivity *indexSelectivity, double *indexCorrelation,
                            double *indexPages)
{
    saved_btree_methods.amcostestimate(root, path, loop_count,
                                       indexStartupCost, indexTotalCost,
                                       indexSelectivity, indexCorrelation,
                                       indexPages);

    if (!tde_iam_path_is_equality_only(path))
    {
        *indexStartupCost += TDE_IAM_NON_EQUALITY_COST;
        *indexTotalCost   += TDE_IAM_NON_EQUALITY_COST;
    }
}

/*
 * tde_iam_index_cannot_answer_equality — index columns on which even an
 * equality lookup through the tree misses rows.
 *
 *   numeric: tde_numeric_ops compares with numeric_cmp, applied to the
 *     ciphertext bytes as if they were a numeric; that is not an ordering,
 *     and the descent misses keys.  Equal values can also differ in bytes
 *     (1.5 and 1.50), which AES-SIV then keeps apart.
 *   nondeterministic collation: equality under the collation is not byte
 *     equality, and AES-SIV can only match identical bytes.
 */
static bool
tde_iam_index_cannot_answer_equality(IndexOptInfo *info)
{
    int         i;

    for (i = 0; i < info->nkeycolumns; i++)
    {
        Oid     collid = info->indexcollations[i];

        if (info->opcintype[i] == NUMERICOID)
            return true;
        if (OidIsValid(collid) && !get_collation_isdeterministic(collid))
            return true;
    }
    return false;
}

/*
 * tde_iam_get_relation_info — called from the get_relation_info_hook
 * (pg_vault_tde.c) for every relation the planner considers.
 */
void
tde_iam_get_relation_info(PlannerInfo *root, Oid relationObjectId,
                          bool inhparent, RelOptInfo *rel)
{
    ListCell   *lc;

    foreach(lc, rel->indexlist)
    {
        IndexOptInfo *info = lfirst_node(IndexOptInfo, lc);

        if (info->amcostestimate != pg_vault_tde_amcostestimate)
            continue;           /* not a tde_btree index */

        /*
         * An index that misses rows on equality is not offered to the
         * planner at all: the query runs as a sequential scan and is correct.
         * Writes still maintain it, and uniqueness and ON CONFLICT inference
         * read the index list from the relcache, not from here.
         */
        if (tde_iam_index_cannot_answer_equality(info))
        {
            rel->indexlist = foreach_delete_current(rel->indexlist, lc);
            continue;
        }

        /*
         * No sort order: no ORDER BY, min()/max() or merge-join input.
         * sortopfamily is the one field the planner reads to decide whether
         * an index is ordered (build_index_pathkeys, and the min/max probe
         * in get_actual_variable_range).  reverse_sort and nulls_first must
         * stay: btcostestimate() reads reverse_sort[0] unconditionally for
         * the correlation estimate, and a NULL there is a segfault.
         */
        info->sortopfamily = NULL;
    }
}

/*
 * tde_iam_check_new_index — refuse a tde_btree index that cannot answer
 * equality, or that would store its keys in plaintext.
 *
 * Called from the object_access_hook at OAT_POST_CREATE, which every index
 * creation reaches: CREATE INDEX, the EXCLUDE constraints of CREATE TABLE and
 * ALTER TABLE ... ADD CONSTRAINT, the rebuild ALTER COLUMN ... TYPE performs,
 * pg_restore.  A check in the ProcessUtility hook sees only the first of
 * those, and the others matter most: UNIQUE and EXCLUDE enforcement reads the
 * index directly, without the planner, so an index that misses equal values
 * silently lets duplicates in.  REINDEX is exempted by the caller: it
 * rebuilds what already exists.
 *
 * `is_internal` is ObjectAccessPostCreate's flag, true for the rebuild of an
 * existing index (ALTER COLUMN ... TYPE): the plaintext-key classes are then
 * let through, as they only carry over an index someone already built.
 */
void
tde_iam_check_new_index(Oid indexOid, bool is_internal)
{
    Relation    index = index_open(indexOid, NoLock);
    Oid         heapOid = index->rd_index->indrelid;
    oidvector  *indclass;
    int         i;

    indclass = (oidvector *) DatumGetPointer(
        SysCacheGetAttrNotNull(INDEXRELID, index->rd_indextuple, Anum_pg_index_indclass));

    for (i = 0; i < IndexRelationGetNumberOfKeyAttributes(index); i++)
    {
        AttrNumber  attnum = index->rd_index->indkey.values[i];
        const char *column = attnum != 0 ? get_attname(heapOid, attnum, false) : "expression";
        Oid         collid = index->rd_indcollation[i];
        HeapTuple   opctup;
        const char *opcname;
        int         j;

        if (index->rd_opcintype[i] == NUMERICOID)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("pg_vault_tde: tde_btree cannot index numeric column \"%s\"",
                            column),
                     errdetail("Equal numeric values do not always encrypt to equal index "
                               "keys (1.5 and 1.50 are equal), and the numeric operator class "
                               "cannot order encrypted keys: lookups, UNIQUE and EXCLUDE "
                               "checks through such an index miss equal values."),
                     errhint("Leave the column unindexed, or drop the tde_btree index before "
                             "changing the column to numeric. Correct numeric support is "
                             "planned for pg_vault_tde 1.8.")));

        if (OidIsValid(collid) && !get_collation_isdeterministic(collid))
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("pg_vault_tde: tde_btree cannot index column \"%s\" with "
                            "nondeterministic collation \"%s\"",
                            column, get_collation_name(collid)),
                     errdetail("Encrypted index keys can only match byte-identical values, so "
                               "equality under this collation — and UNIQUE or EXCLUDE checks "
                               "relying on it — would miss equal values."),
                     errhint("Index the column with a deterministic collation.")));

        if (is_internal)
            continue;

        opctup = SearchSysCache1(CLAOID, ObjectIdGetDatum(indclass->values[i]));
        if (!HeapTupleIsValid(opctup))
            elog(ERROR, "cache lookup failed for operator class %u", indclass->values[i]);
        opcname = pstrdup(NameStr(((Form_pg_opclass) GETSTRUCT(opctup))->opcname));
        ReleaseSysCache(opctup);

        /*
         * A plaintext-key operator class is the same exposure as a plaintext
         * index access method, so it follows the same rule: refused, unless
         * pg_vault_tde.allow_plaintext_index is on — which is also what lets
         * a dump that names one (pg_dump writes non-default classes out) be
         * restored.
         */
        for (j = 0; j < (int) lengthof(tde_iam_legacy_opclasses); j++)
        {
            if (strcmp(opcname, tde_iam_legacy_opclasses[j]) != 0)
                continue;

            ereport(pg_vault_tde_allow_plaintext_index ? WARNING : ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("pg_vault_tde: operator class \"%s\" stores index keys in "
                            "plaintext", opcname),
                     errdetail("It is a v1.5 operator class, kept only so that indexes "
                               "already built on it keep working."),
                     pg_vault_tde_allow_plaintext_index
                     ? errhint("Allowed because pg_vault_tde.allow_plaintext_index is on. "
                               "Omit the operator class to use the encrypted default, "
                               "%.*s_enc_ops.", (int) (strlen(opcname) - 4), opcname)
                     : errhint("Omit the operator class to use the encrypted default, "
                               "%.*s_enc_ops, or set pg_vault_tde.allow_plaintext_index = on "
                               "to allow it with a WARNING.",
                               (int) (strlen(opcname) - 4), opcname)));
        }
    }

    index_close(index, NoLock);
}

/* ── INIT + HANDLER ─────────────────────────────────────────────────────── */

/*
 * tde_iam_init
 *
 * Copies the btree IndexAmRoutine into our mutable tde_btree_methods
 * struct and overrides the four key-manipulating callbacks.  Must be
 * called from _PG_init() exactly once, after GUC registration and before
 * any index operation.
 *
 * Uses F_BTHANDLER (OID 330 from utils/fmgroids.h) to call the btree
 * handler function directly, which is the same mechanism PostgreSQL uses
 * internally when it creates a btree-backed index.
 */
void
tde_iam_init(void)
{
    /*
     * Call the btree handler function to get a freshly allocated
     * IndexAmRoutine populated with all btree callbacks.
     * PointerGetDatum(NULL) passes a null 'internal' argument, which is
     * what bthandler() expects (it ignores it).
     */
    IndexAmRoutine *tmp = (IndexAmRoutine *) DatumGetPointer(
        OidFunctionCall1(F_BTHANDLER, PointerGetDatum(NULL)));

    Assert(tmp != NULL);
    Assert(tmp->type == T_IndexAmRoutine);

    /*
     * Copy the btree callbacks into TWO static structs:
     *  - saved_btree_methods: unchanged original, used for delegation
     *  - tde_btree_methods:   patched copy returned to PG via handler
     *
     * Both are BSS statics, so their content is reliably inherited by
     * forked backends (no stale heap pointers).
     */
    memcpy(&saved_btree_methods, tmp, sizeof(IndexAmRoutine));
    memcpy(&tde_btree_methods, tmp, sizeof(IndexAmRoutine));

    /* Safe to free now — we've memcpy'd everything we need */
    pfree(tmp);

    saved_btree_methods_valid = true;

    /* Override the callbacks that need to see or produce encrypted keys */
    tde_btree_methods.ambuild     = pg_vault_tde_ambuild;
    tde_btree_methods.aminsert    = pg_vault_tde_aminsert;
    tde_btree_methods.ambeginscan = pg_vault_tde_ambeginscan;
    tde_btree_methods.amendscan   = pg_vault_tde_amendscan;
    tde_btree_methods.amrescan    = pg_vault_tde_amrescan;
    tde_btree_methods.amvalidate  = pg_vault_tde_amvalidate;


    /* Encrypted tuples are unencryptable only if they comes from the table */
    tde_btree_methods.amcanreturn = NULL;

    /*
     * Disable parallel index build.  pg_vault_tde_ambuild delegates to
     * btree's ambuild by impersonating index->rd_rel->relam = BTREE_AM_OID
     * for the duration of the call — but that impersonation only mutates
     * the LEADER's in-memory Relation. Real parallel workers open their own
     * fresh copy of the index relation (nbtsort.c's _bt_parallel_build_main
     * calling index_open()), which reports the true tde_btree AM oid. That
     * reaches core code we cannot hook (sortsupport.c's
     * PrepareSortSupportFromIndexRel), which unconditionally
     * ereport(ERROR)s on a non-btree relam. Forcing a single-process build
     * keeps every scan/sort call inside the (correctly impersonated) leader.
     */
    tde_btree_methods.amcanbuildparallel = false;

    /*
     * IN (...) / = ANY (...): let the executor expand the array into one
     * scalar rescan per element.  With amsearcharray on, btree receives a
     * single SK_SEARCHARRAY key whose argument is the array itself, and
     * pg_vault_tde_amrescan() has no way to encrypt the elements in place.
     * The planner then uses bitmap index scans for such clauses.
     */
    tde_btree_methods.amsearcharray = false;

    /*
     * Price out every path that would compare anything but equality — see
     * pg_vault_tde_amcostestimate().  The function pointer also identifies
     * tde_btree indexes to the planner hook, tde_iam_get_relation_info().
     */
    tde_btree_methods.amcostestimate = pg_vault_tde_amcostestimate;

    /*
     * Allow STORAGE type ≠ opcintype for tde_*_enc_ops operator classes.
     * Standard btree sets amstorage=false; we need true so that
     * CREATE OPERATOR CLASS ... STORAGE bytea does not fail with
     * "storage type cannot be different from data type".
     */
    tde_btree_methods.amstorage   = true;

    ereport(DEBUG1,
            (errmsg("[IAM] tde_btree initialized: btree AM wrapped with "
                    "AES-256-SIV encryption layer")));
}

/*
 * pg_vault_tde_get_iam_routine
 *
 * Returns a palloc'd copy of tde_btree_methods for the handler function.
 *
 * PostgreSQL's InitIndexAmRoutine() calls GetIndexAmRoutine() to obtain
 * the IndexAmRoutine struct, copies it into rd_indexcxt, then pfree()'s
 * the original pointer.  If we returned &tde_btree_methods (a static BSS
 * variable), pfree would crash with "invalid pointer (header 0x0)".
 * Therefore we must return a freshly palloc'd copy that pfree can safely
 * reclaim.
 *
 * If tde_iam_init() has not yet been called (e.g. during pg_dump or
 * a direct pg_vault_tde_iam_handler call without shared_preload_libraries),
 * it is called here as a lazy initializer to ensure the struct is valid.
 */
extern const IndexAmRoutine *pg_vault_tde_get_iam_routine(void);
const IndexAmRoutine *
pg_vault_tde_get_iam_routine(void)
{
    IndexAmRoutine *result;

    if (!saved_btree_methods_valid)
        tde_iam_init();

    result = (IndexAmRoutine *) palloc(sizeof(IndexAmRoutine));
    memcpy(result, &tde_btree_methods, sizeof(IndexAmRoutine));
    return result;
}

/*
 * tde_enc_bytea_cmp
 *
 * B-Tree support function 1 (three-way comparator) for tde_*_enc_ops
 * operator classes.  Both arguments are AES-256-SIV ciphertexts of the
 * same length (20, 24, or 32 bytes depending on the original type).
 *
 * AES-SIV is deterministic: equal plaintexts → equal ciphertexts under
 * the same DEK.  The memcmp order has no semantic meaning; range scans
 * on enc_ops indexes return arbitrary results (documented limitation).
 */
PG_FUNCTION_INFO_V1(tde_enc_bytea_cmp);
Datum
tde_enc_bytea_cmp(PG_FUNCTION_ARGS)
{
    bytea  *a   = PG_GETARG_BYTEA_PP(0);
    bytea  *b   = PG_GETARG_BYTEA_PP(1);
    int     la  = VARSIZE_ANY_EXHDR(a);
    int     lb  = VARSIZE_ANY_EXHDR(b);
    int     cmp = memcmp(VARDATA_ANY(a), VARDATA_ANY(b), Min(la, lb));

    if (cmp != 0)
        PG_RETURN_INT32(cmp > 0 ? 1 : -1);
    PG_RETURN_INT32(la > lb ? 1 : (la < lb ? -1 : 0));
}
