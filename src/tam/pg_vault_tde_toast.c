/*
 * pg_vault_tde_toast.c - TOAST data encryption for pg_vault_tde
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * When a column value exceeds ~2KB, PostgreSQL's TOAST machinery:
 *   1. (Optionally) compresses the datum (pglz or lz4)
 *   2. Splits it into TDE_TOAST_CHUNK_SIZE byte chunks
 *   3. Stores chunks in a side relation (pg_toast_<oid>)
 *   4. Replaces the main tuple column with an "external" varlena pointer
 *
 * The challenge for TDE: by the time our TAM's tuple_insert sees a main-
 * table tuple, the oversized values have ALREADY been processed by the TOAST
 * machinery and are stored (in plaintext) in the TOAST table.  The main
 * tuple contains only a VARATT_IS_EXTERNAL pointer.
 *
 * SOLUTION: We enforce that the TOAST table associated with any TDE-enabled
 * relation ALSO uses the pg_vault_tde Table AM.  PostgreSQL creates TOAST
 * tables via heap_create_with_catalog; we hook this via the
 * relation_set_new_filelocator TAM callback to set the correct AM Oid before
 * the first write.  When TOAST chunks are inserted into the TOAST table they
 * pass through our tuple_insert hook, which calls tde_toast_encrypt_chunk.
 *
 * This approach means:
 *  - TOAST chunk encryption is transparent: no changes to query planner.
 *  - Compression happens BEFORE encryption (by PostgreSQL) \u2014 correct order.
 *  - Each chunk gets its own random GCM IV, so identical chunks produce
 *    different ciphertexts (no information leakage via deduplication).
 *  - The external TOAST pointer in the main table is NOT encrypted (it
 *    contains only an OID + chunk sequence, no payload data).
 */
#include "postgres.h"

#include "common/pg_lzcompress.h"   /* pglz_compress, PGLZ_strategy_default, PGLZ_MAX_OUTPUT */
#include "access/genam.h"
#include "access/heapam.h"
#include "access/table.h"
#include "varatt.h"
#include "access/toast_compression.h" /* TOAST_PGLZ_COMPRESSION_ID */
#include "utils/rel.h"              /* RelationGetRelid */
#include "access/toast_internals.h"
#include "access/heaptoast.h"
#include "access/xact.h"
#include "utils/memutils.h"
#include "access/toast_helper.h"
#include "access/detoast.h"

#include "src/include/pg_vault_tde_crypto.h"
#include "src/include/pg_vault_tde_tam.h"
#include "src/include/pg_vault_tde_toast.h"
/*
 * tde_toast_encrypt_chunk
 *
 * Encrypts one raw TOAST chunk (up to TDE_TOAST_CHUNK_SIZE bytes) using
 * AES-256-GCM.  Called from the TAM tuple_insert hook when inserting into a
 * TOAST table that has been assigned the pg_vault_tde AM.
 *
 * Each chunk gets a fresh random IV (generated inside tde_gcm_encrypt via
 * pg_strong_random).  This is intentional: even if two chunks contain the
 * same data (unlikely after pglz/lz4, but possible for sparse data), they
 * produce different ciphertexts.
 *
 * @param chunk_data   raw TOAST chunk bytes
 * @param chunk_len    number of bytes in this chunk
 * @param out_len      set to encrypted output length
 * @returns            palloc'd encrypted buffer; caller cleans up
 */
char *
tde_toast_encrypt_chunk(Oid parent_relid, const char *chunk_data, Size chunk_len, Size *out_len)
{
    Assert(chunk_data != NULL);
    Assert(chunk_len > 0 && chunk_len <= TOAST_MAX_CHUNK_SIZE);

    /*
     * Delegate to the shared AES-256-GCM primitive with the parent
     * relation's DEK.  The [IV|CT|TAG|VERSION|GEN] wire format is
     * self-contained: each chunk carries its own IV.
     */
    return tde_gcm_encrypt(parent_relid, chunk_data, chunk_len, out_len);
}

/*
 * tde_toast_decrypt_chunk
 *
 * Decrypts a TOAST chunk previously encrypted by tde_toast_encrypt_chunk.
 * Verifies the GCM authentication tag before returning plaintext; any
 * tampering aborts via ereport(ERROR).
 *
 * @param enc_data     [IV|CT|TAG|VERSION|GEN] encrypted chunk
 * @param enc_len      total encrypted length
 * @param out_len      set to decrypted chunk length
 * @returns            palloc'd plaintext chunk; caller cleans up
 */
char *
tde_toast_decrypt_chunk(Oid parent_relid, const char *enc_data, Size enc_len, Size *out_len)
{
    char *out;

    Assert(enc_data != NULL);
    Assert(enc_len > TDE_V4_OVERHEAD);

    /* Chunk path (not the hot seq-scan): palloc the plaintext destination. */
    out = (char *) palloc(enc_len - TDE_V4_OVERHEAD);
    if (!tde_gcm_decrypt(parent_relid, enc_data, enc_len, out, out_len))
    {
        pfree(out);
        return NULL;
    }
    return out;
}

/*
 * TOAST read path note:
 *
 * An explicit tde_toast_reassemble() function is NOT required.  When the
 * TOAST table uses encrypted_heap AM (pg_vault_tde.toast_encryption = on),
 * the standard PG read path already decrypts chunks transparently:
 *
 *   heap_fetch_toast_slice(toastrel, ...)
 *     └─ systable_beginscan_ordered(toastrel, toastidx, ...)
 *          └─ index_getnext_slot()
 *               └─ table_index_fetch_tuple()          ← dispatches via rd_tableam
 *                    └─ tde_index_fetch_tuple()        ← our TAM override
 *                         └─ decode_slot()             ← decrypts each chunk tuple
 *                              └─ tde_decrypt_heap_tuple(chunk, toastrel_oid)
 *
 * Each TOAST chunk tuple is decrypted before fastgetattr() extracts
 * chunk_data, so heap_fetch_toast_slice reassembles plaintext chunks
 * into the final Datum without any TDE-specific logic at its level.
 */




Datum pg_vault_tde_toast_save_datum(Relation rel, Datum value, 
                                            struct varlena* oldexternal, int options)
{
    Relation  toast_rel; 
    Relation* toast_idxs;
    HeapTuple toast_tup;
    TupleDesc toast_tup_desc;
    Datum t_values[3];
    bool t_isnull[3];

    CommandId mycid = GetCurrentCommandId(true);
    
    /*
     * Declare volatile to prevent -Wclobbered: this variable is initialized
     * before the PG_TRY block (inside the while loop below) and read after
     * the loop; volatile tells the compiler not to keep it in a register
     * across the longjmp boundary.
     */
    volatile struct varatt_external toast_pointer;
    struct varlena *extval;

    union {
        struct varlena hdr;

        char data[TOAST_MAX_CHUNK_SIZE + VARHDRSZ];

        int32 align_it;
    } chunk_data = {0};

    int32 chunk_size;
    int32 chunk_seq = 0;
    char* data_p;
    int32 data_todo;
    Pointer dval = DatumGetPointer(value);
    int num_indexes;
    int validIndex;

    Assert(!VARATT_IS_EXTERNAL(value));

    /*
	 * Open the toast relation and its indexes.  We can use the index to check
	 * uniqueness of the OID we assign to the toasted item, even though it has
	 * additional columns besides OID.
	 */

    toast_rel = table_open(rel->rd_rel->reltoastrelid, RowExclusiveLock);
    toast_tup_desc = toast_rel->rd_att;

    validIndex = toast_open_indexes(toast_rel, RowExclusiveLock, &toast_idxs, &num_indexes);

    /*
	 * Get the data pointer and length, and compute va_rawsize and va_extinfo.
	 *
	 * va_rawsize is the size of the equivalent fully uncompressed datum, so
	 * we have to adjust for short headers.
	 *
	 * va_extinfo stored the actual size of the data payload in the toast
	 * records and the compression method in first 2 bits if data is
	 * compressed.
	 */

    if(VARATT_IS_SHORT(dval))
    {
        data_p = VARDATA_SHORT(dval);
        data_todo = VARSIZE_SHORT(dval) - VARHDRSZ_SHORT;
        toast_pointer.va_rawsize = data_todo + VARHDRSZ;
        toast_pointer.va_extinfo = data_todo;
    }
    else if (VARATT_IS_COMPRESSED(dval)) 
    {
        data_p = VARDATA(dval);
        data_todo = VARSIZE(dval) - VARHDRSZ;

        /* rawsize in compressed datum is just the size of the payload */
        toast_pointer.va_rawsize = VARDATA_COMPRESSED_GET_EXTSIZE(dval) + VARHDRSZ;
        VARATT_EXTERNAL_SET_SIZE_AND_COMPRESS_METHOD(toast_pointer, data_todo, 
                                                     VARDATA_COMPRESSED_GET_COMPRESS_METHOD(dval));

        Assert(VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer));
    }
    else {
        data_p = VARDATA(dval);
        data_todo = VARSIZE(dval) - VARHDRSZ;
        toast_pointer.va_rawsize = VARSIZE(dval);
        toast_pointer.va_extinfo = data_todo;
    }

    /*
	 * Insert the correct table OID into the result TOAST pointer.
	 *
	 * Normally this is the actual OID of the target toast table, but during
	 * table-rewriting operations such as CLUSTER, we have to insert the OID
	 * of the table's real permanent toast table instead.  rd_toastoid is set
	 * if we have to substitute such an OID.
	 */

    if(OidIsValid(rel->rd_toastoid))
        toast_pointer.va_toastrelid = rel->rd_toastoid;
    else 
        toast_pointer.va_toastrelid = RelationGetRelid(toast_rel);

    /*
	 * Choose an OID to use as the value ID for this toast value.
	 *
	 * Normally we just choose an unused OID within the toast table.  But
	 * during table-rewriting operations where we are preserving an existing
	 * toast table OID, we want to preserve toast value OIDs too.  So, if
	 * rd_toastoid is set and we had a prior external value from that same
	 * toast table, re-use its value ID.  If we didn't have a prior external
	 * value (which is a corner case, but possible if the table's attstorage
	 * options have been changed), we have to pick a value ID that doesn't
	 * conflict with either new or existing toast value OIDs.
	 */

    if(!OidIsValid(rel->rd_toastoid))
    {
        toast_pointer.va_valueid = GetNewOidWithIndex(toast_rel, RelationGetRelid(toast_idxs[validIndex]), (AttrNumber) 1);
    }
    else {
        toast_pointer.va_valueid = InvalidOid;
        if(oldexternal != NULL) {
            struct varatt_external old_toast_pointer;
            
            Assert(VARATT_IS_EXTERNAL_ONDISK(oldexternal));

            VARATT_EXTERNAL_GET_POINTER(old_toast_pointer, oldexternal);

            if(old_toast_pointer.va_toastrelid == rel->rd_toastoid)
            {
                toast_pointer.va_valueid = old_toast_pointer.va_valueid;
            }
        }
        
        if(toast_pointer.va_valueid == InvalidOid){
            toast_pointer.va_valueid = GetNewOidWithIndex(toast_rel, RelationGetRelid(toast_idxs[validIndex]), (AttrNumber) 1);
        }
    }

    t_values[0] = ObjectIdGetDatum(toast_pointer.va_valueid); //chunk_id    
    t_values[2] = PointerGetDatum(&chunk_data);  //Pointer to the start of the data
    t_isnull[0] = false;
    t_isnull[1] = false;
    t_isnull[2] = false;

    /*
     * Split items into chunk 
     */

    while(data_todo > 0) {
        int i; 

        chunk_size = Min((int32) TOAST_MAX_CHUNK_SIZE, data_todo);
        t_values[1] = Int32GetDatum(chunk_seq++);

        SET_VARSIZE(&chunk_data, chunk_size + VARHDRSZ);
        memcpy(VARDATA(&chunk_data), data_p, chunk_size);

        toast_tup = heap_form_tuple(toast_tup_desc, t_values, t_isnull);


        /*
         * Assing t_tableOid to rel->rd_toastoid because 
         * during table rewriting operations we have to insert the OID
	     * of the table's real permanent toast table instead.  
         */
        toast_tup->t_tableOid = OidIsValid(rel->rd_toastoid) ?
                                rel->rd_toastoid :
                                RelationGetRelid(toast_rel);

        {
            /*
            * Encrypt the TOAST chunk with the parent relation's DEK (KMS routes
            * TOAST relid → parent relid) and insert it directly via heap_insert.
            *
            * We call heap_insert directly (rather than pg_vault_tde_tuple_insert)
            * because we already have a HeapTuple, not a TupleTableSlot.
            *
            * PG_TRY ensures toast_enc is pfree'd on error; the outer PG_TRY in
            * pg_vault_tde_toast_tuple handles toast_rel / idx cleanup.
            */
            HeapTuple chunk_enc = NULL;
            
            PG_TRY();
            {
                chunk_enc = tde_encrypt_heap_tuple(toast_tup, toast_tup->t_tableOid);

                heap_insert(toast_rel, chunk_enc, mycid, options, NULL);

                /*
                * heap_insert writes the physical TID into toast_enc->t_self.
                * Copy it to toast_plain->t_self so the index_insert call below
                * can reference the correct heap tuple location.
                */

                ItemPointerCopy(&chunk_enc->t_self, &toast_tup->t_self);
            }
            PG_CATCH();
            {
                if(chunk_enc != NULL)
                    pfree(chunk_enc);
                PG_RE_THROW();
            }
            PG_END_TRY();
            pfree(chunk_enc);
        }

        for(i = 0; i < num_indexes; i++) {
            if(toast_idxs[i]->rd_index->indisready)
                index_insert(toast_idxs[i], t_values, t_isnull, 
                            &(toast_tup->t_self), 
                            toast_rel, 
                            toast_idxs[i]->rd_index->indisunique ? UNIQUE_CHECK_YES : UNIQUE_CHECK_NO,
                            false, NULL);
        }

        heap_freetuple(toast_tup);

        data_todo -= chunk_size;
        data_p += chunk_size;
    }

    toast_close_indexes(toast_idxs, num_indexes, NoLock);
    table_close(toast_rel, NoLock);

    extval = (struct varlena *) palloc(VARHDRSZ_EXTERNAL + sizeof(varatt_external));
    SET_VARTAG_EXTERNAL(extval, VARTAG_ONDISK);
    memcpy(VARDATA_EXTERNAL(extval), (const void *) &toast_pointer, sizeof(toast_pointer));

    return PointerGetDatum(extval);
}

 /*
 * Move an attribute to external storage.
 */
void
pg_vault_tde_toast_tuple_externalize(ToastTupleContext *ttc, int attribute, int options)
{
	Datum	   *value = &ttc->ttc_values[attribute];
	Datum		old_value = *value;
	ToastAttrInfo *attr = &ttc->ttc_attr[attribute];

	attr->tai_colflags |= TOASTCOL_IGNORE;
	*value = pg_vault_tde_toast_save_datum(ttc->ttc_rel, old_value, attr->tai_oldexternal,
							  options);
	if ((attr->tai_colflags & TOASTCOL_NEEDS_FREE) != 0)
		pfree(DatumGetPointer(old_value));
	attr->tai_colflags |= TOASTCOL_NEEDS_FREE;
	ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);
}


HeapTuple
pg_vault_tde_toast_tuple(Relation rel, HeapTuple newtup, HeapTuple oldtup, int options)
{
    TupleDesc    tupdesc = RelationGetDescr(rel);

    Size maxDataLen; 
    Size hoff;

    int          natts = tupdesc->natts;

    Datum        values[MaxHeapAttributeNumber];
    bool         isnull[MaxHeapAttributeNumber]; //Datum can't be null
    Datum        old_values[MaxHeapAttributeNumber];
    bool         old_isnull[MaxHeapAttributeNumber]; //Datum can't be null

    HeapTuple    toasted;

    ToastAttrInfo toast_attr[MaxHeapAttributeNumber];
    ToastTupleContext ttc;

    options &= ~HEAP_INSERT_SPECULATIVE;

    /*
	 * We should only ever be called for tuples of plain relations or
	 * materialized views --- recursing on a toast rel is bad news.
	 */
    Assert(rel->rd_rel->relkind == RELKIND_RELATION ||
           rel->rd_rel->relkind == RELKIND_MATVIEW);

    Assert(natts < MaxHeapAttributeNumber);

    heap_deform_tuple(newtup, tupdesc, values, isnull);
    if(oldtup != NULL) 
        heap_deform_tuple(oldtup, tupdesc, old_values, old_isnull);

    /*
     * Prepare for toasting 
     */
    ttc.ttc_rel = rel;
    ttc.ttc_values = values;
    ttc.ttc_isnull = isnull;
    if(oldtup == NULL) {
        ttc.ttc_oldvalues = NULL;
        ttc.ttc_oldisnull = NULL;
    }
    else {
        ttc.ttc_oldvalues = old_values;
        ttc.ttc_oldisnull = old_isnull;
    }

    ttc.ttc_attr = toast_attr;
    toast_tuple_init(&ttc);


    /* ----------
	 * Compress and/or save external until data fits into target length
	 *
	 *	1: Inline compress attributes with attstorage EXTENDED, and store very
	 *	   large attributes with attstorage EXTENDED or EXTERNAL external
	 *	   immediately
	 *	2: Store attributes with attstorage EXTENDED or EXTERNAL external
	 *	3: Inline compress attributes with attstorage MAIN
	 *	4: Store attributes with attstorage MAIN external
	 * ----------
	 */

     /* compute header overhead --- this should match heap_form_tuple() */
	hoff = SizeofHeapTupleHeader;
	if ((ttc.ttc_flags & TOAST_HAS_NULLS) != 0)
		hoff += BITMAPLEN(natts);
	hoff = MAXALIGN(hoff);
	/* now convert to a limit on the tuple data size */
	maxDataLen = (Size) RelationGetToastTupleTarget(rel, (int) TOAST_TUPLE_TARGET) - hoff;

    /*
        * 1. Inline compress of the biggest, the largest attribute & 
        *  external storage of too big compressed extended attributes  
        */
    while(heap_compute_data_size(tupdesc, values, isnull) > maxDataLen) {
        int biggest_attno; 

        biggest_attno = toast_tuple_find_biggest_attribute(&ttc, true, false); //Find automatically biggest attribute FOR COMPRESSION
        if(biggest_attno < 0) break;
        
        /*
            * If the biggest attributes has type storage extended, we try to compress it.
            * If it's incompressible, we mark it for ignore on subsequent compression passes.
            */
        if(TupleDescAttr(tupdesc, biggest_attno)->attstorage == TYPSTORAGE_EXTENDED) {
            toast_tuple_try_compression(&ttc, biggest_attno);
        }
        else {
            toast_attr[biggest_attno].tai_colflags |= TOASTCOL_INCOMPRESSIBLE;
        }

        if((Size) toast_attr[biggest_attno].tai_size > maxDataLen && 
            rel->rd_rel->reltoastrelid != InvalidOid)
            pg_vault_tde_toast_tuple_externalize(&ttc, biggest_attno, options);
    }

    /*
        * 2. Storage of attribute with attstorage EXTENDED or EXTERNAL
        */

    while(heap_compute_data_size(tupdesc, values, isnull) > maxDataLen && 
            rel->rd_rel->reltoastrelid != InvalidOid) 
    {
        int biggest_attno;

        biggest_attno = toast_tuple_find_biggest_attribute(&ttc, false, false); //Find biggest attribute without caring about compression
        if(biggest_attno < 0)
            break;

        pg_vault_tde_toast_tuple_externalize(&ttc, biggest_attno, options);
    }

    /*
        * 3. Attribute with storage type MAIN: compression (inline storage)
        */

    while(heap_compute_data_size(tupdesc, values, isnull) > maxDataLen)
    {
        int biggest_attno;
        
        biggest_attno = toast_tuple_find_biggest_attribute(&ttc, true, true); //Find biggest attribute FOR COMPRESSION considering MAIN attstorage type
        if(biggest_attno < 0)
            break;
        
        toast_tuple_try_compression(&ttc, biggest_attno);
    }

    /*
        * 4. Store attributes of TYPE main externally 
        * 
        *  "(Actually, out-of-line storage will still be performed for such columns, 
        *   but only as a last resort when there is no other way to make the row small enough to fit on a page.) 
        *  ----- Chapter 66.2"
        */
    while(heap_compute_data_size(tupdesc, values, isnull) > maxDataLen &&
            rel->rd_rel->reltoastrelid != InvalidOid)
    {
        int biggest_attno;

        biggest_attno = toast_tuple_find_biggest_attribute(&ttc, false, true); //Find MAIN attributes
        if(biggest_attno < 0)
            break;

        pg_vault_tde_toast_tuple_externalize(&ttc, biggest_attno, options);
    }

    if((ttc.ttc_flags & TOAST_NEEDS_CHANGE) != 0)
    {
        HeapTupleHeader old_data = newtup->t_data;
        HeapTupleHeader new_data;

        int32  new_header_len;
        int32  new_data_len;
        int32  new_tuple_len;

        new_header_len = SizeofHeapTupleHeader;
        if ((ttc.ttc_flags & TOAST_HAS_NULLS) != 0)
            new_header_len += BITMAPLEN(natts);

        new_header_len = MAXALIGN(new_header_len);
        new_data_len = heap_compute_data_size(tupdesc,
                                            values, isnull);
        new_tuple_len = new_header_len + new_data_len;

        toasted = (HeapTuple) palloc0(HEAPTUPLESIZE + new_tuple_len);
        toasted->t_len = new_tuple_len;
        toasted->t_self = newtup->t_self;
        toasted->t_tableOid = newtup->t_tableOid;
        new_data = (HeapTupleHeader) ((char*) toasted + HEAPTUPLESIZE);
        toasted->t_data = new_data;

        memcpy(new_data, old_data, SizeofHeapTupleHeader);
        HeapTupleHeaderSetNatts(new_data, natts);
        new_data->t_hoff = new_header_len;

        heap_fill_tuple(tupdesc, 
                        values, 
                        isnull, 
                        (char*) new_data + new_header_len, 
                        new_data_len, 
                        &(new_data->t_infomask),
                        ((ttc.ttc_flags & TOAST_HAS_NULLS) != 0) ? new_data->t_bits : NULL);

    }
    else 
        toasted = newtup;

    /*
     * Delete any old external TOAST chunks that were replaced by new values.
     * toast_tuple_init (called above) marks old external attributes as
     * TOASTCOL_NEEDS_DELETE_OLD when the new value differs; toast_tuple_cleanup
     * calls toast_delete_datum for each such attribute.
     *
     * Without this call, the large→large UPDATE path orphans the old TOAST
     * chunks: the fallback in pg_vault_tde_tuple_update only fires when the
     * new tuple has NO external TOAST (!HeapTupleHasExternal), so large→large
     * updates (where both old and new tuples are external) are not covered.
     */
    toast_tuple_cleanup(&ttc);

    return toasted;
}
