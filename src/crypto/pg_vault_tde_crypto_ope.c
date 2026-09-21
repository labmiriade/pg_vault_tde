/*
 * pg_vault_tde_crypto_ope.c - Order Preserving Encryption using AES-256-ECB
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * Order-Preserving Encryption (OPE) allows indexes to support range queries
 * (>, <, BETWEEN) and ordering optimizations directly on encrypted data without
 * exposing the raw plaintexts to the storage layer. Standard index structures
 * like B-Trees require strict mathematical ordering semantics (if A < B, then
 * Enc(A) < Enc(B)), which probabilistic schemes completely destroy.
 *
 * 1. Monotonic Order-Preserving Masking
 * We enforce lexicographical string alignment by mapping variable-length keys
 * onto a fixed-size, base-256 big-endian byte array payload. To obscure values
 * while maintaining strict sorting consistency, a key-dependent deterministic
 * noise block is generated using OpenSSL AES-256-ECB over a block of static zero
 * inputs. By applying 128-bit multi-precision big-endian carry arithmetic from
 * right to left, this noise block shifts the entire numerical scale uniformly,
 * injecting secure entropy without disrupting the natural alphabetical ordering.
 *
 * 2. Process-Local Context Caching & Lifetime Model
 * Allocating cipher contexts (`EVP_CIPHER_CTX_new`) and resetting keys on every
 * row operation causes severe heap fragmentation and severe latency spikes during
 * bulk operations. We optimize this by caching a single context (`encrypt_slot`)
 * inside a global static struct allocated in `TopMemoryContext`.
 *
 * Because AES-256-ECB is completely stateless and does not employ an IV, the
 * key schedule remains resident in memory. On cache hits (matching relation
 * DEKs), the initialization overhead (`EVP_EncryptInit_ex`) is entirely bypassed,
 * routing performance straight through an un-interrupted `EVP_EncryptUpdate` path.
 *
 * 3. Security Trade-offs
 * By design, OPE leaks the relative order of data. Because AES-ECB maps identical
 * plaintexts into identical ciphertexts under the same key without cross-block
 * mixing, this scheme is vulnerable to frequency analysis and data distribution
 * mapping. This module relies strictly on the assumption that SQL Access Control
 * Lists (ACLs) and physical database environment boundaries prevent unauthorized
 * baseline visibility into structural page distribution patterns. Frequency 
 * analysis is a requirement for correct database statistics.
 */

#include "postgres.h"
#include "utils/memutils.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

#include "src/include/pg_vault_tde_crypto_ope.h"

typedef struct OpeCacheSlot
{
	EVP_CIPHER_CTX *ctx;
	unsigned char cached_key[32];
	bool is_valid;
} OpeCacheSlot;

/* Reusable process-local static slots for both OPE operations */
static OpeCacheSlot encrypt_slot = {NULL, {0}, false};

/*
 * tde_crypto_ope_ctx_init
 * Idempotently allocates the OpenSSL contexts in TopMemoryContext.
 * Call this during backend initialization or lazily prior to crypto tasks.
 */
void tde_crypto_ope_ctx_init(void)
{
	if (encrypt_slot.ctx == NULL)
	{
		MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);
		encrypt_slot.ctx = EVP_CIPHER_CTX_new();
		MemoryContextSwitchTo(old);
		if (encrypt_slot.ctx != NULL)
		{
			EVP_CIPHER_CTX_set_padding(encrypt_slot.ctx, 0);
		}
	}
}

/*
 * tde_crypto_ope_ctx_cleanup
 * Safely frees OpenSSL states and cleanses sensitive tracking keys from memory.
 * Can be registered via on_proc_exit() or called directly during error resolution.
 */
void tde_crypto_ope_ctx_cleanup(void)
{
	if (encrypt_slot.ctx != NULL)
	{
		EVP_CIPHER_CTX_free(encrypt_slot.ctx);
		encrypt_slot.ctx = NULL;
	}
	OPENSSL_cleanse(encrypt_slot.cached_key, sizeof(encrypt_slot.cached_key));
	encrypt_slot.is_valid = false;
}


/*
 * tde_crypto_ope_encrypt
 * Maps variable-length plaintext strings straight to an order-preserving byte layout.
 */
char *
tde_crypto_ope_encrypt(const char *dek, int dek_len,
					   const char *plaintext, Size plaintext_len, Size *out_len)
{
	char *serialized_buffer;
	OreSerializedPayload *payload;
	unsigned char prf_master_key[32];
	unsigned char block_input[16];
	unsigned char block_output[16];
	int out_l;
	uint32_t i;

	/* Multi-precision carry tracking variables */
	uint32_t carry;
	int block_idx;

	Assert(plaintext != NULL);
	Assert(out_len != NULL);

	/* 1. Derive master PRF context key stream from the relation DEK */
	if (SHA256((const unsigned char *)dek, dek_len, prf_master_key) == NULL)
	{
		elog(ERROR, "[CRYPTO-OPE] Master key derivation sequence failed");
	}

	/* 2. Package output allocations using palloc (not palloc0) as we overwrite fully */
	*out_len = sizeof(OreSerializedPayload);
	serialized_buffer = (char *)palloc(*out_len);
	payload = (OreSerializedPayload *)serialized_buffer;

	/*
	 * 3. Base-256 Lexicographical Alignment.
	 * Copy characters into fixed layout, padding trailing positions with zero bytes.
	 */
	for (i = 0; i < 16; i++)
	{
		payload->ope_ciphertext[i] = (i < plaintext_len) ? (unsigned char)plaintext[i] : 0;
	}

	/* Ensure context is initialized */
	if (encrypt_slot.ctx == NULL)
	{
		tde_crypto_ope_ctx_init();
		if (encrypt_slot.ctx == NULL)
		{
			pfree(serialized_buffer);
			elog(ERROR, "[CRYPTO-OPE] Encrypt context allocation failure");
		}
	}

	/* 4. Cache Check / Key Switch Transformation Path for the main cipher context */
	if (!encrypt_slot.is_valid || memcmp(encrypt_slot.cached_key, prf_master_key, 32) != 0)
	{
		if (EVP_EncryptInit_ex(encrypt_slot.ctx, EVP_aes_256_ecb(), NULL, prf_master_key, NULL) != 1)
		{
			tde_crypto_ope_ctx_cleanup();
			pfree(serialized_buffer);
			elog(ERROR, "[CRYPTO-OPE] Main cipher initialization failure");
		}
		memcpy(encrypt_slot.cached_key, prf_master_key, 32);
		encrypt_slot.is_valid = true;
	}

	/* 5. Process pure fast-path ECB block mapping step */
	memset(block_input, 0, sizeof(block_input));
	if (EVP_EncryptUpdate(encrypt_slot.ctx, block_output, &out_l, block_input, 16) != 1)
	{
		tde_crypto_ope_ctx_cleanup();
		pfree(serialized_buffer);
		elog(ERROR, "[CRYPTO-OPE] Main cipher monotonic mask tracking aborted");
	}

	/*
	 * 6. Mix the deterministic noise block directly into the scalar text payload.
	 * Apply 128-bit big-endian carry arithmetic from right-to-left.
	 */
	carry = 0;
	for (block_idx = 15; block_idx >= 0; block_idx--)
	{
		uint32_t sum = (uint32_t)payload->ope_ciphertext[block_idx] +
					   (uint32_t)block_output[block_idx] +
					   carry;

		payload->ope_ciphertext[block_idx] = (unsigned char)(sum & 0xFF);
		carry = sum >> 8;
	}

	OPENSSL_cleanse(prf_master_key, sizeof(prf_master_key));

	return serialized_buffer;
}

/*
 * tde_crypto_ope_compare
 * Compares two fixed-size scalar text blocks instantly.
 */
int tde_crypto_ope_compare(const char *ctxt1, const char *ctxt2)
{
	OreSerializedPayload *payload1 = (OreSerializedPayload *)ctxt1;
	OreSerializedPayload *payload2 = (OreSerializedPayload *)ctxt2;

	int comp_result = memcmp(payload1->ope_ciphertext, payload2->ope_ciphertext, 16);

	if (comp_result < 0)
		return -1;
	else if (comp_result > 0)
		return 1;

	return 0;
}