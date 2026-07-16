# KMS Module Instructions — @SecurityKMS

> **Scope**: `src/kms/pg_vault_tde_kms.c`, `src/include/pg_vault_tde_kms.h`

---

## Module Responsibility

Manages the Data Encryption Key (DEK) lifecycle:
1. **Shared-memory cache** — per-relation DEK cache (`TdeRelDekMap`, an `HTAB`
   keyed by relid), guarded by a single `LWLock`. Lives in
   `src/kms/pg_vault_tde_catalog.c`.
2. **Vault token cache** — fixed-size `pg_vault_tde_kms_cache` shmem struct in
   `pg_vault_tde_kms.c` holding the shared Vault auth token (dynamic tranche).
3. **Vault HTTP connector** — `libcurl`-based request to HashiCorp Vault / OpenBao
4. **Key rotation** — wipe DEK, bump generation, invalidate all backends lazily

---

## Shared Memory Layout

### v1.5+ — Per-Relation DEK Cache (current)

See § Per-Table DEK Cache (v1.5+) below for the `TdeRelDekMap` `HTAB` layout.
This is the structure used for all newly created encrypted relations. It lives
in `src/kms/pg_vault_tde_catalog.c`, not this module's `.c` file.

### Critical: Shared Memory Initialization Sequence

Two distinct shmem objects, two distinct (both correct) tranche strategies:

```
# 1. TdeRelDekMap HTAB — DEK cache (named tranche) — in pg_vault_tde_catalog.c
shmem_request_hook (pg_vault_tde_catalog_shmem_request):
  ├── RequestAddinShmemSpace(hash_estimate_size(capacity, sizeof(TdeRelDekMap)))
  └── RequestNamedLWLockTranche("TdeRelDekMap", 1)   ← named-tranche request OK here
shmem_startup_hook (pg_vault_tde_catalog_shmem_init):
  ├── rel_dek_lock = &GetNamedLWLockTranche("TdeRelDekMap")[0].lock
  └── ShmemInitHash("TdeRelDekMap", capacity, capacity, &info, HASH_ELEM | HASH_BLOBS)

# 2. pg_vault_tde_kms_cache — Vault token (dynamic tranche) — in pg_vault_tde_kms.c
shmem_request_hook:
  └── RequestAddinShmemSpace(sizeof(pg_vault_tde_kms_cache))
      ⚠ Do NOT call RequestNamedLWLockTranche() / LWLockNewTrancheId() here
shmem_startup_hook:
  └── ShmemInitStruct("pg_vault_tde_kms_cache", ..., &found)
      └── if (!found): LWLockNewTrancheId() + LWLockInitialize(&cache->lock, id)
                       ← requires shmem to be mapped
```

**Why** `LWLockNewTrancheId()` must wait until `shmem_startup_hook`: it acquires
`WaitEventCustomCounterLock`, a spinlock in shared memory. If called from
`_PG_init` or `shmem_request_hook`, shared memory doesn't exist yet → segfault.
(Named-tranche *requests* via `RequestNamedLWLockTranche` ARE allowed in
`shmem_request_hook` — which is why the DEK map uses that strategy.)

---

## DEK Access Pattern (Hot Path)

`pg_vault_tde_kms_get_rel_dek(relid, dek_out, len)` — per-relation accessor:

```c
/* relid is first mapped to the DEK-owning OID (TOAST→parent, relrewrite→base). */
Oid effective_relid = resolve_effective_relid(relid);

/* 1. Fast path: shmem HTAB hit (LW_SHARED) */
LWLockAcquire(rel_dek_lock, LW_SHARED);
e = (TdeRelDekMap *) hash_search(rel_dek_map, &effective_relid, HASH_FIND, NULL);
if (e && e->dek_valid) {
    memcpy(dek_out, e->dek, TDE_DEK_LEN);
    LWLockRelease(rel_dek_lock);
    return true;
}
LWLockRelease(rel_dek_lock);

/* 2. Slow path: catalog read + KMS unwrap + cache insert (LW_EXCLUSIVE) */
unwrap_from_catalog(effective_relid, dek_out);
/* tde_rel_dek_cache_store: hash_search(HASH_ENTER_NULL) under LW_EXCLUSIVE;
 * NULL return = HTAB full → ERROR (raise pg_vault_tde.max_encrypted_relations). */
return true;
```

### Performance Rules
- `hash_search(HASH_FIND)` under `LW_SHARED` is O(1) average → one shmem lock
  per encrypt/decrypt call. The DEK is copied to a stack buffer every call.
- Cross-call reuse lives in the **crypto layer**, not here: the `TdeCipherSlot`
  EVP contexts cache the AES key schedule keyed by `(relid, generation)`, so the
  expensive `EVP_EncryptInit_ex2`-with-key runs only when relid/generation change.
- `LW_EXCLUSIVE` only on cache miss insert, eviction, or key rotation.
- NEVER upgrade shared→exclusive inline — release first, re-acquire exclusive.

---

## Key Rotation Protocol

Per-relation rotation is handled via `pg_vault_tde_catalog_update_rel_dek(relid)` — see `pg_vault_tde_catalog.h`.

---

## Memory Security Rules

| Operation | Cleanse Required |
|-----------|-----------------|
| `OPENSSL_cleanse(shmem->dek, TDE_DEK_LEN)` | YES — on rotation |
| `OPENSSL_cleanse(local_dek, TDE_DEK_LEN)` | YES — on `on_proc_exit` |
| `OPENSSL_cleanse(dek_out, TDE_DEK_LEN)` | Caller's responsibility |

---

## Vault HTTP Connector (v1.1 — Scaffolded)

```c
/*
 * pg_vault_tde_kms_request_async — HTTP(S) call to Vault Transit API.
 *
 * Uses libcurl multi-handle for non-blocking I/O so the PostgreSQL
 * backend is not blocked during Vault RTT.
 *
 * GUC parameters consumed:
 *   pg_vault_tde.vault_url
 *   pg_vault_tde.vault_token
 *   pg_vault_tde.vault_transit_mount
 *   pg_vault_tde.vault_key_name
 *   pg_vault_tde.vault_ca_cert
 *   pg_vault_tde.vault_timeout_ms
 *   pg_vault_tde.vault_namespace
 */
```

When implementing:
- Use `CURLOPT_CAINFO` for TLS verification (from `vault_ca_cert` GUC)
- Use `CURLOPT_TIMEOUT_MS` (from `vault_timeout_ms` GUC)
- Parse JSON response with a minimal JSON parser (no jsmn.h GPL dep)
- On failure: `ereport(ERROR)` — never leave the DEK cache in an inconsistent state

---

## Constants (Canonical Definitions)

These constants are defined ONLY in `pg_vault_tde_kms.h`:
- `TDE_DEK_LEN = 32`

Do NOT redefine in any `.c` file or other header.

---

## KMS Provider Abstraction Layer (v1.5+)

Starting from v1.5, the KMS layer is split into a **provider vtable** and
per-provider implementations. ALL code that calls `pg_vault_tde_kms_get_rel_dek()`
or `pg_vault_tde_kms_get_dek()` is unaffected — the provider is transparent.

### Provider Interface (`pg_vault_tde_kms_provider.h`)

```c
typedef struct TdeKmsProvider {
    const char *name;           /* 'vault', 'local', 'pkcs11', 'kmip' */

    /* Lifecycle */
    bool (*init)(void);         /* Called from shmem_startup_hook */
    void (*shutdown)(void);     /* Called from on_proc_exit */

    /* DEK key operations */
    bool (*wrap_dek)(Oid relid, const unsigned char *dek, int dek_len,
                     unsigned char *wrapped_out, int *wrapped_len);
    bool (*unwrap_dek)(Oid relid, const unsigned char *wrapped, int wrapped_len,
                       unsigned char *dek_out, int dek_len);
    bool (*generate_dek)(Oid relid, unsigned char *dek_out, int dek_len);
    bool (*rewrap_dek)(Oid relid);   /* Called on KEK rotation */
    bool (*delete_key)(Oid relid);   /* Called on DROP TABLE */

    /* Diagnostics */
    bool (*health_check)(StringInfo report);
} TdeKmsProvider;

/* Active provider for this connection — resolved from pg_vault_tde.kms_provider
 * GUC at connection time (PGC_SUSET: may differ per database). */
extern const TdeKmsProvider *tde_active_kms_provider;
```

### `wrap_dek(out, &out_len)` Contract — MUST READ (v1.6 patch)

`*wrapped_len` is **bidirectional**:

- **Input**: caller MUST initialize `*wrapped_len` to the **capacity in bytes**
  of the `wrapped_out` buffer (i.e. `sizeof(buffer)` for stack arrays).
- **Output**: provider sets `*wrapped_len` to the number of bytes actually
  written.

**Anti-pattern** (silently broke `CREATE TABLE ... USING encrypted_heap`
under the Vault provider in pre-patch v1.6):

```c
unsigned char wrapped[TDE_WRAPPED_DEK_MAX];
int wrapped_len = 0;                           /* WRONG — capacity is 0 */
provider->wrap_dek(relid, dek, 32, wrapped, &wrapped_len);
/* Vault provider's wrap_dek interprets *out_len as input capacity:
 * a 0 capacity makes it refuse to write any bytes and return false. */
```

**Correct**:

```c
unsigned char wrapped[TDE_WRAPPED_DEK_MAX];
int wrapped_len = sizeof(wrapped);             /* OK — capacity in bytes */
if (!provider->wrap_dek(relid, dek, 32, wrapped, &wrapped_len))
    ereport(ERROR, ...);
/* On success, wrapped_len now contains bytes-written. */
```

Two other historical occurrences of the same bug were fixed in
`src/kms/pg_vault_tde_kms_local.c` (lines ~1413 in `change_passphrase` and
~1706 in `rotate_kek` — both used `int new_len = sizeof(new_wrapped);`).

### `change_passphrase` / `rotate_kek` SPI re-wrap contract (v1.6 patch)

Both functions iterate over `pg_vault_tde_catalog` and re-wrap each DEK.
The naive pattern below is **broken**:

```c
spi_ret = SPI_execute("SELECT relid, wrapped_dek FROM ...", true, 0);
for (i = 0; i < SPI_processed; i++) {
    HeapTuple tup = SPI_tuptable->vals[i];   /* invalidated on iter 2+ */
    /* ... derive new_wrapped ... */
    SPI_execute_with_args("UPDATE ...", ...); /* ← OVERWRITES SPI_tuptable */
}
```

`SPI_execute_with_args` resets `SPI_tuptable` and `SPI_processed` to the
UPDATE's empty tuptable, so on the second iteration `SPI_tuptable->vals[i]`
dereferences freed memory and SEGV-s the backend.

The required pattern is **two-phase**: snapshot the SELECT into caller-
owned arrays in `TopTransactionContext` BEFORE issuing any UPDATE, then
iterate the local arrays.

### `change_passphrase` KEK derivation (v1.6 patch)

`local_open_wallet(path, NEW_pass, kek)` runs `PKCS12_verify_mac`, which
fails on a wallet file still authenticated under the OLD passphrase.  The
correct sequence is:

1. `local_open_wallet(path, OLD_pass, old_kek)` — verifies on-disk MAC.
2. `local_derive_kek_from_pass(NEW_pass, new_kek)` — PBKDF2-only with the
   fixed `"pg_vault_tde_kek_v1"` salt; no file I/O, no MAC check.
3. Re-wrap each DEK with `local_wrap_dek_with_kek(...new_kek)`.
4. Rewrite the wallet file under `NEW_pass` via `local_create_wallet_file`.

`local_derive_kek_from_pass()` is the helper that decouples KEK
derivation from MAC verification.  Use it instead of
`local_wrap_dek_with_pass()` whenever the wallet file's MAC does not yet
match the target passphrase.

### `rotate_kek` / `export_bundle` dual-source KEK (v1.6 patch, unified in v1.7)

`pg_vault_tde_rotate_kek()` (v1.7, unified; replaced the local-wallet-only
`pg_vault_tde_wallet_rotate_kek()` from v1.6) prefers
`local_wallet_state->kek` (set by a prior `wallet_unlock`) over
`local_get_passphrase()` when running under the `local` provider.  This means
tests that already called `wallet_unlock` no longer need to configure
`pg_vault_tde.wallet_passphrase_env` to call `rotate_kek`.  Under the `vault`
provider the function calls Vault Transit key rotation and re-wraps all DEKs.

This contract applies symmetrically to `unwrap_dek(wrapped, wrapped_len, dek_out, dek_len)`:
`dek_len` here is **input-only capacity** because the unwrapped output is
always exactly `TDE_DEK_LEN`. Providers MAY assert `dek_len >= TDE_DEK_LEN`.

When implementing a new provider, call sites that allocate with
`palloc(TDE_WRAPPED_DEK_MAX)` MUST still set `*out_len = TDE_WRAPPED_DEK_MAX`
before the call — the same bidirectional contract holds for heap buffers.

### Provider Registration

```c
/* In pg_vault_tde.c _PG_init: */
if (strcmp(guc_kms_provider, "vault") == 0)
    tde_active_kms_provider = &tde_kms_vault_provider;
else if (strcmp(guc_kms_provider, "local") == 0)
    tde_active_kms_provider = &tde_kms_local_provider;
else if (strcmp(guc_kms_provider, "pkcs11") == 0)
    tde_active_kms_provider = &tde_kms_pkcs11_provider;  /* v1.7 */
else if (strcmp(guc_kms_provider, "kmip") == 0)
    tde_active_kms_provider = &tde_kms_kmip_provider;    /* v1.8 */
```

### Provider Files

| File | Provider | Available Since |
|------|----------|-----------------|
| `src/kms/pg_vault_tde_kms_vault.c` | `vault` | v1.0 (refactored in v1.5) |
| `src/kms/pg_vault_tde_kms_local.c` | `local` | v1.5 (v1.6 patch: wrap_dek capacity-init bug fixed in `change_passphrase` + `rotate_kek`; v1.7: `wallet_rotate_kek` renamed to unified `pg_vault_tde_rotate_kek`) |
| `src/kms/pg_vault_tde_catalog.c` | dispatch / catalog access | v1.5 (v1.6 patch: wrap_dek capacity-init bug fixed at line 488 — was blocking `CREATE TABLE` under Vault provider) |
| `src/kms/pg_vault_tde_kms_pkcs11.c` | `pkcs11` | v1.7 |
| `src/kms/pg_vault_tde_kms_kmip.c` | `kmip` | v1.8 |

### Local Wallet Provider Rules (`local`)

- Wallet file: `/var/lib/pg_vault_tde/<DB_OID>/wallet.p12` (default; GUC `pg_vault_tde.wallet_path`)
- Format: PKCS#12 with `NID_aes_256_cbc` encryption (OpenSSL 3.x `PKCS12_create_ex2()`)
- Passphrase: from environment variable ONLY — GUC `pg_vault_tde.wallet_passphrase_env`
  holds the env var NAME, never the value. Never read from `postgresql.conf`.
- On `init()`: open wallet, derive KEK, store in process-local frame ONLY
- On `wrap_dek()`: `EVP_aes_256_wrap()` using KEK; store wrapped bytes in
  `pg_vault_tde_catalog.wrapped_dek`; `OPENSSL_cleanse(kek, 32)` immediately after
- On `unwrap_dek()`: open wallet, derive KEK, `EVP_aes_256_unwrap()`, return plaintext
  DEK to caller's stack frame; `OPENSSL_cleanse(kek, 32)` immediately after
- Wallet file permissions MUST be `0600` — enforced at create time and in `health_check()`
- PKCS#11 (HSM-backed keys) is a separate `pkcs11` provider — `local` is software-only

#### GUC context: all KMS parameters are PGC_SUSET

All `pg_vault_tde` KMS GUCs (including `wallet_path`, `kms_provider`, all
`vault_*` parameters, and all `wallet_*` parameters) use `PGC_SUSET` rather
than `PGC_POSTMASTER`.  This serves two purposes:

1. **Per-database KMS isolation**: a superuser can assign different KMS settings
   to individual databases via `ALTER DATABASE SET pg_vault_tde.kms_provider = ...`
   without restarting the server.  Each new connection resolves the effective GUC
   value for its own database.

2. **Runtime wallet init**: `pg_vault_tde_wallet_init()` can call
   `SetConfigOption(..., PGC_SUSET, PGC_S_SESSION)` to update `wallet_path` for
   the current session immediately after wallet creation.

The only parameters that remain `PGC_POSTMASTER` are `max_encrypted_relations`
(shared-memory sizing) and `crypto_provider` (OpenSSL provider selection at startup).

A `show_hook` (`wallet_path_show_hook`, implemented in `pg_vault_tde_kms_local.c`) is
registered so that `SHOW pg_vault_tde.wallet_path` returns the **computed** default path
(`/var/lib/pg_vault_tde/<DB_OID>/wallet.p12`) even when the GUC is not explicitly
set in `postgresql.conf`.  Without the hook, `SHOW` returns the empty string stored in
the GUC variable.

`local_get_wallet_path()` guards against early calls (before the backend has connected
to a database) by returning `""` when
`!OidIsValid(MyDatabaseId)`.

#### `PKCS12_create` maciter parameter (v1.6 patch)

The 8th argument to `PKCS12_create()` / `PKCS12_create_ex2()` (`maciter`) must be
`PKCS12_DEFAULT_ITER` (2048), **not** `-1`.  In OpenSSL 3.x, `-1` disables the
PKCS#12 MAC entirely, producing a wallet that `PKCS12_verify_mac` cannot authenticate
— this causes `local_open_wallet` to fail with "wallet MAC verification failed" on
the very first `wrap_dek` call after `wallet_init`.  Always use `PKCS12_DEFAULT_ITER`.

### Per-Table DEK Cache (v1.5+)

```c
/*
 * Each encrypted relation has its own DEK entry, stored as the value type of
 * the TdeRelDekMap HTAB (ShmemInitHash, HASH_BLOBS) keyed by relid.
 * There is NO per-entry lock — a single file-scope `rel_dek_lock` (named
 * tranche "TdeRelDekMap") guards the whole table.
 */
typedef struct TdeRelDekMap {
    Oid          relid;                  /* hash key */
    char         dek[TDE_DEK_LEN];       /* current AES-256 DEK, 32 bytes */
    char         prev_dek[TDE_DEK_LEN];  /* previous DEK (valid during rotation) */
    uint64       generation;             /* rotation epoch for this relation */
    bool         dek_valid;              /* true iff dek[] holds a live key */
    bool         prev_dek_valid;         /* true iff prev_dek[] is populated */
} TdeRelDekMap;
```

Defined in `src/include/pg_vault_tde_catalog.h`. The v1.4 global DEK
(`TdeShmemData`, `relid = 0` sentinel) was removed in v1.7. All relations must
have a `pg_vault_tde_catalog` entry.

---

## Dependency Constraints

- This module MUST NOT include `pg_vault_tde_tam.h`, `pg_vault_tde_iam.h`, or `pg_vault_tde_crypto.h`
- This module MUST NOT call any TAM, IAM, or crypto functions
- This module is the bottom of the dependency chain
- Only PostgreSQL shmem/LWLock APIs, libcurl (vault provider), and OpenSSL PKCS12 API (local provider) are permitted external dependencies
- `tde_active_kms_provider` is the ONLY global dispatch point — no `if (provider == vault)` outside `pg_vault_tde.c`

---

## Vault Unreachable Fallback Protocol

When Vault is unreachable (network error, timeout, HTTP 5xx):

### Startup (shmem_startup_hook)

```
1. Try Vault HTTP call with vault_timeout_ms
2. If fail → retry once with 2× timeout
3. If still fail → log WARNING and set shmem state to DEK_NOT_SET
4. PostgreSQL starts normally — encrypted_heap tables will ereport(ERROR)
   on first access ("no DEK available")
```

### Runtime (pg_vault_tde_kms_get_rel_dek)

```
1. Check shmem cache (LW_SHARED) — if DEK set, return it (fast path)
2. If DEK_NOT_SET → attempt Vault HTTP call (LW_EXCLUSIVE)
3. If Vault unreachable → ereport(ERROR, "Vault unreachable ...")
4. NEVER cache a stale DEK — generation must match Vault's response
```

### Anti-Pattern

```c
/* BAD — silently returns stale DEK when Vault is down */
if (!vault_reachable)
    return cached_dek;  /* ← stale! generation mismatch! */

/* GOOD — fail explicitly */
if (!vault_reachable)
    ereport(ERROR,
            errcode(ERRCODE_CONNECTION_FAILURE),
            errmsg("pg_vault_tde: cannot reach Vault at %s", vault_url),
            errhint("Check pg_vault_tde.vault_url and network connectivity"));
```
