# KMS Module Instructions — @SecurityKMS

> **Scope**: `src/kms/pg_vault_tde_kms.c`, `src/include/pg_vault_tde_kms.h`

---

## Module Responsibility

Manages the Data Encryption Key (DEK) lifecycle:
1. **Shared-memory cache** — single DEK + generation epoch, `LWLock`-protected
2. **Per-backend local cache** — `TopMemoryContext` copy, lazy refresh on generation mismatch
3. **Vault HTTP connector** — `libcurl`-based async request to HashiCorp Vault / OpenBao
4. **Key rotation** — wipe DEK, bump generation, invalidate all backends lazily

---

## Shared Memory Layout

```c
typedef struct TdeKmsSharedState {
    LWLock      lock;             /* embedded by VALUE (not pointer) */
    uint64      generation;       /* monotonically incremented on rotate */
    bool        dek_valid;        /* false until first key injection */
    char        dek[TDE_DEK_LEN]; /* 32-byte AES-256 key */
} TdeKmsSharedState;
```

### Critical: Shared Memory Initialization Sequence

```
shmem_request_hook:
  └── RequestAddinShmemSpace(sizeof(TdeKmsSharedState))
      ⚠ Do NOT call RequestNamedLWLockTranche() here
      ⚠ Do NOT call LWLockNewTrancheId() here

shmem_startup_hook:
  └── ShmemInitStruct("pg_vault_tde_dek_cache", ..., &found)
      └── if (!found):
              LWLockNewTrancheId()       ← requires shmem to be mapped
              LWLockInitialize(&cache->lock, tranche_id)
      └── LWLockRegisterTranche(id, "pg_vault_tde_kms")  ← every process
```

**Why**: `LWLockNewTrancheId()` acquires `WaitEventCustomCounterLock`, a
spinlock in shared memory. If called from `_PG_init` or `shmem_request_hook`,
shared memory doesn't exist yet → segfault.

---

## DEK Access Pattern (Hot Path)

```c
bool pg_vault_tde_kms_get_dek(unsigned char *dek_out, int len)
{
    /* 1. Fast path: local cache hit (no lock) */
    if (local_valid && local_generation == shmem->generation) {
        memcpy(dek_out, local_dek, TDE_DEK_LEN);
        return true;
    }

    /* 2. Slow path: acquire LW_SHARED, copy from shmem */
    LWLockAcquire(&shmem->lock, LW_SHARED);
    if (!shmem->dek_valid) {
        LWLockRelease(&shmem->lock);
        return false;  /* no key set yet */
    }
    memcpy(dek_out, shmem->dek, TDE_DEK_LEN);
    local_generation = shmem->generation;
    LWLockRelease(&shmem->lock);

    /* 3. Update local cache */
    memcpy(local_dek, dek_out, TDE_DEK_LEN);
    local_valid = true;
    return true;
}
```

### Performance Rules
- Local cache avoids shmem lock on generation match → O(1) per tuple
- Maximum one `LW_SHARED` acquisition per generation mismatch
- `LW_EXCLUSIVE` only during `rotate_key()` or `set_dek()`
- NEVER upgrade shared→exclusive inline — release first, re-acquire exclusive

---

## Key Rotation Protocol

```c
void pg_vault_tde_rotate_key(void)
{
    LWLockAcquire(&shmem->lock, LW_EXCLUSIVE);
    OPENSSL_cleanse(shmem->dek, TDE_DEK_LEN);
    shmem->generation++;
    shmem->dek_valid = false;
    LWLockRelease(&shmem->lock);
}
```

- Each backend detects the mismatch lazily on next `get_dek()` call
- No SIGUSR1/SIGHUP needed — generation epoch is self-detecting
- Old-generation rows become permanently unreadable (by design)
- Re-encryption utility is a v1.2 roadmap item

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

/* Global active provider — set by pg_vault_tde.kms_provider GUC at startup */
extern const TdeKmsProvider *tde_active_kms_provider;
```

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
| `src/kms/pg_vault_tde_kms_local.c` | `local` | v1.5 |
| `src/kms/pg_vault_tde_kms_pkcs11.c` | `pkcs11` | v1.7 |
| `src/kms/pg_vault_tde_kms_kmip.c` | `kmip` | v1.8 |

### Local Wallet Provider Rules (`local`)

- Wallet file: `$PGDATA/pg_vault_tde/wallet.p12` (default; GUC `pg_vault_tde.wallet_path`)
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

### Per-Table DEK Cache (v1.5+)

```c
/*
 * TdeRelDekCache replaces the single TdeShmemData.dek[32] field.
 * Each encrypted relation has its own DEK entry in a fixed-size shmem array.
 * Keyed by Oid (relfilenode).
 */
typedef struct TdeRelDekEntry {
    Oid             relid;                  /* 0 = unused slot */
    LWLock          lock;
    uint64          generation;
    bool            dek_valid;
    bool            prev_dek_valid;
    char            dek[TDE_DEK_LEN];       /* current DEK */
    char            prev_dek[TDE_DEK_LEN];  /* fallback for reencrypt_table */
} TdeRelDekEntry;

typedef struct TdeRelDekCache {
    int             capacity;               /* pg_vault_tde.max_encrypted_relations */
    TdeRelDekEntry  entries[FLEXIBLE_ARRAY_MEMBER];
} TdeRelDekCache;
```

Backward compatibility: relations with no `pg_vault_tde_catalog` row use the v1.4
legacy single-DEK (sentinel `relid = 0`).

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
5. User can call pg_vault_tde_set_test_dek() for dev/test, or fix Vault
```

### Runtime (pg_vault_tde_kms_get_dek)

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
