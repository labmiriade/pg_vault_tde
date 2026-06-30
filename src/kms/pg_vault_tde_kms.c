/*
 * pg_vault_tde_kms.c - KMS/Vault integration (async, shared memory cache)
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 */
#include "postgres.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "storage/latch.h"               /* WaitLatch, MyLatch */
#include "postmaster/bgworker.h"          /* BackgroundWorkerUnblockSignals */
#include "tcop/tcopprot.h"               /* die() signal handler */
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "common/pg_prng.h"
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_guc.h"  /* Vault GUC variables */
#include "src/include/pg_vault_tde_audit.h"
#include "common/base64.h"                  /* pg_b64_decode */
#include "utils/timestamp.h"                /* GetCurrentTimestamp */

/*
 * AES-256 DEK is exactly 32 bytes (TDE_DEK_LEN, defined in pg_vault_tde_kms.h).
 *
 * KEY ROTATION DESIGN:
 * -------------------
 * We track a uint64 'generation' counter alongside the DEK.  Every key
 * rotation atomically increments the generation AND replaces the DEK under
 * an exclusive LWLock.  Each backend caches the generation of the DEK it
 * loaded locally; on every encrypt/decrypt it checks the shared generation
 * under a shared lock.  If the numbers differ, it drops its local copy and
 * reloads.  This gives us:
 *   - Zero blocking for concurrent readers: a rotation never waits for
 *     in-flight read operations to finish; they complete with the old DEK.
 *   - Bounded staleness: the stale window is at most one LWLock pair per
 *     encrypt/decrypt call (microseconds on modern hardware).
 *   - No signal/interrupt required: generation mismatch is detected
 *     lazily on the hot path, not via ProcSendSignal.
 *
 * LOCKING: The LWLock is embedded by value — NOT as a pointer.  A pointer
 * stored in shared memory would be a virtual-address from the process that
 * initialised the segment and would be meaningless (and dangerous) in every
 * other backend.  The embedded struct lets GetNamedLWLockTranche hand us a
 * pointer into the segment that is valid across all processes.
 *
 * TDE_DEK_LEN is NOT redefined here; it comes from pg_vault_tde_kms.h to
 * avoid macro-redefinition warnings and keep a single source of truth.
 */

typedef struct
{
    LWLock       lock;               /* embedded — valid across all backends */
   

    /*
     * Background worker shared token state (v1.3):
     *
     * When pg_vault_tde.bgw_enabled = true, a background worker periodically
     * renews the Vault token and stores it here.  All backends read this
     * shared token instead of performing per-backend logins, eliminating
     * the N-backends × N-logins overhead for AppRole/K8s auth.
     */
    char         shared_token[512];
    bool         shared_token_valid;
    TimestampTz  token_renewed_at;
    int          token_ttl_seconds;     /* reported TTL from Vault */
} pg_vault_tde_kms_cache;

static pg_vault_tde_kms_cache *kms_cache = NULL;

/*
 * pg_vault_tde_kms_shmem_request
 *
 * Must be called from the shmem_request_hook chain (PG 15+).  Reserves
 * space for the DEK cache in shared memory.
 */
void
pg_vault_tde_kms_shmem_request(void)
{
    RequestAddinShmemSpace(sizeof(pg_vault_tde_kms_cache));
}

/*
 * pg_vault_tde_kms_shmem_init
 *
 * Called from the shmem_startup_hook chain after shared memory has been
 * allocated.  Maps the Vault token cache struct (pg_vault_tde_kms_cache) and
 * wires up its embedded LWLock via the dynamic-tranche pattern.
 * (The per-relation DEK cache is a separate HTAB owned by
 * pg_vault_tde_catalog.c — see pg_vault_tde_catalog_shmem_init.)
 */
void
pg_vault_tde_kms_shmem_init(void)
{
    bool found;
    int  tranche_id;

    /*
     * ShmemInitStruct maps (or creates) the shared struct and sets |found|.
     * Must be called first so we know whether initialisation is needed.
     */
    kms_cache = ShmemInitStruct("pg_vault_tde_kms_cache",
                                sizeof(pg_vault_tde_kms_cache),
                                &found);

    if (!found)
    {
        /*
         * First process in (always the postmaster): allocate a unique tranche
         * ID and fully initialise the struct.
         *
         * LWLockNewTrancheId() acquires WaitEventCustomCounterLock, a spinlock
         * in shared memory.  It MUST be called after shmem is set up — i.e.
         * from shmem_startup_hook — never from _PG_init.
         */
        tranche_id = LWLockNewTrancheId();
        LWLockInitialize(&kms_cache->lock, tranche_id);
        kms_cache->shared_token_valid = false;
        memset(kms_cache->shared_token, 0, sizeof(kms_cache->shared_token));
        kms_cache->token_renewed_at = 0;
        kms_cache->token_ttl_seconds = 0;
    }
    else
    {
        /* Backend attaching to an already-initialised segment: recover ID. */
        tranche_id = kms_cache->lock.tranche;
    }

    /*
     * LWLockRegisterTranche writes only to a process-local name table.
     * Call it in every process so the tranche name appears in pg_locks
     * and wait-event LWLOCK displays for that process.
     */
    LWLockRegisterTranche(tranche_id, "pg_vault_tde_kms");
}

/*
 * vault_response_buf — growable buffer for libcurl write callback.
 *
 * Allocated in CurrentMemoryContext so it is freed on error via
 * the PG memory context mechanism.
 */
typedef struct
{
    char   *data;
    size_t  len;
    size_t  alloc;
    bool    overflow;   /* set by vault_write_cb when response exceeds cap */
} vault_response_buf;

/* Hard cap on Vault HTTP response size. 64 KB is ample for any Transit API key op. */
#define VAULT_RESPONSE_MAX  (64 * 1024)

/* --- forward declarations --- */
static size_t           vault_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);
static char            *vault_json_extract_string(const char *json, const char *key);
static int              vault_base64_decode(const char *b64_input, unsigned char *output, int output_maxlen);
static char            *vault_perform_login(void);
static const char      *vault_get_effective_token(void);
static bool             vault_refresh_token_internal(void);
static bool             vault_provider_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                                                   unsigned char *new_wrapped, int *new_len);
static bool             vault_probe_health(void);
static bool             detect_aes_ni(void);
static bool             vault_resp_init(vault_response_buf *buf);
static void             vault_resp_free(vault_response_buf *buf);
static CURL            *vault_make_curl(vault_response_buf *resp);
static struct curl_slist *vault_add_namespace_header(struct curl_slist *headers);
static bool             vault_transit_request(const char *path, const char *body,
                                               vault_response_buf *response);
static bool             vault_provider_init(void);
static bool             vault_provider_wrap_dek(const unsigned char *dek, int dek_len,
                                                 unsigned char *wrapped_out, int *out_len);
static bool             vault_provider_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                                                   unsigned char *dek_out, int *dek_len);
static bool             vault_provider_health_check(void);
static void             vault_provider_shutdown(void);
static bool             vault_prepare_kek_rotation(void);
static void             vault_commit_kek_rotation(void);

PG_FUNCTION_INFO_V1(pg_vault_tde_vault_status);

/*
 * vault_write_cb — libcurl CURLOPT_WRITEFUNCTION callback.
 *
 * Appends received data to a vault_response_buf.  Uses repalloc for
 * growth (never malloc).
 *
 * Never calls ereport() — doing so would longjmp through libcurl's stack
 * frames, bypassing its internal cleanup.  Instead, sets buf->overflow and
 * returns 0 (CURLE_WRITE_ERROR) so libcurl aborts cleanly; the caller checks
 * the flag after curl_easy_cleanup() and raises the error there.
 */
static size_t
vault_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    vault_response_buf *buf = (vault_response_buf *) userdata;
    size_t bytes;

    /* Guard against size_t overflow in size * nmemb */
    if (size != 0 && nmemb > SIZE_MAX / size)
    {
        buf->overflow = true;
        return 0;
    }
    bytes = size * nmemb;

    /* Enforce hard response cap before touching memory */
    if (buf->len + bytes + 1 > VAULT_RESPONSE_MAX)
    {
        buf->overflow = true;
        return 0;   /* signals CURLE_WRITE_ERROR to libcurl */
    }

    if (buf->len + bytes + 1 > buf->alloc)
    {
        size_t new_alloc = buf->len + bytes + 1;
        if (new_alloc <= SIZE_MAX / 2)
            new_alloc *= 2;
        buf->alloc = new_alloc;
        buf->data = repalloc(buf->data, buf->alloc);
    }
    memcpy(buf->data + buf->len, ptr, bytes);
    buf->len += bytes;
    buf->data[buf->len] = '\0';
    return bytes;
}

/*
 * vault_json_extract_string — extract a JSON string value by key.
 *
 * Minimal JSON parser: finds "key": "value" and returns a palloc'd copy
 * of value.  Does NOT handle nested objects beyond one level of "data".
 * Adequate for Vault Transit API responses which have a flat structure
 * inside the "data" object.
 *
 * Returns NULL if key not found.  Caller must pfree the result.
 */
static char *
vault_json_extract_string(const char *json, const char *key)
{
    char    search_pattern[256];
    const char *pos;
    const char *start;
    const char *end;
    size_t  val_len;
    char   *result;

    snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", key);
    pos = strstr(json, search_pattern);
    if (pos == NULL)
        return NULL;

    /* Skip past "key" */
    pos += strlen(search_pattern);

    /* Skip whitespace and colon */
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ':')
        pos++;

    if (*pos != '"')
        return NULL;

    start = pos + 1;  /* skip opening quote */
    end = start;
    while (*end != '\0' && *end != '"')
    {
        if (*end == '\\')
            end++;  /* skip escaped char */
        if (*end != '\0')
            end++;
    }

    val_len = end - start;
    result = palloc(val_len + 1);
    memcpy(result, start, val_len);
    result[val_len] = '\0';
    return result;
}

/*
 * vault_base64_decode — decode a base64 string to raw bytes.
 *
 * Uses PostgreSQL's built-in pg_b64_decode (from common/base64.h).
 * Returns the number of decoded bytes.  Caller must OPENSSL_cleanse +
 * pfree when the output contains key material.
 */
static int
vault_base64_decode(const char *b64_input, unsigned char *output, int output_maxlen)
{
    int decoded_len;

    /*
     * pg_b64_decode dst type changed: char * in PG17, uint8 * in PG18.
     */
#if PG_VERSION_NUM >= 180000
    decoded_len = pg_b64_decode(b64_input, strlen(b64_input),
                                (uint8 *) output, output_maxlen);
#else
    decoded_len = pg_b64_decode(b64_input, strlen(b64_input),
                                (char *) output, output_maxlen);
#endif
    if (decoded_len < 0)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("pg_vault_tde: failed to base64-decode Vault response")));

    return decoded_len;
}

/*
 * vault_active_token — per-backend cached token from AppRole/K8s login.
 *
 * When vault_auth_method is "token", this is NULL and we use the static
 * GUC pg_vault_tde_vault_token directly.  When using AppRole or K8s auth,
 * this holds the dynamic client token obtained from the login endpoint.
 */
static char *vault_active_token = NULL;

/*
 * vault_perform_login — authenticate to Vault and obtain a client token.
 *
 * For "approle": POST /v1/auth/approle/login with {role_id, secret_id}.
 * For "kubernetes": POST /v1/auth/<mount>/login with {role, jwt}.
 *
 * The JWT token for Kubernetes is read from the standard service account
 * token file: /var/run/secrets/kubernetes.io/serviceaccount/token.
 *
 * Returns a palloc'd token string (in TopMemoryContext), or NULL on failure.
 */
static char *
vault_perform_login(void)
{
    CURL               *curl;
    CURLcode            res;
    struct curl_slist   *headers = NULL;
    vault_response_buf   response;
    char                url[1024];
    char                post_body[2048];
    char               *token = NULL;
    long                http_code = 0;

    if (pg_vault_tde_vault_url == NULL || pg_vault_tde_vault_url[0] == '\0')
        return NULL;

    /* Build login URL and post body based on auth method */
    if (strcmp(pg_vault_tde_vault_auth_method, "approle") == 0)
    {
        if (pg_vault_tde_vault_role_id == NULL ||
            pg_vault_tde_vault_role_id[0] == '\0')
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: AppRole auth requires vault_role_id")));
            return NULL;
        }

        snprintf(url, sizeof(url), "%s/v1/auth/approle/login",
                 pg_vault_tde_vault_url);
        snprintf(post_body, sizeof(post_body),
                 "{\"role_id\": \"%s\", \"secret_id\": \"%s\"}",
                 pg_vault_tde_vault_role_id,
                 (pg_vault_tde_vault_secret_id && pg_vault_tde_vault_secret_id[0] != '\0')
                     ? pg_vault_tde_vault_secret_id : "");
    }
    else if (strcmp(pg_vault_tde_vault_auth_method, "kubernetes") == 0)
    {
        FILE  *fp;
        char   jwt[8192];
        size_t jwt_len;
        const char *token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";

        if (pg_vault_tde_vault_k8s_role == NULL ||
            pg_vault_tde_vault_k8s_role[0] == '\0')
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: Kubernetes auth requires vault_k8s_role")));
            return NULL;
        }

        fp = fopen(token_path, "r");
        if (fp == NULL)
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: cannot read K8s service account token at %s",
                            token_path)));
            return NULL;
        }
        jwt_len = fread(jwt, 1, sizeof(jwt) - 1, fp);
        fclose(fp);
        jwt[jwt_len] = '\0';

        /* Trim trailing newline if present */
        while (jwt_len > 0 && (jwt[jwt_len-1] == '\n' || jwt[jwt_len-1] == '\r'))
            jwt[--jwt_len] = '\0';

        snprintf(url, sizeof(url), "%s/v1/auth/%s/login",
                 pg_vault_tde_vault_url,
                 pg_vault_tde_vault_k8s_mount);
        snprintf(post_body, sizeof(post_body),
                 "{\"role\": \"%s\", \"jwt\": \"%s\"}",
                 pg_vault_tde_vault_k8s_role, jwt);

        OPENSSL_cleanse(jwt, sizeof(jwt));
    }
    else
    {
        /* "token" auth: no login needed */
        return NULL;
    }

    response.alloc    = 2048;
    response.len      = 0;
    response.overflow = false;
    response.data     = palloc(response.alloc);
    response.data[0] = '\0';

    curl = curl_easy_init();
    if (curl == NULL)
    {
        pfree(response.data);
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);

    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Vault namespace header (enterprise only) */
    if (pg_vault_tde_vault_namespace != NULL &&
        pg_vault_tde_vault_namespace[0] != '\0')
    {
        char ns_header[512];
        snprintf(ns_header, sizeof(ns_header),
                 "X-Vault-Namespace: %s", pg_vault_tde_vault_namespace);
        headers = curl_slist_append(headers, ns_header);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (pg_vault_tde_vault_ca_cert != NULL &&
        pg_vault_tde_vault_ca_cert[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_CAINFO, pg_vault_tde_vault_ca_cert);

    if (pg_vault_tde_vault_timeout_ms > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,
                         (long) pg_vault_tde_vault_timeout_ms);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vault_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (http_code == 200)
        {
            /*
             * Vault login response: {"auth": {"client_token": "s.xxxxx", ...}}
             * Extract client_token from the "auth" sub-object.
             */
            token = vault_json_extract_string(response.data, "client_token");
            if (token != NULL)
            {
                tde_audit(KMS_AUTH_SUCCESS, NULL, true);
                ereport(LOG,
                        (errmsg("pg_vault_tde: Vault %s login successful",
                                pg_vault_tde_vault_auth_method)));
            }
            else
            {
                tde_audit(KMS_AUTH_FAILURE, NULL, false);
                ereport(WARNING,
                        (errmsg("pg_vault_tde: Vault login response missing client_token"),
                         errdetail("Response: %.256s", response.data)));
            }
        }
        else
        {
            tde_audit(KMS_AUTH_FAILURE, NULL, false);
            ereport(WARNING,
                    (errmsg("pg_vault_tde: Vault login returned HTTP %ld", http_code),
                     errdetail("Response: %.256s", response.data)));
        }
    }
    else
    {
        tde_audit(KMS_AUTH_FAILURE, NULL, false);
        if (response.overflow)
            ereport(WARNING,
                    (errmsg("pg_vault_tde: Vault login response too large (limit %d bytes)",
                            VAULT_RESPONSE_MAX)));
        else
            ereport(WARNING,
                    (errmsg("pg_vault_tde: Vault login HTTP request failed: %s",
                            curl_easy_strerror(res))));
    }

    /*
     * AppRole secret_id rotation (v1.4):
     *
     * After a successful AppRole login, destroy the used secret_id so it
     * cannot be replayed.  This implements the "response_wrapping" single-use
     * pattern: each execution cycle fetches a fresh secret_id from Vault,
     * performs login, then immediately invalidates the used credential.
     *
     * Requires pg_vault_tde.vault_role_name to be set (the human-readable
     * role name, distinct from the UUID role_id credential).
     *
     * Endpoint: POST /v1/auth/approle/role/<role_name>/secret-id/destroy
     * Body:     {"secret_id": "<used_secret_id>"}
     *
     * Failure to destroy is non-fatal: log a WARNING, continue with the
     * obtained token.  The secret_id has a short TTL and will expire anyway.
     */
    if (token != NULL &&
        strcmp(pg_vault_tde_vault_auth_method, "approle") == 0 &&
        pg_vault_tde_vault_role_name != NULL &&
        pg_vault_tde_vault_role_name[0] != '\0' &&
        pg_vault_tde_vault_secret_id != NULL &&
        pg_vault_tde_vault_secret_id[0] != '\0')
    {
        CURL               *destroy_curl;
        CURLcode            destroy_res;
        struct curl_slist   *destroy_headers = NULL;
        vault_response_buf   destroy_resp;
        char                destroy_url[1024];
        char                destroy_body[2048];
        char                destroy_auth[512];
        long                destroy_code = 0;

        snprintf(destroy_url, sizeof(destroy_url),
                 "%s/v1/auth/approle/role/%s/secret-id/destroy",
                 pg_vault_tde_vault_url, pg_vault_tde_vault_role_name);
        snprintf(destroy_body, sizeof(destroy_body),
                 "{\"secret_id\": \"%s\"}",
                 pg_vault_tde_vault_secret_id);

        destroy_resp.alloc    = 512;
        destroy_resp.len      = 0;
        destroy_resp.overflow = false;
        destroy_resp.data     = palloc(destroy_resp.alloc);
        destroy_resp.data[0]  = '\0';

        destroy_curl = curl_easy_init();
        if (destroy_curl != NULL)
        {
            snprintf(destroy_auth, sizeof(destroy_auth),
                     "X-Vault-Token: %s", token);
            destroy_headers = curl_slist_append(destroy_headers, destroy_auth);
            destroy_headers = curl_slist_append(destroy_headers,
                                                "Content-Type: application/json");

            if (pg_vault_tde_vault_namespace != NULL &&
                pg_vault_tde_vault_namespace[0] != '\0')
            {
                char ns_hdr[512];
                snprintf(ns_hdr, sizeof(ns_hdr),
                         "X-Vault-Namespace: %s",
                         pg_vault_tde_vault_namespace);
                destroy_headers = curl_slist_append(destroy_headers, ns_hdr);
            }

            curl_easy_setopt(destroy_curl, CURLOPT_URL, destroy_url);
            curl_easy_setopt(destroy_curl, CURLOPT_POST, 1L);
            curl_easy_setopt(destroy_curl, CURLOPT_POSTFIELDS, destroy_body);
            curl_easy_setopt(destroy_curl, CURLOPT_HTTPHEADER, destroy_headers);
            curl_easy_setopt(destroy_curl, CURLOPT_TIMEOUT_MS,
                             (long) (pg_vault_tde_vault_timeout_ms > 0
                                      ? pg_vault_tde_vault_timeout_ms : 5000));
            curl_easy_setopt(destroy_curl, CURLOPT_WRITEFUNCTION, vault_write_cb);
            curl_easy_setopt(destroy_curl, CURLOPT_WRITEDATA, &destroy_resp);

            if (pg_vault_tde_vault_ca_cert != NULL &&
                pg_vault_tde_vault_ca_cert[0] != '\0')
                curl_easy_setopt(destroy_curl, CURLOPT_CAINFO,
                                 pg_vault_tde_vault_ca_cert);

            destroy_res = curl_easy_perform(destroy_curl);
            if (destroy_res == CURLE_OK)
            {
                curl_easy_getinfo(destroy_curl, CURLINFO_RESPONSE_CODE,
                                  &destroy_code);
                /* 204 No Content = success for destroy endpoint */
                if (destroy_code == 204 || destroy_code == 200)
                    ereport(LOG,
                            (errmsg("pg_vault_tde: AppRole secret_id "
                                    "destroyed after login (role=%s)",
                                    pg_vault_tde_vault_role_name)));
                else
                    ereport(WARNING,
                            (errmsg("pg_vault_tde: AppRole secret_id "
                                    "destroy returned HTTP %ld — "
                                    "secret_id may not be invalidated",
                                    destroy_code)));
            }
            else
                ereport(WARNING,
                        (errmsg("pg_vault_tde: AppRole secret_id destroy "
                                "request failed: %s",
                                curl_easy_strerror(destroy_res))));

            OPENSSL_cleanse(destroy_auth, sizeof(destroy_auth));
            OPENSSL_cleanse(destroy_body, sizeof(destroy_body));
            OPENSSL_cleanse(destroy_resp.data, destroy_resp.len);
            pfree(destroy_resp.data);
            curl_slist_free_all(destroy_headers);
            curl_easy_cleanup(destroy_curl);
        }
    }

    /* Cleanup — post_body may contain secret_id or JWT */
    OPENSSL_cleanse(post_body, sizeof(post_body));
    OPENSSL_cleanse(response.data, response.len);
    pfree(response.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return token;
}

/*
 * vault_get_effective_token — return the token to use for Vault API calls.
 *
 * For static "token" auth: returns the GUC value directly.
 * For AppRole/K8s: performs login if no cached token, and returns the
 * cached dynamic token.  Token is stored in TopMemoryContext so it
 * survives transaction boundaries.
 */
static const char *
vault_get_effective_token(void)
{
    if (pg_vault_tde_vault_auth_method == NULL ||
        strcmp(pg_vault_tde_vault_auth_method, "token") == 0)
    {
        return pg_vault_tde_vault_token;
    }

    /*
     * BGW shared token (v1.3): if the background worker has stored a valid
     * token in shmem, use it instead of doing a per-backend login.
     * This eliminates N × login overhead when many backends need Vault access.
     */
    if (vault_active_token == NULL && kms_cache != NULL)
    {
        LWLockAcquire(&kms_cache->lock, LW_SHARED);
        if (kms_cache->shared_token_valid && kms_cache->shared_token[0] != '\0')
        {
            MemoryContext old_ctx = MemoryContextSwitchTo(TopMemoryContext);
            vault_active_token = pstrdup(kms_cache->shared_token);
            MemoryContextSwitchTo(old_ctx);
        }
        LWLockRelease(&kms_cache->lock);
    }

    /* AppRole or Kubernetes: login if needed */
    if (vault_active_token == NULL)
    {
        char *new_token = vault_perform_login();
        if (new_token != NULL)
        {
            MemoryContext old_ctx = MemoryContextSwitchTo(TopMemoryContext);
            vault_active_token = pstrdup(new_token);
            MemoryContextSwitchTo(old_ctx);
            pfree(new_token);
        }
    }

    return vault_active_token;
}

/*
 * pg_vault_tde_refresh_token — SQL-callable wrapper for token renewal.
 *
 * Calls POST /v1/auth/token/renew-self with the current Vault token.
 * Returns true if renewal succeeded, false if re-login is needed.
 * On failure, clears vault_active_token so the next call re-authenticates.
 * Exposed as pg_vault_tde_refresh_token() for operators to manually
 * trigger token renewal (e.g., from a cron job or pg_cron).
 */
PG_FUNCTION_INFO_V1(pg_vault_tde_refresh_token);

static bool
vault_refresh_token_internal(void)
{
    CURL               *curl;
    CURLcode            res;
    struct curl_slist   *headers = NULL;
    vault_response_buf   response;
    char                url[1024];
    char                auth_header[512];
    const char         *token;
    long                http_code = 0;
    bool                success = false;

    token = vault_get_effective_token();
    if (token == NULL || token[0] == '\0')
        return false;

    snprintf(url, sizeof(url), "%s/v1/auth/token/renew-self",
             pg_vault_tde_vault_url);

    response.alloc    = 1024;
    response.len      = 0;
    response.overflow = false;
    response.data = palloc(response.alloc);
    response.data[0] = '\0';

    curl = curl_easy_init();
    if (curl == NULL)
    {
        pfree(response.data);
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");

    snprintf(auth_header, sizeof(auth_header),
             "X-Vault-Token: %s", token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (pg_vault_tde_vault_ca_cert != NULL &&
        pg_vault_tde_vault_ca_cert[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_CAINFO, pg_vault_tde_vault_ca_cert);

    if (pg_vault_tde_vault_timeout_ms > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,
                         (long) pg_vault_tde_vault_timeout_ms);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vault_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    res = curl_easy_perform(curl);

    if (response.overflow)
        ereport(WARNING,
                (errmsg("pg_vault_tde: Vault token renewal response too large (limit %d bytes)",
                        VAULT_RESPONSE_MAX)));
    else if (res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200)
        {
            int   ttl = 0;

            success = true;

            /*
             * Token entropy logging (v1.4): extract the lease_duration
             * from the renewal response and warn operators if the TTL is
             * critically short relative to the renewal interval.
             *
             * Vault response: {"auth": {...}, "lease_duration": <int>, ...}
             * We search for the numeric field directly (vault_json_extract_string
             * only handles quoted string values).
             */
            {
                const char *p = strstr(response.data, "\"lease_duration\"");
                if (p == NULL)
                    p = strstr(response.data, "\"ttl\"");
                if (p != NULL)
                {
                    /* Skip past the key and colon */
                    while (*p && *p != ':')
                        p++;
                    if (*p == ':')
                    {
                        p++;
                        while (*p == ' ')
                            p++;
                        ttl = (int) strtol(p, NULL, 10);
                    }
                }
            }

            if (ttl > 0)
            {
                /* Store TTL in shmem for health_check() reporting */
                if (kms_cache != NULL)
                {
                    LWLockAcquire(&kms_cache->lock, LW_EXCLUSIVE);
                    kms_cache->token_ttl_seconds = ttl;
                    LWLockRelease(&kms_cache->lock);
                }

                ereport(LOG,
                        (errmsg("pg_vault_tde: token renewed successfully, "
                                "TTL=%d seconds", ttl)));

                /* Warn if TTL is dangerously close to renewal interval */
                if (ttl < pg_vault_tde_token_renewal_interval * 2)
                    ereport(WARNING,
                            (errmsg("pg_vault_tde: token TTL (%d s) < 2 × "
                                    "renewal interval (%d s) — token may "
                                    "expire before next renewal; increase "
                                    "vault token TTL or decrease "
                                    "pg_vault_tde.token_renewal_interval",
                                    ttl,
                                    pg_vault_tde_token_renewal_interval)));
            }
            else
                ereport(DEBUG1,
                        (errmsg("pg_vault_tde: token renewal successful "
                                "(TTL not reported by server)")));
        }
        else
        {
            ereport(WARNING,
                    (errmsg("pg_vault_tde: token renewal failed (HTTP %ld)",
                            http_code)));
            /* Force re-login on next call */
            if (vault_active_token)
            {
                OPENSSL_cleanse(vault_active_token, strlen(vault_active_token));
                pfree(vault_active_token);
                vault_active_token = NULL;
            }
        }
    }

    OPENSSL_cleanse(auth_header, sizeof(auth_header));
    OPENSSL_cleanse(response.data, response.len);
    pfree(response.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return success;
}

Datum
pg_vault_tde_refresh_token(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL(vault_refresh_token_internal());
}

/* ================================================================
 * Vault Transit KEK Wrapping (v1.3)
 *
 * The DEKs are wrapped (encrypted) by Vault's Transit master key (KEK).
 *
 * ================================================================ */

#include "miscadmin.h"              /* DataDir */
#include <sys/stat.h>               /* mkdir */


static bool
vault_provider_rewrap_dek(const unsigned char *old_wrapped, int old_len,
                           unsigned char *new_wrapped, int *new_len)
{
    vault_response_buf  resp;
    char               *post_body = NULL;
    char               *wrapped   = NULL;
    char                path[512];
    bool                success   = false;

    post_body = palloc(old_len + 64);
    snprintf(post_body, old_len + 64, "{\"ciphertext\": \"%.*s\"}",
             (int) old_len, (const char *) old_wrapped);

    snprintf(path, sizeof(path), "/v1/%s/rewrap/%s",
             pg_vault_tde_vault_transit_mount,
             pg_vault_tde_vault_key_name);

    if (vault_transit_request(path, post_body, &resp))
    {
        wrapped = vault_json_extract_string(resp.data, "ciphertext");
        if (wrapped != NULL)
        {
            size_t wrapped_len = strlen(wrapped);

            if ((int) wrapped_len > *new_len)
            {
                OPENSSL_cleanse(wrapped, wrapped_len);
                pfree(wrapped);
                ereport(ERROR,
                        errmsg("pg_vault_tde: rewrapped DEK (%zu) exceeds buffer (%d)",
                                wrapped_len, *new_len));
            }

            memcpy(new_wrapped, wrapped, wrapped_len);
            *new_len = (int) wrapped_len;

            OPENSSL_cleanse(wrapped, wrapped_len);
            pfree(wrapped);
            wrapped = NULL;
            success = true;
        }
    }
    else
        ereport(ERROR,
                errmsg("pg_vault_tde: kms vault: can't rewrap DEK"));

    vault_resp_free(&resp);
    OPENSSL_cleanse(post_body, strlen(post_body));
    pfree(post_body);

    return success;
}
/* ================================================================
 * pg_vault_tde_health_check — unified diagnostic composite (v1.3)
 *
 * Returns a 14-column composite aggregating all subsystem states:
 * DEK, Vault, authentication, OpenSSL, hardware acceleration, and
 * overall health status derived from the component statuses.
 *
 * overall_status rules:
 *   "healthy"  — DEK valid, if Vault configured then reachable + token OK
 *   "degraded" — DEK valid, but Vault unreachable or token stale
 *   "error"    — no DEK available (encrypted tables will fail)
 * ================================================================ */

#include "funcapi.h"                /* get_call_result_type, BlessTupleDesc */
#include "src/include/pg_vault_tde_hw_accel.h"
#include <openssl/opensslv.h>       /* OPENSSL_VERSION_TEXT */

/*
 * vault_probe_health — lightweight Vault connectivity probe.
 *
 * Calls GET /v1/sys/health which is unauthenticated (no token required)
 * and returns HTTP 200 for an unsealed, active Vault server.  Uses a
 * short 2-second timeout to avoid blocking the backend.
 *
 * Returns true if Vault is reachable and responding, false otherwise.
 */
static bool
vault_probe_health(void)
{
    CURL               *curl;
    CURLcode            res;
    char                url[1024];
    long                http_code = 0;
    bool                reachable = false;

    if (pg_vault_tde_vault_url == NULL || pg_vault_tde_vault_url[0] == '\0')
        return false;

    snprintf(url, sizeof(url), "%s/v1/sys/health", pg_vault_tde_vault_url);

    curl = curl_easy_init();
    if (curl == NULL)
        return false;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L);    /* intentionally short */
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);            /* HEAD-style: discard body */

    if (pg_vault_tde_vault_ca_cert != NULL &&
        pg_vault_tde_vault_ca_cert[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_CAINFO, pg_vault_tde_vault_ca_cert);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        /* 200 = active+unsealed, 429 = standby, 472 = perf-standby — all "alive" */
        reachable = (http_code == 200 || http_code == 429 || http_code == 472);
    }

    curl_easy_cleanup(curl);
    return reachable;
}

/*
 * detect_aes_ni — check x86 AES-NI / ARM CE availability at runtime.
 *
 * On x86_64: reads /proc/cpuinfo for the "aes" flag.
 * On aarch64: reads /proc/cpuinfo for the "aes" feature.
 * Falls back to false if /proc/cpuinfo is not readable (e.g. non-Linux).
 */
static bool
detect_aes_ni(void)
{
#ifdef __linux__
    FILE *fp = fopen("/proc/cpuinfo", "r");
    char  line[4096];
    bool  found = false;

    if (fp == NULL)
        return false;

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        /* x86: "flags" line; ARM: "Features" line — both list "aes" */
        if ((strncmp(line, "flags", 5) == 0 ||
             strncmp(line, "Features", 8) == 0) &&
            strstr(line, " aes") != NULL)
        {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
#else
    return false;
#endif
}

PG_FUNCTION_INFO_V1(pg_vault_tde_health_check);
PGDLLEXPORT Datum
pg_vault_tde_health_check(PG_FUNCTION_ARGS)
{
    TupleDesc       tupdesc;
    Datum           values[15];
    bool            nulls[15];
    HeapTuple       result_tup;

    /* State variables */
    bool            dek_valid = false;
    uint64          gen = 0;
    bool            prev_dek_valid_flag = false;
    bool            vault_configured;
    bool            vault_reachable = false;
    bool            token_available;
    bool            encryption_enabled;
    bool            aes_ni;
    const char     *overall;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    tupdesc = BlessTupleDesc(tupdesc);

    memset(nulls, 0, sizeof(nulls));

    /* --- Vault state --- */
    vault_configured = (pg_vault_tde_vault_url != NULL &&
                        pg_vault_tde_vault_url[0] != '\0');
    if (vault_configured)
        vault_reachable = vault_probe_health();

    /* --- Auth / token state --- */
    token_available = (vault_get_effective_token() != NULL &&
                       vault_get_effective_token()[0] != '\0');

    /* --- Other flags --- */
    encryption_enabled = pg_vault_tde_enabled;
    aes_ni = detect_aes_ni();

    /* --- overall_status derivation --- */
    if (!dek_valid)
        overall = "error";
    else if (vault_configured && (!vault_reachable || !token_available))
        overall = "degraded";
    else
        overall = "healthy";

    /* --- Fill 15-column composite --- */
    /*  0: overall_status text */
    values[0] = CStringGetTextDatum(overall);
    /*  1: dek_valid boolean */
    values[1] = BoolGetDatum(dek_valid);
    /*  2: generation bigint */
    values[2] = Int64GetDatum((int64) gen);
    /*  3: prev_dek_available boolean */
    values[3] = BoolGetDatum(prev_dek_valid_flag);
    /*  4: vault_configured boolean */
    values[4] = BoolGetDatum(vault_configured);
    /*  5: vault_url text */
    if (pg_vault_tde_vault_url != NULL && pg_vault_tde_vault_url[0] != '\0')
        values[5] = CStringGetTextDatum(pg_vault_tde_vault_url);
    else
        nulls[5] = true;
    /*  6: vault_reachable boolean */
    values[6] = BoolGetDatum(vault_reachable);
    /*  7: auth_method text */
    values[7] = CStringGetTextDatum(
        pg_vault_tde_vault_auth_method ? pg_vault_tde_vault_auth_method : "token");
    /*  8: token_available boolean */
    values[8] = BoolGetDatum(token_available);
    /*  9: openssl_version text */
    values[9] = CStringGetTextDatum(OPENSSL_VERSION_TEXT);
    /* 10: aes_ni_available boolean */
    values[10] = BoolGetDatum(aes_ni);
    /* 11: crypto_provider text */
    {
        const char *prov = tde_hw_accel_provider_name();
        values[11] = CStringGetTextDatum(prov != NULL && prov[0] != '\0' ? prov : "default");
    }
    /* 12: encryption_enabled boolean */
    values[12] = BoolGetDatum(encryption_enabled);
    /* 13: dek_cache_ttl integer */
    values[13] = Int32GetDatum(pg_vault_tde_dek_cache_ttl);

    /*
     * 14: wrapped_dek_perms text (v1.4)
     *
     * Report the octal permission bits of the wrapped-DEK file so
     * operators can verify the file is mode 0600.  Returns NULL when
     * Vault integration is not configured (no path) or the file does
     * not yet exist (first boot, or Vault never reached).
     */
    {
        char   *dek_path = NULL;
        struct stat st;

        if (dek_path != NULL && dek_path[0] != '\0' &&
            stat(dek_path, &st) == 0)
        {
            char perm_str[8];
            snprintf(perm_str, sizeof(perm_str), "%04o",
                     (int) (st.st_mode & 0777));
            values[14] = CStringGetTextDatum(perm_str);
        }
        else
            nulls[14] = true;

        if (dek_path != NULL)
            pfree(dek_path);
    }

    result_tup = heap_form_tuple(tupdesc, values, nulls);
    PG_RETURN_DATUM(HeapTupleGetDatum(result_tup));
}

/* ================================================================
 * Background Worker: Vault Token Renewal (v1.3)
 *
 * A single BGW runs in the postmaster alongside the backends and
 * periodically calls vault_refresh_token_internal().  On success it
 * stores the renewed token in shmem (shared_token) so all backends
 * can read it without performing individual logins.
 *
 * Lifecycle:
 *   _PG_init → RegisterBackgroundWorker (must happen before fork)
 *   postmaster forks → BGW starts → WaitLatch loop
 *   On SIGTERM: clean exit via CHECK_FOR_INTERRUPTS
 *
 * GUCs:
 *   pg_vault_tde.bgw_enabled (bool) — default false
 *   pg_vault_tde.token_renewal_interval (int, seconds) — default 3600
 * ================================================================ */

#include "postmaster/bgworker.h"
#include "pgstat.h"                 /* pgstat_report_activity */
#include "storage/ipc.h"            /* proc_exit */
#include "storage/latch.h"          /* WaitLatch */

PGDLLEXPORT void pg_vault_tde_bgw_main(Datum main_arg);

/*
 * pg_vault_tde_bgw_main — background worker entry point.
 *
 * Runs a WaitLatch loop that wakes every token_renewal_interval seconds
 * and renews the Vault token.  On success, stores the shared token in
 * shmem so all backends can read it.
 *
 * If token renewal fails, the BGW logs a warning and retries on the
 * next cycle.  It never exits on failure — only on SIGTERM/postmaster death.
 */
void
pg_vault_tde_bgw_main(Datum main_arg)
{
    int     interval_ms;

    /* Register signal handlers (BGW must do this itself) */
    pqsignal(SIGTERM, die);
    BackgroundWorkerUnblockSignals();

    ereport(LOG,
            (errmsg("pg_vault_tde: token renewal BGW started "
                    "(interval=%ds, auth_method=%s)",
                    pg_vault_tde_token_renewal_interval,
                    pg_vault_tde_vault_auth_method ? pg_vault_tde_vault_auth_method : "token")));

    /* Convert seconds → ms for WaitLatch */
    interval_ms = pg_vault_tde_token_renewal_interval * 1000;
    if (interval_ms <= 0)
        interval_ms = 3600000;  /* safety fallback: 1 hour */

    for (;;)
    {
        int   rc;

        /* Wait for the configured interval or a signal */
        rc = WaitLatch(MyLatch,
                       WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
                       interval_ms,
                       PG_WAIT_EXTENSION);

        ResetLatch(MyLatch);

        if (rc & WL_POSTMASTER_DEATH)
            proc_exit(1);

        /* CHECK_FOR_INTERRUPTS processes ProcDiePending set by die() */
        CHECK_FOR_INTERRUPTS();

        /* Skip renewal if auth is static token (no dynamic login needed) */
        if (pg_vault_tde_vault_auth_method == NULL ||
            strcmp(pg_vault_tde_vault_auth_method, "token") == 0)
            continue;

        /* Attempt token renewal */
        pgstat_report_activity(STATE_RUNNING, "renewing Vault token");

        if (vault_refresh_token_internal())
        {
            /*
             * Store the renewed token in shmem so all backends can use it.
             * vault_active_token in this process was updated by the
             * vault_refresh_token_internal → vault_get_effective_token chain.
             */
            if (vault_active_token != NULL && kms_cache != NULL)
            {
                LWLockAcquire(&kms_cache->lock, LW_EXCLUSIVE);
                strlcpy(kms_cache->shared_token, vault_active_token,
                        sizeof(kms_cache->shared_token));
                kms_cache->shared_token_valid = true;
                kms_cache->token_renewed_at = GetCurrentTimestamp();
                LWLockRelease(&kms_cache->lock);
            }

            ereport(DEBUG1,
                    (errmsg("pg_vault_tde: BGW token renewal successful")));
        }
        else
        {
            /*
             * Renewal failed — try a fresh login instead.
             * Clear the cached token to force re-authentication.
             */
            if (vault_active_token)
            {
                OPENSSL_cleanse(vault_active_token, strlen(vault_active_token));
                pfree(vault_active_token);
                vault_active_token = NULL;
            }

            {
                char *new_token = vault_perform_login();
                if (new_token != NULL)
                {
                    MemoryContext old_ctx = MemoryContextSwitchTo(TopMemoryContext);
                    vault_active_token = pstrdup(new_token);
                    MemoryContextSwitchTo(old_ctx);
                    pfree(new_token);

                    /* Store in shmem */
                    if (kms_cache != NULL)
                    {
                        LWLockAcquire(&kms_cache->lock, LW_EXCLUSIVE);
                        strlcpy(kms_cache->shared_token, vault_active_token,
                                sizeof(kms_cache->shared_token));
                        kms_cache->shared_token_valid = true;
                        kms_cache->token_renewed_at = GetCurrentTimestamp();
                        LWLockRelease(&kms_cache->lock);
                    }

                    ereport(LOG,
                            (errmsg("pg_vault_tde: BGW re-login successful after renewal failure")));
                }
                else
                {
                    ereport(WARNING,
                            (errmsg("pg_vault_tde: BGW token renewal AND re-login failed — "
                                    "will retry in %d seconds",
                                    pg_vault_tde_token_renewal_interval)));
                }
            }
        }

        pgstat_report_activity(STATE_IDLE, NULL);
    }

    /* Unreachable — die() will call proc_exit via CHECK_FOR_INTERRUPTS */
    proc_exit(0);
}

/*
 * pg_vault_tde_register_bgw — register the token renewal background worker.
 *
 * Must be called from _PG_init() before the postmaster forks.
 * Only registers if pg_vault_tde.bgw_enabled = true AND
 * auth_method is not "token" (static tokens don't need renewal).
 */
void
pg_vault_tde_register_bgw(void)
{
    BackgroundWorker  worker;

    if (!pg_vault_tde_bgw_enabled)
        return;

    memset(&worker, 0, sizeof(BackgroundWorker));

    snprintf(worker.bgw_name, BGW_MAXLEN, "pg_vault_tde token renewal");
    snprintf(worker.bgw_type, BGW_MAXLEN, "pg_vault_tde bgw");
    snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_vault_tde");
    snprintf(worker.bgw_function_name, BGW_MAXLEN, "pg_vault_tde_bgw_main");

    worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
    worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
    worker.bgw_restart_time = 60;    /* restart 60s after crash */
    worker.bgw_main_arg = (Datum) 0;
    worker.bgw_notify_pid = 0;

    RegisterBackgroundWorker(&worker);

    ereport(LOG,
            (errmsg("pg_vault_tde: background worker registered "
                    "(interval=%ds)",
                    pg_vault_tde_token_renewal_interval)));
}

/* =========================================================================
 * v1.5: KMS Provider vtable for the Vault/OpenBao backend
 *
 * Wraps the existing Vault-specific function into the
 * TdeKmsProvider interface so that pg_vault_tde.c can select providers
 * by name at startup.
 *
 * The vault provider's init(), wrap_dek(), and unwrap_dek()
 * are thin actual function performing operations.  
 * =========================================================================*/

#include "src/kms/pg_vault_tde_kms_provider.h"

/*
 * vault_resp_init / vault_resp_free — lifecycle helpers for vault_resp_buf.
 */
static bool
vault_resp_init(vault_response_buf *buf)
{
    buf->alloc  = 2048;
    buf->len    = 0;
    buf->data   = palloc(buf->alloc);
    buf->data[0] = '\0';
    return true;
}

static void
vault_resp_free(vault_response_buf *buf)
{
    if (buf->data)
    {
        OPENSSL_cleanse(buf->data, buf->len);
        pfree(buf->data);
        buf->data = NULL;
        buf->len  = 0;
    }
}

/*
 * vault_make_curl — create and configure a CURL handle with common options.
 *
 * Sets the CA cert and timeout from config if provided.
 * Caller must curl_easy_cleanup() the returned handle.
 */
static CURL *
vault_make_curl(vault_response_buf *resp)
{
    CURL   *curl = curl_easy_init();

    if (curl == NULL)
        return NULL;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vault_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);

    if (pg_vault_tde_vault_ca_cert && pg_vault_tde_vault_ca_cert[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_CAINFO, pg_vault_tde_vault_ca_cert);

    if(pg_vault_tde_vault_timeout_ms > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) pg_vault_tde_vault_timeout_ms);

    return curl;
}

/*
 * vault_add_namespace_header — append X-Vault-Namespace header if set.
 */
static struct curl_slist *
vault_add_namespace_header(struct curl_slist *headers)
{
    char hdr[288];

    if (pg_vault_tde_vault_namespace && pg_vault_tde_vault_namespace[0] != '\0')
    {
        snprintf(hdr, sizeof(hdr), "X-Vault-Namespace: %s",
                pg_vault_tde_vault_namespace);
        headers = curl_slist_append(headers, hdr);
    }
    return headers;
}

/*
 * vault_transit_request -- utility used by both vault_wrap_dek 
 * and vault_unwrap_dek to make a request to the transit endpoints.
 * 
 */

/*
 * vault_transit_request -- POST to a Vault Transit endpoint.
 *
 * path   : URL path starting with '/', e.g. "/v1/transit/encrypt/mykey".
 *          The base URL (pg_vault_tde_vault_url) is prepended here; callers
 *          only supply the path so the base GUC is read in exactly one place.
 * body   : JSON request body; NULL or "" for operations that need no body
 *          (e.g. rotate).
 * response: caller-allocated struct; vault_resp_init is called internally.
 *           Caller must call vault_resp_free() after use.
 */
static bool vault_transit_request(const char *path,
                                   const char *body, vault_response_buf *response)
{
    const char          *vault_token  = NULL;
    char                url[1024];
    CURL                *curl          = NULL;
    char                auth_hdr[512];
    struct curl_slist   *headers       = NULL;
    CURLcode            res;
    long                http_code;
    bool volatile       success = false;

    Assert(path != NULL);
    Assert(response != NULL);

    if (pg_vault_tde_vault_url == NULL || pg_vault_tde_vault_url[0] == '\0')
        ereport(ERROR,
            errmsg("pg_vault_tde: vault_url is not set"));

    if ((vault_token = vault_get_effective_token()) == NULL)
        ereport(ERROR,
            errmsg("pg_vault_tde: authentication failed"));

    /* Base URL is read only here; callers supply the path. */
    snprintf(url, sizeof(url), "%s%s", pg_vault_tde_vault_url, path);

    PG_TRY();
    {
        if (!vault_resp_init(response))
            ereport(ERROR,
                errmsg("pg_vault_tde: buffer allocation for response failed"));

        curl = vault_make_curl(response);
        if (curl == NULL)
            ereport(ERROR,
                errmsg("pg_vault_tde: curl init failed"));

        snprintf(auth_hdr, sizeof(auth_hdr),
                "X-Vault-Token: %s", vault_token);

        headers = curl_slist_append(headers, auth_hdr);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = vault_add_namespace_header(headers);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body != NULL ? body : "");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);

        if (response->overflow)
            ereport(ERROR,
                errmsg("pg_vault_tde: Vault response too large (limit %d bytes)",
                        VAULT_RESPONSE_MAX));
        else if (res == CURLE_OK)
        {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code == 200)
                success = true;
            else
                ereport(ERROR,
                    errmsg("pg_vault_tde: Vault %s returned HTTP %ld (response %.256s)",
                            path, http_code, response->data));
        }
        else
            ereport(ERROR,
                errmsg("pg_vault_tde: HTTP request to %s failed: %s",
                        path, curl_easy_strerror(res)));
    }
    PG_CATCH();
    {
        if (curl)
        {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
        OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));
        PG_RE_THROW();
    }
    PG_END_TRY();

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));

    return success;
}


static bool
vault_provider_init(void)
{  
    return true;
}

static bool
vault_provider_wrap_dek(const unsigned char *dek, int dek_len,
                        unsigned char *wrapped_out, int *out_len)
{
    vault_response_buf  resp;
    char               *ciphertext = NULL;
    char               *post_body  = NULL;
    char                path[512];
    bool                success    = false;
    size_t              b64_len    = ((dek_len + 2) / 3) * 4 + 1;
    char               *b64_dek   = palloc(b64_len);

    EVP_EncodeBlock((unsigned char *) b64_dek, dek, dek_len);

    post_body = palloc(b64_len + 32);
    snprintf(post_body, b64_len + 32, "{\"plaintext\": \"%s\"}", b64_dek);

    OPENSSL_cleanse(b64_dek, b64_len);
    pfree(b64_dek);

    snprintf(path, sizeof(path), "/v1/%s/encrypt/%s",
             pg_vault_tde_vault_transit_mount,
             pg_vault_tde_vault_key_name);

    if (vault_transit_request(path, post_body, &resp))
    {
        ciphertext = vault_json_extract_string(resp.data, "ciphertext");
        if (ciphertext != NULL)
        {
            size_t ct_len = strlen(ciphertext);

            if (ct_len > (size_t) *out_len)
                ereport(ERROR, errmsg("pg_vault_tde: wrapped DEK (%zu) exceeds buffer (%d)",
                                      ct_len, *out_len));
            memcpy(wrapped_out, ciphertext, ct_len);
            *out_len = (int) ct_len;
            success = true;
        }
    }

    if (post_body)
    {
        OPENSSL_cleanse(post_body, strlen(post_body));
        pfree(post_body);
    }
    vault_resp_free(&resp);
    if (ciphertext)
    {
        OPENSSL_cleanse(ciphertext, strlen(ciphertext));
        pfree(ciphertext);
    }
    return success;
}

static bool
vault_provider_unwrap_dek(const unsigned char *wrapped, int wrapped_len,
                           unsigned char *dek_out, int *dek_len)
{
    vault_response_buf  resp;
    char               *plaintext_b64 = NULL;
    char               *post_body     = NULL;
    char                path[512];
    bool                success       = false;
    unsigned char       raw_dek[TDE_DEK_LEN];
    int                 decoded_len;
    Size                body_len      = wrapped_len + 64 + 1;

    Assert(dek_out != NULL && dek_len != NULL);

    post_body = palloc(body_len);
    snprintf(post_body, body_len, "{\"ciphertext\": \"%.*s\"}",
             (int) wrapped_len, (const char *) wrapped);

    snprintf(path, sizeof(path), "/v1/%s/decrypt/%s",
             pg_vault_tde_vault_transit_mount,
             pg_vault_tde_vault_key_name);

    if (vault_transit_request(path, post_body, &resp))
    {
        plaintext_b64 = vault_json_extract_string(resp.data, "plaintext");
        if (plaintext_b64 != NULL)
        {
            decoded_len = vault_base64_decode(plaintext_b64, raw_dek, TDE_DEK_LEN);
            if (decoded_len == TDE_DEK_LEN)
            {
                memcpy(dek_out, raw_dek, TDE_DEK_LEN);
                *dek_len = TDE_DEK_LEN;
                success = true;
            }
            OPENSSL_cleanse(raw_dek, TDE_DEK_LEN);
            OPENSSL_cleanse(plaintext_b64, strlen(plaintext_b64));
            pfree(plaintext_b64);
            plaintext_b64 = NULL;
        }
    }

    if (post_body)
    {
        OPENSSL_cleanse(post_body, strlen(post_body));
        pfree(post_body);
    }
    vault_resp_free(&resp);
    if (plaintext_b64)
    {
        OPENSSL_cleanse(plaintext_b64, strlen(plaintext_b64));
        pfree(plaintext_b64);
    }
    return success;
}

static bool
vault_provider_health_check(void)
{
    const char *tok = vault_get_effective_token();

    if (tok == NULL || tok[0] == '\0')
        return false;
    return vault_probe_health();
}

static void
vault_provider_shutdown(void)
{
    /* Nothing to do: curl handles cleaned up in tde_backend_cleanup() */
}

/* -------------------------------------------------------------------------
 * vault_prepare_kek_rotation — POST /v1/<mount>/keys/<key>/rotate to Vault.
 *
 * After this call Vault uses a new key version for encrypt; old versions
 * remain available for decrypt (ciphertext is version-tagged as vault:vN:…).
 * vault_provider_rewrap_dek (unwrap + wrap) automatically re-wraps under the
 * new version because wrap always uses the latest key.
 * -------------------------------------------------------------------------*/
static bool
vault_prepare_kek_rotation(void)
{
    vault_response_buf  response;
    char                path[512];

    /* Vault Transit rotate endpoint: POST /v1/<mount>/keys/<key>/rotate */
    snprintf(path, sizeof(path), "/v1/%s/keys/%s/rotate",
             pg_vault_tde_vault_transit_mount,
             pg_vault_tde_vault_key_name);

    if (!vault_transit_request(path, NULL, &response))
    {
        vault_resp_free(&response);
        ereport(ERROR,
                errmsg("pg_vault_tde: Vault KEK rotate failed"));
    }

    vault_resp_free(&response);
    return true;
}

PGDLLEXPORT Datum
pg_vault_tde_vault_status(PG_FUNCTION_ARGS)
{
    TupleDesc   tupdesc;
    Datum       values[3];
    bool        nulls[3];
    HeapTuple   result_tuple;

    /* State variables */
    bool    vault_configured    = false;
    bool    reachable   = false;

    if(get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    
    tupdesc = BlessTupleDesc(tupdesc);

    memset(nulls, 0, sizeof(nulls));

    vault_configured = (pg_vault_tde_vault_url != NULL &&
                        pg_vault_tde_vault_url[0] != '\0');
    
    vault_configured = vault_configured &&
                    (pg_vault_tde_kms_provider != NULL &&
                    strcmp(pg_vault_tde_kms_provider, "vault") == 0);

    if(vault_configured)
        reachable = vault_probe_health();

    values[0] = BoolGetDatum(vault_configured);
    values[1] = CStringGetTextDatum(pg_vault_tde_vault_auth_method ? pg_vault_tde_vault_auth_method : "Not configured");
    values[2] = BoolGetDatum(reachable);

    result_tuple = heap_form_tuple(tupdesc, values, nulls);
    PG_RETURN_DATUM(HeapTupleGetDatum(result_tuple));
}

static void
vault_commit_kek_rotation(void)
{
    /* Vault manages key versions server-side — nothing to do locally. */
}

static const TdeKmsProvider vault_provider_impl = {
    .name                 = "vault",
    .init                 = vault_provider_init,
    .wrap_dek             = vault_provider_wrap_dek,
    .unwrap_dek           = vault_provider_unwrap_dek,
    .rewrap_dek           = vault_provider_rewrap_dek,
    .prepare_kek_rotation = vault_prepare_kek_rotation,
    .commit_kek_rotation  = vault_commit_kek_rotation,
    .health_check         = vault_provider_health_check,
    .shutdown             = vault_provider_shutdown,
};

const TdeKmsProvider *
pg_vault_tde_kms_vault_provider(void)
{
    return &vault_provider_impl;
}

