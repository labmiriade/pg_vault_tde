/*
 * pg_dump_tde_kms_vault.c — Vault KMS provider for pg_dump_tde.
 *
 * Implements PdeKmsProvider for HashiCorp Vault / OpenBao Transit Engine.
 * Runs in a frontend (pg_dump) process — uses palloc/free, not palloc,
 * and pg_log_error instead of ereport.
 *
 * Authentication methods supported:
 *   token      — static Vault token from GUC pg_vault_tde.vault_token
 *   approle    — dynamic login via role_id + secret_id
 *   kubernetes — dynamic login via K8s service account JWT
 *
 * IMPORTANT: unlike the backend KMS module, this code does NOT destroy
 * the AppRole secret_id after login.  pg_dump is a one-shot process and
 * the secret_id credential may already have been consumed by the backend;
 * destroying it here would corrupt a still-valid credential.  Operators
 * must provision a separate, dedicated secret_id for backup operations.
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 */

#include "postgres_fe.h"
#include "common/logging.h"
#include "common/fe_memutils.h"
#include "pg_dump_tde_kms.h"


#include <curl/curl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

/* Maximum field sizes for Vault configuration strings. */
#define VAULT_URL_MAX       512
#define VAULT_AUTH_MAX       64
#define VAULT_PATH_MAX      256
#define VAULT_TOKEN_MAX     512
#define VAULT_CRED_MAX      256
#define VAULT_NS_MAX        256

/*
 * PdeVaultConfig — all Vault connection parameters read from PostgreSQL GUCs
 * via a libpq connection.  Fields are fixed-size char arrays so that
 * LOAD_PARAM can use strlcpy + sizeof safely.
 */
typedef struct PdeVaultConfig
{
    char    vault_url[VAULT_URL_MAX];
    char    auth_method[VAULT_AUTH_MAX];
    char    transit_mount[VAULT_PATH_MAX];
    char    key_name[VAULT_PATH_MAX];
    char    ca_cert[VAULT_PATH_MAX];
    char    token[VAULT_TOKEN_MAX];
    char    role_id[VAULT_CRED_MAX];
    char    secret_id[VAULT_CRED_MAX];
    /* Kubernetes auth fields */
    char    k8s_role[VAULT_CRED_MAX];
    char    k8s_mount[VAULT_PATH_MAX];
    /* Enterprise / optional */
    char    vault_namespace[VAULT_NS_MAX];
    char    timeout_ms[32];             /* stored as string, parsed to long */
} PdeVaultConfig;

static PdeVaultConfig* config = NULL;

/*
 * vault_resp_buf — growable buffer for libcurl WRITEFUNCTION callback.
 * Uses palloc/realloc since this is frontend code.
 */
typedef struct
{
    char   *data;
    size_t  len;
    size_t  alloc;
} vault_resp_buf;

static bool     vault_init(PGconn * conn);

static bool     vault_generate_dek(unsigned char *out, int len);
static bool     vault_wrap_dek(const unsigned char *dek, int dek_len,
                                unsigned char *out, int *out_len);
static char    *vault_perform_login(const PdeVaultConfig *config);
static bool     vault_config_load(PGconn *conn, PdeVaultConfig *config);

/* Public: wrap DEK when a PGconn is available. */
char           *vault_wrap_dek_with_config(PGconn *conn,
                                            const unsigned char *dek,
                                            int dek_len);

/* -------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------
 */

/*
 * vault_write_cb — libcurl WRITEFUNCTION that appends data to vault_resp_buf.
 *
 * Uses realloc for growth; caller must pfree buf->data when done.
 */
static size_t
vault_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    vault_resp_buf *buf     = (vault_resp_buf *) userdata;
    size_t          bytes   = size * nmemb;

    if (buf->len + bytes + 1 > buf->alloc)
    {
        size_t  new_alloc = (buf->len + bytes + 1) * 2;
        char   *tmp = realloc(buf->data, new_alloc);

        if (tmp == NULL)
            return 0;   /* signal error to curl */
        buf->data   = tmp;
        buf->alloc  = new_alloc;
    }
    memcpy(buf->data + buf->len, ptr, bytes);
    buf->len            += bytes;
    buf->data[buf->len]  = '\0';
    return bytes;
}

/*
 * vault_resp_init / vault_resp_free — lifecycle helpers for vault_resp_buf.
 */
static bool
vault_resp_init(vault_resp_buf *buf)
{
    buf->alloc  = 2048;
    buf->len    = 0;
    buf->data   = palloc(buf->alloc);
    buf->data[0] = '\0';
    return true;
}

static void
vault_resp_free(vault_resp_buf *buf)
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
 * vault_json_extract_string — extract a JSON string value by key.
 *
 * Minimal parser: finds "key": "value" and returns a palloc'd copy of
 * value.  Adequate for Vault API responses which have a flat structure.
 * Caller must pfree() the result.  Returns NULL if key not found.
 */
static char *
vault_json_extract_string(const char *json, const char *key)
{
    char        pattern[256];
    const char *pos;
    const char *start;
    const char *end;
    size_t      val_len;
    char       *result;

    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    pos = strstr(json, pattern);
    if (pos == NULL)
        return NULL;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' ||
           *pos == ':')
        pos++;

    if (*pos != '"')
        return NULL;

    start = pos + 1;
    end   = start;
    while (*end != '\0' && *end != '"')
    {
        if (*end == '\\')
            end++;
        if (*end != '\0')
            end++;
    }

    val_len = end - start;
    result  = palloc(val_len + 1);
    memcpy(result, start, val_len);
    result[val_len] = '\0';
    return result;
}

/*
 * vault_make_curl — create and configure a CURL handle with common options.
 *
 * Sets the CA cert and timeout from config if provided.
 * Caller must curl_easy_cleanup() the returned handle.
 */
static CURL *
vault_make_curl(const PdeVaultConfig *config, vault_resp_buf *resp)
{
    CURL   *curl = curl_easy_init();
    long    timeout_ms;

    if (curl == NULL)
        return NULL;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vault_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);

    if (config->ca_cert[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_CAINFO, config->ca_cert);

    timeout_ms = config->timeout_ms[0] != '\0'
                    ? strtol(config->timeout_ms, NULL, 10) : 5000;
    if (timeout_ms > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);

    return curl;
}

/*
 * vault_add_namespace_header — append X-Vault-Namespace header if set.
 */
static struct curl_slist *
vault_add_namespace_header(struct curl_slist *headers,
                           const PdeVaultConfig *config)
{
    char hdr[VAULT_NS_MAX + 32];

    if (config->vault_namespace[0] != '\0')
    {
        snprintf(hdr, sizeof(hdr), "X-Vault-Namespace: %s",
                 config->vault_namespace);
        headers = curl_slist_append(headers, hdr);
    }
    return headers;
}

/* -------------------------------------------------------------------------
 * vault_perform_login
 * -------------------------------------------------------------------------
 */

/*
 * vault_perform_login — authenticate to Vault and return a client token.
 *
 * For "token" auth: returns a strdup of config->token directly (no HTTP).
 * For "approle":    POST /v1/auth/approle/login {role_id, secret_id}.
 * For "kubernetes": POST /v1/auth/<mount>/login {role, jwt} where the JWT
 *                   is read from the standard K8s service account file.
 *
 * Returns a palloc'd token string on success, NULL on failure.
 * Caller must OPENSSL_cleanse + pfree the result when done.
 *
 * Note: the AppRole secret_id is NOT destroyed after login.  See the file
 * header for the rationale.
 */
static char *
vault_perform_login(const PdeVaultConfig *config)
{
    CURL               *curl;
    CURLcode            res;
    struct curl_slist  *headers = NULL;
    vault_resp_buf      resp;
    char                url[VAULT_URL_MAX + 64];
    char                post_body[8192 + 256];  /* large enough for JWT */
    char               *token = NULL;
    long                http_code = 0;

    if (config->vault_url[0] == '\0')
    {
        pg_log_error("vault: vault_url is not set");
        return NULL;
    }

    /* --- "token" auth: no login needed --- */
    if (config->auth_method[0] == '\0' ||
        strcmp(config->auth_method, "token") == 0)
    {
        if (config->token[0] == '\0')
        {
            pg_log_error("vault: auth_method=token but vault_token is empty");
            return NULL;
        }
        return pg_strdup(config->token);
    }

    /* --- AppRole --- */
    if (strcmp(config->auth_method, "approle") == 0)
    {
        if (config->role_id[0] == '\0')
        {
            pg_log_error("vault: AppRole auth requires vault_role_id");
            return NULL;
        }
        snprintf(url, sizeof(url), "%s/v1/auth/approle/login",
                 config->vault_url);
        snprintf(post_body, sizeof(post_body),
                 "{\"role_id\": \"%s\", \"secret_id\": \"%s\"}",
                 config->role_id,
                 config->secret_id);
    }
    /* --- Kubernetes JWT --- */
    else if (strcmp(config->auth_method, "kubernetes") == 0)
    {
        static const char *jwt_path =
            "/var/run/secrets/kubernetes.io/serviceaccount/token";
        FILE   *fp;
        char    jwt[8192];
        size_t  jwt_len;

        if (config->k8s_role[0] == '\0')
        {
            pg_log_error("vault: Kubernetes auth requires vault_k8s_role");
            return NULL;
        }

        fp = fopen(jwt_path, "r");
        if (fp == NULL)
        {
            pg_log_error("vault: cannot read K8s service account token at %s",
                         jwt_path);
            return NULL;
        }
        jwt_len         = fread(jwt, 1, sizeof(jwt) - 1, fp);
        fclose(fp);
        jwt[jwt_len]    = '\0';

        /* Trim trailing newline */
        while (jwt_len > 0 &&
               (jwt[jwt_len - 1] == '\n' || jwt[jwt_len - 1] == '\r'))
            jwt[--jwt_len] = '\0';

        snprintf(url, sizeof(url), "%s/v1/auth/%s/login",
                 config->vault_url,
                 config->k8s_mount[0] != '\0' ? config->k8s_mount
                                               : "kubernetes");
        snprintf(post_body, sizeof(post_body),
                 "{\"role\": \"%s\", \"jwt\": \"%s\"}",
                 config->k8s_role, jwt);

        OPENSSL_cleanse(jwt, sizeof(jwt));
    }
    else
    {
        pg_log_error("vault: unsupported auth_method \"%s\"",
                     config->auth_method);
        return NULL;
    }

    if (!vault_resp_init(&resp))
    {
        pg_log_error("vault: out of memory");
        OPENSSL_cleanse(post_body, sizeof(post_body));
        return NULL;
    }

    curl = vault_make_curl(config, &resp);
    if (curl == NULL)
    {
        pg_log_error("vault: curl_easy_init failed");
        OPENSSL_cleanse(post_body, sizeof(post_body));
        vault_resp_free(&resp);
        return NULL;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = vault_add_namespace_header(headers, config);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200)
        {
            /*
             * Vault login response: {"auth": {"client_token": "...", ...}}
             * vault_json_extract_string finds the first occurrence of the
             * key anywhere in the JSON, which correctly hits "client_token"
             * inside the "auth" sub-object.
             */
            token = vault_json_extract_string(resp.data, "client_token");
            if (token == NULL)
                pg_log_error("vault: login response missing client_token "
                             "(response: %.256s)", resp.data);
        }
        else
            pg_log_error("vault: login returned HTTP %ld (response: %.256s)",
                         http_code, resp.data);
    }
    else
        pg_log_error("vault: login HTTP request failed: %s",
                     curl_easy_strerror(res));

    OPENSSL_cleanse(post_body, sizeof(post_body));
    vault_resp_free(&resp);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return token;
}

/* -------------------------------------------------------------------------
 * vault_config_load
 * -------------------------------------------------------------------------
 */

/*
 * vault_config_load — read Vault GUCs from a live PostgreSQL connection.
 *
 * Uses SHOW <guc> for each parameter.  Missing or empty GUCs are stored
 * as empty strings; callers must validate required fields themselves.
 */
static bool
vault_config_load(PGconn *conn, PdeVaultConfig *config)
{
    LOAD_PARAM(vault_url,       "pg_vault_tde.vault_url");
    LOAD_PARAM(auth_method,     "pg_vault_tde.vault_auth_method");
    LOAD_PARAM(transit_mount,   "pg_vault_tde.vault_transit_mount");
    LOAD_PARAM(key_name,        "pg_vault_tde.vault_key_name");
    LOAD_PARAM(ca_cert,         "pg_vault_tde.vault_ca_cert");
    LOAD_PARAM(token,           "pg_vault_tde.vault_token");
    LOAD_PARAM(role_id,         "pg_vault_tde.vault_role_id");
    LOAD_PARAM(secret_id,       "pg_vault_tde.vault_secret_id");
    LOAD_PARAM(k8s_role,        "pg_vault_tde.vault_k8s_role");
    LOAD_PARAM(k8s_mount,       "pg_vault_tde.vault_k8s_mount");
    LOAD_PARAM(vault_namespace, "pg_vault_tde.vault_namespace");
    LOAD_PARAM(timeout_ms,      "pg_vault_tde.vault_timeout_ms");

    return true;
}

/* -------------------------------------------------------------------------
 * PdeKmsProvider callbacks
 * -------------------------------------------------------------------------
 */

/*
 * vault_generate_dek — fill `out` with `len` cryptographically random bytes.
 *
 * Uses OpenSSL RAND_bytes.  In a frontend process there is no fork-safety
 * concern with the OpenSSL PRNG (no postmaster fork after this point),
 * so RAND_bytes is appropriate here (unlike the backend, which requires
 * pg_strong_random to avoid PRNG state sharing across forks).
 */
static bool
vault_generate_dek(unsigned char *out, int len)
{
    if (RAND_bytes(out, len) != 1)
    {
        pg_log_error("vault: RAND_bytes failed to generate %d-byte DEK", len);
        return false;
    }
    return true;
}
/*
 * vault_wrap_dek — wrap the DEK using Vault Transit encrypt.
 *
 * Encodes the raw DEK as base64, POSTs to Vault Transit /encrypt,
 * then base64-decodes the ciphertext into @out.
 */
static bool
vault_wrap_dek(const unsigned char *dek, int dek_len,
               unsigned char *out, int *out_len)
{
    char               *vault_token    = NULL;
    CURL               *curl           = NULL;
    struct curl_slist  *headers        = NULL;
    vault_resp_buf      resp;
    char               *ciphertext     = NULL;
    char                auth_hdr[VAULT_TOKEN_MAX + 20];
    char                url[VAULT_URL_MAX + 128];
    char               *post_body      = NULL;
    long                http_code      = 0;
    CURLcode            res;
    bool success = false;

    if(config == NULL || config->vault_url[0] == '\0')
    {
        pg_log_error("pg_dump_tde: vault_url is not set");
        return false;
    }

    if((vault_token = vault_perform_login(config)) == NULL)
    {
        pg_log_error("pg_dump_tde: authentication failed");
        return false;
    }

    /* Base64-encode the DEK*/
    size_t b64_len = ((dek_len + 2)/3) * 4 + 1; /* Standard formula 3 byte in -> 4 ASCII out*/
    char *b64_dek = palloc(b64_len);

    EVP_EncodeBlock((unsigned char *) b64_dek, dek, dek_len);

    /*POST v1/<mount>/encrypt/<key> {"plaintext": "<b64>"} */
    snprintf(url, sizeof(url), "%s/v1/%s/encrypt/%s", 
             config->vault_url, 
             config->transit_mount[0] != '\0' ? config->transit_mount : "transit", 
             config->key_name);
    
    /*Write the request body*/
    post_body = palloc(b64_len + 32);
    snprintf(post_body, b64_len + 32, "{\"plaintext\": \"%s\"}", b64_dek);

    OPENSSL_cleanse(b64_dek, b64_len);
    pfree(b64_dek);
    b64_dek = NULL;

    if(!vault_resp_init(&resp))
    {
        pg_log_error("pg_dump_tde: error allocating response");
        goto cleanup;
    }

    curl = vault_make_curl(config, &resp);
    if(curl == NULL)
    {
        pg_log_error("pg_dump_tde: curl init failed");
        goto cleanup;
    }

    snprintf(auth_hdr, sizeof(auth_hdr), "X-Vault-Token: %s", vault_token);
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = vault_add_namespace_header(headers, config);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);

    if(res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if(http_code == 200)
        {
            ciphertext = vault_json_extract_string(resp.data, "ciphertext");
            
            if(ciphertext != NULL)
            {
                size_t new_len = strlen(ciphertext);

                if(new_len > (size_t)*out_len)
                    pg_log_error("pg_dump_tde: Buffer Overflow on ciphertext");
                else{
                    memcpy(out, ciphertext, new_len);
                    *out_len = new_len;
                    success = true;
                }
                
            }
        }
        else
            pg_log_error("pg_dump_tde: encrypt returned HTTP %ld (reponse %.256s)", 
                         http_code, resp.data);
    }
    else    
        pg_log_error("pg_dump_tde: HTTP request failed");

cleanup: 
    if(b64_dek)
    {
        OPENSSL_cleanse(b64_dek, b64_len);
        pfree(b64_dek);
    }
    if(post_body)
    {
        OPENSSL_cleanse(post_body, strlen(post_body));
        pfree(post_body);
    }
    if(curl)
    {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    vault_resp_free(&resp);

    if(vault_token)
    {
        OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));
        OPENSSL_cleanse(vault_token, strlen(vault_token));
        pfree(vault_token);
    }   

    if(ciphertext)
    {
        OPENSSL_cleanse(ciphertext, strlen(ciphertext));
        pfree(ciphertext);
    }

    return success;
}

static bool vault_init(PGconn *conn)
{
    config = palloc0(sizeof(PdeVaultConfig));
    if(!vault_config_load(conn, config))
    {
        pfree(config);
        config = NULL;
        return false;
    }
    return true;
}

static void vault_shutdown(void)
{
    if(config != NULL)
    {
        OPENSSL_cleanse(config, sizeof(*config));
        pfree(config);
        config = NULL;
    }
}

static const PdeKmsProvider vault_provider_impl = {
    .name           = "vault",
    .init           = vault_init,
    .generate_dek   = vault_generate_dek,
    .wrap_dek       = vault_wrap_dek,
    .shutdown       = vault_shutdown,
};

const PdeKmsProvider *
pg_dump_tde_kms_vault_provider(void)
{
    return &vault_provider_impl;
}
