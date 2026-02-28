/*
 * vault_mock.go — Lightweight HashiCorp Vault Transit API mock server
 *
 * Serves the full API surface required by pg_vault_tde v1.3+:
 *
 *   POST /v1/{mount}/datakey/plaintext/{key_name}
 *     → Returns a random 32-byte DEK as base64 plaintext + wrapped ciphertext
 *
 *   POST /v1/{mount}/decrypt/{key_name}
 *     → Unwraps a ciphertext produced by datakey; returns plaintext DEK.
 *       Used by pg_vault_tde on startup when a wrapped DEK is persisted to
 *       $PGDATA/pg_vault_tde/wrapped_dek.
 *
 *   POST /v1/{mount}/rewrap/{key_name}
 *     → Re-wraps a ciphertext under the current key version (simulates key
 *       rotation without changing the underlying DEK).
 *       Used by pg_vault_tde_vault_rewrap_dek().
 *
 *   POST /v1/auth/approle/login
 *     → Accepts role_id + secret_id, returns a client token.
 *       Used when pg_vault_tde.auth_method = "approle".
 *
 *   POST /v1/auth/token/renew-self
 *     → Renews the caller's token TTL.
 *       Used by the background worker (pg_vault_tde.bgw_enabled = on).
 *
 *   GET  /v1/sys/health
 *     → Returns 200 OK with Vault-compatible health status.
 *
 * Environment variables:
 *   VAULT_MOCK_PORT        — listen port (default: 8200)
 *   VAULT_MOCK_TOKEN       — expected X-Vault-Token (default: "test-token")
 *   VAULT_MOCK_MOUNT       — transit mount path (default: "transit")
 *   VAULT_MOCK_KEY_NAME    — key name (default: "pg-tde-dek")
 *   VAULT_MOCK_ROLE_ID     — AppRole role_id to accept (default: "test-role-id")
 *   VAULT_MOCK_SECRET_ID   — AppRole secret_id to accept (default: "test-secret-id")
 *   VAULT_MOCK_APP_TOKEN   — token issued on successful AppRole login (default: "approle-token")
 *
 * Build:  go build -o vault-mock vault_mock.go
 * Run:    ./vault-mock
 *
 * Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)
 */
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	listenPort   = getEnv("VAULT_MOCK_PORT", "8200")
	token        = getEnv("VAULT_MOCK_TOKEN", "test-token")
	mount        = getEnv("VAULT_MOCK_MOUNT", "transit")
	keyName      = getEnv("VAULT_MOCK_KEY_NAME", "pg-tde-dek")
	roleID       = getEnv("VAULT_MOCK_ROLE_ID", "test-role-id")
	secretID     = getEnv("VAULT_MOCK_SECRET_ID", "test-secret-id")
	approleToken = getEnv("VAULT_MOCK_APP_TOKEN", "approle-token")
)

/*
 * generateDEK produces a random 32-byte AES-256 key.
 * Uses crypto/rand (backed by /dev/urandom on Linux) — NOT math/rand.
 */
func generateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

/*
 * healthHandler responds to GET /v1/sys/health with a Vault-compatible
 * health response.  pg_vault_tde does not call this endpoint yet, but
 * operational tooling (consul-template, envconsul) checks it.
 */
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"initialized":                  true,
		"sealed":                       false,
		"standby":                      false,
		"performance_standby":          false,
		"replication_performance_mode": "disabled",
		"replication_dr_mode":          "disabled",
		"server_time_utc":              time.Now().Unix(),
		"version":                      "1.15.0-mock",
		"cluster_name":                 "vault-mock-tde",
		"cluster_id":                   "mock-cluster-id",
	}
	json.NewEncoder(w).Encode(resp)
}

/*
 * datakeyHandler responds to POST /v1/{mount}/datakey/plaintext/{key_name}
 *
 * This is the primary endpoint pg_vault_tde_vault_fetch_dek() calls.
 * We generate a fresh random 32-byte DEK and return it as base64 in the
 * Vault Transit API response format.
 *
 * In production Vault, the "ciphertext" field contains the DEK wrapped
 * (encrypted) under the named Transit key — the server keeps the wrapping
 * key, and the client stores the ciphertext for later unwrap.  Our mock
 * returns a fake ciphertext since pg_vault_tde v1 only uses the plaintext.
 */
func datakeyHandler(w http.ResponseWriter, r *http.Request) {
	/* Verify request method */
	if r.Method != http.MethodPost {
		http.Error(w, `{"errors":["method not allowed"]}`, http.StatusMethodNotAllowed)
		return
	}

	/* Verify authentication token */
	if !requireToken(w, r) {
		return
	}

	/* Verify path matches expected mount/key */
	expectedPath := fmt.Sprintf("/v1/%s/datakey/plaintext/%s", mount, keyName)
	if !strings.HasPrefix(r.URL.Path, expectedPath) {
		log.Printf("[WARN] Unexpected path: %s (expected %s)", r.URL.Path, expectedPath)
		http.Error(w, `{"errors":["unknown path"]}`, http.StatusNotFound)
		return
	}

	/* Generate random DEK */
	dek, err := generateDEK()
	if err != nil {
		log.Printf("[ERROR] DEK generation failed: %v", err)
		http.Error(w, `{"errors":["internal error"]}`, http.StatusInternalServerError)
		return
	}

	plainB64 := base64.StdEncoding.EncodeToString(dek)

	/* Fake ciphertext: in production this is the DEK wrapped by Transit key */
	fakeCipher := fmt.Sprintf("vault:v1:%s",
		base64.StdEncoding.EncodeToString(append([]byte("WRAPPED:"), dek...)))

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"request_id":     "mock-request-id",
		"lease_id":       "",
		"renewable":      false,
		"lease_duration": 0,
		"data": map[string]interface{}{
			"plaintext":   plainB64,
			"ciphertext":  fakeCipher,
			"key_version": 1,
		},
		"wrap_info": nil,
		"warnings":  nil,
		"auth":      nil,
	}
	json.NewEncoder(w).Encode(resp)
	log.Printf("[INFO] Issued DEK (plaintext=%s..., %d bytes)", plainB64[:8], len(dek))
}

/*
 * requireToken validates X-Vault-Token against the configured token OR the
 * approle-issued token.  Returns false and writes a 403 if invalid.
 */
func requireToken(w http.ResponseWriter, r *http.Request) bool {
	got := r.Header.Get("X-Vault-Token")
	if got == token || got == approleToken {
		return true
	}
	log.Printf("[WARN] Invalid token: got %q", got)
	http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	return false
}

/*
 * decryptHandler responds to POST /v1/{mount}/decrypt/{key_name}
 *
 * pg_vault_tde calls this on startup when a wrapped DEK has been persisted
 * to $PGDATA/pg_vault_tde/wrapped_dek (KEK wrapping feature, v1.3+).
 *
 * The mock reverses the fake wrapping produced by datakeyHandler:
 *   ciphertext = "vault:v1:" + base64("WRAPPED:" + rawDEK)
 * We strip the prefix, base64-decode, remove the "WRAPPED:" sentinel, and
 * return the raw DEK as base64 plaintext.
 */
func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"errors":["method not allowed"]}`, http.StatusMethodNotAllowed)
		return
	}
	if !requireToken(w, r) {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"errors":["bad request"]}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Ciphertext == "" {
		http.Error(w, `{"errors":["missing ciphertext field"]}`, http.StatusBadRequest)
		return
	}

	/* Strip "vault:v1:" prefix */
	ct := req.Ciphertext
	if !strings.HasPrefix(ct, "vault:v1:") {
		http.Error(w, `{"errors":["invalid ciphertext format"]}`, http.StatusBadRequest)
		return
	}
	ct = strings.TrimPrefix(ct, "vault:v1:")

	decoded, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		http.Error(w, `{"errors":["base64 decode failed"]}`, http.StatusBadRequest)
		return
	}

	/* Remove "WRAPPED:" sentinel (8 bytes) */
	sentinel := []byte("WRAPPED:")
	if len(decoded) <= len(sentinel) || string(decoded[:len(sentinel)]) != string(sentinel) {
		http.Error(w, `{"errors":["invalid ciphertext structure"]}`, http.StatusBadRequest)
		return
	}
	rawDEK := decoded[len(sentinel):]

	plainB64 := base64.StdEncoding.EncodeToString(rawDEK)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"request_id":     "mock-decrypt-id",
		"lease_id":       "",
		"renewable":      false,
		"lease_duration": 0,
		"data": map[string]interface{}{
			"plaintext": plainB64,
		},
		"wrap_info": nil,
		"warnings":  nil,
		"auth":      nil,
	}
	json.NewEncoder(w).Encode(resp)
	log.Printf("[INFO] Decrypt: returned DEK plaintext=%s...", plainB64[:8])
}

/*
 * rewrapHandler responds to POST /v1/{mount}/rewrap/{key_name}
 *
 * In production Vault, rewrap re-encrypts the DEK under the latest key
 * version, which advances the key_version field without changing the DEK.
 * The mock bumps the version byte in the fake ciphertext prefix:
 *   vault:v1:... → vault:v2:...
 *
 * Called by pg_vault_tde_vault_rewrap_dek() to rotate the KEK wrapping.
 */
func rewrapHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"errors":["method not allowed"]}`, http.StatusMethodNotAllowed)
		return
	}
	if !requireToken(w, r) {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"errors":["bad request"]}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Ciphertext == "" {
		http.Error(w, `{"errors":["missing ciphertext field"]}`, http.StatusBadRequest)
		return
	}

	/*
	 * Replace the version tag in the fake ciphertext.
	 * vault:v1:... → vault:v2:... (simulate key version increment)
	 */
	newCiphertext := strings.Replace(req.Ciphertext, "vault:v1:", "vault:v2:", 1)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"request_id":     "mock-rewrap-id",
		"lease_id":       "",
		"renewable":      false,
		"lease_duration": 0,
		"data": map[string]interface{}{
			"ciphertext":  newCiphertext,
			"key_version": 2,
		},
		"wrap_info": nil,
		"warnings":  nil,
		"auth":      nil,
	}
	json.NewEncoder(w).Encode(resp)
	log.Printf("[INFO] Rewrap: new ciphertext=%s...", newCiphertext[:16])
}

/*
 * approleLoginHandler responds to POST /v1/auth/approle/login
 *
 * Accepts role_id + secret_id credentials and returns a client token.
 * Used when pg_vault_tde.auth_method = "approle".
 */
func approleLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"errors":["method not allowed"]}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"errors":["bad request"]}`, http.StatusBadRequest)
		return
	}

	var req struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"errors":["bad request body"]}`, http.StatusBadRequest)
		return
	}

	if req.RoleID != roleID || req.SecretID != secretID {
		log.Printf("[WARN] AppRole login failed: role_id=%q secret_id=%q", req.RoleID, req.SecretID)
		http.Error(w, `{"errors":["invalid credentials"]}`, http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"request_id":     "mock-approle-login-id",
		"lease_id":       "",
		"renewable":      true,
		"lease_duration": 0,
		"data":           nil,
		"wrap_info":      nil,
		"warnings":       nil,
		"auth": map[string]interface{}{
			"client_token":   approleToken,
			"accessor":       "mock-accessor",
			"policies":       []string{"default", "tde-policy"},
			"token_policies": []string{"default", "tde-policy"},
			"metadata": map[string]string{
				"role_name": "tde-role",
			},
			"lease_duration": 3600,
			"renewable":      true,
			"entity_id":      "mock-entity-id",
			"token_type":     "service",
			"orphan":         true,
		},
	}
	json.NewEncoder(w).Encode(resp)
	log.Printf("[INFO] AppRole login: issued token %s...", approleToken[:8])
}

/*
 * tokenRenewHandler responds to POST /v1/auth/token/renew-self
 *
 * Renews the caller's token TTL.  Called by the background worker
 * (pg_vault_tde.bgw_enabled = on) on the token_renewal_interval.
 * The mock always succeeds for any known token.
 */
func tokenRenewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"errors":["method not allowed"]}`, http.StatusMethodNotAllowed)
		return
	}
	if !requireToken(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"request_id":     "mock-renew-id",
		"lease_id":       "",
		"renewable":      true,
		"lease_duration": 0,
		"data":           nil,
		"wrap_info":      nil,
		"warnings":       nil,
		"auth": map[string]interface{}{
			"client_token":   r.Header.Get("X-Vault-Token"),
			"accessor":       "mock-accessor",
			"policies":       []string{"default", "tde-policy"},
			"token_policies": []string{"default", "tde-policy"},
			"metadata":       map[string]string{},
			"lease_duration": 3600,
			"renewable":      true,
			"entity_id":      "mock-entity-id",
			"token_type":     "service",
			"orphan":         false,
		},
	}
	json.NewEncoder(w).Encode(resp)
	log.Printf("[INFO] Token renewed for token=%s...", r.Header.Get("X-Vault-Token")[:8])
}

/*
 * catchAll logs and rejects unexpected requests.
 */
func catchAll(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WARN] Unhandled %s %s", r.Method, r.URL.Path)
	http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
}

func main() {
	mux := http.NewServeMux()

	/* Health endpoint */
	mux.HandleFunc("/v1/sys/health", healthHandler)

	/*
	 * Auth endpoints — registered before the catch-all transit prefix
	 * so that /v1/auth/... does not accidentally match transitPrefix.
	 */
	mux.HandleFunc("/v1/auth/approle/login", approleLoginHandler)
	mux.HandleFunc("/v1/auth/token/renew-self", tokenRenewHandler)

	/*
	 * Transit endpoints — all keyed under /{mount}/.
	 * We dispatch by matching the sub-path segment after the mount:
	 *   /v1/{mount}/datakey/plaintext/{key}  → datakeyHandler
	 *   /v1/{mount}/decrypt/{key}            → decryptHandler
	 *   /v1/{mount}/rewrap/{key}             → rewrapHandler
	 */
	transitPrefix := fmt.Sprintf("/v1/%s/", mount)
	mux.HandleFunc(transitPrefix, func(w http.ResponseWriter, r *http.Request) {
		sub := strings.TrimPrefix(r.URL.Path, transitPrefix)
		switch {
		case strings.HasPrefix(sub, "datakey/plaintext/"):
			datakeyHandler(w, r)
		case strings.HasPrefix(sub, "decrypt/"):
			decryptHandler(w, r)
		case strings.HasPrefix(sub, "rewrap/"):
			rewrapHandler(w, r)
		default:
			log.Printf("[WARN] Unhandled transit sub-path: %s", sub)
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
		}
	})

	/* Catch-all for debugging */
	mux.HandleFunc("/", catchAll)

	addr := "0.0.0.0:" + listenPort
	log.Printf("[INFO] vault-mock starting on %s (mount=%s, key=%s)", addr, mount, keyName)
	log.Printf("[INFO] Expected token: %s | AppRole token: %s", token, approleToken)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] Server failed: %v", err)
	}
}
