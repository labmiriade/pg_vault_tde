/*
 * pg_vault_tde_guc.h - GUC parameter extern declarations
 *
 * Copyright (c) 2026 Miriade Srl  
 * Licensed under the PostgreSQL License.
 *
 * All GUC variables are defined as static in pg_vault_tde.c and exposed
 * here so that kms.c, tam.c, and other translation units can read them
 * without re-registering them.
 */
#ifndef PG_VAULT_TDE_GUC_H
#define PG_VAULT_TDE_GUC_H

#include "postgres.h"

/* Vault endpoint URL (e.g. "https://vault.example.com:8200") */
extern char *pg_vault_tde_vault_url;

/* Vault namespace (enterprise only; empty for community edition) */
extern char *pg_vault_tde_vault_namespace;

/* Vault token — not shown in pg_settings (GUC_SUPERONLY | GUC_NOT_IN_SAMPLE) */
extern char *pg_vault_tde_vault_token;

/* Transit engine mount path (default: "transit") */
extern char *pg_vault_tde_vault_transit_mount;

/* Transit key name for DEK wrapping (default: "pg-tde-dek") */
extern char *pg_vault_tde_vault_key_name;

/* Path to CA certificate bundle for Vault TLS verification */
extern char *pg_vault_tde_vault_ca_cert;

/* Vault HTTP request timeout in milliseconds (0 = no timeout) */
extern int         pg_vault_tde_vault_timeout_ms;

/*
 * Master enable/disable switch.
 * When false, tde_encrypt_heap_tuple and tde_decrypt_heap_tuple become
 * identity functions (copy verbatim) to allow overhead benchmarking.
 */
extern bool        pg_vault_tde_enabled;

/*
 * DEK cache TTL in seconds (v1.1).
 * When > 0, the per-backend local DEK copy expires after this many seconds,
 * forcing a reload from shmem regardless of generation.  0 = disabled
 * (local copy only expires on generation mismatch, i.e. key rotation).
 */
extern int         pg_vault_tde_dek_cache_ttl;

/*
 * Vault authentication method (v1.1): "token", "approle", or "kubernetes".
 * Default: "token" (use pg_vault_tde.vault_token directly).
 */
extern char       *pg_vault_tde_vault_auth_method;

/*
 * AppRole credentials (v1.1).  Used only when vault_auth_method = "approle".
 */
extern char       *pg_vault_tde_vault_role_id;
extern char       *pg_vault_tde_vault_secret_id;

/*
 * AppRole role name (v1.4): the Vault role NAME (as opposed to role_id UUID).
 * Required for AppRole secret_id rotation (secret-id/destroy endpoint).
 * When empty, secret_id rotation is skipped after login.
 * Example: "pg-tde" for a role created with `vault write auth/approle/role/pg-tde ...`
 */
extern char       *pg_vault_tde_vault_role_name;

/*
 * Kubernetes auth path and role (v1.1).
 * Used only when vault_auth_method = "kubernetes".
 */
extern char       *pg_vault_tde_vault_k8s_role;
extern char       *pg_vault_tde_vault_k8s_mount;

/*
 * OpenSSL 3.x provider name for hardware acceleration (v1.1).
 * Empty (default) = use built-in AES-NI/ARM CE auto-dispatch.
 * "qatprovider" = Intel QAT co-processor offload.
 * "fips" = FIPS 140-2/3 validated provider.
 */
extern char       *pg_vault_tde_crypto_provider;

/*
 * Background worker for token renewal (v1.3).
 * bgw_enabled: whether to start the token renewal BGW (default: false).
 * token_renewal_interval: seconds between renewal attempts (default: 3600).
 */
extern bool        pg_vault_tde_bgw_enabled;
extern int         pg_vault_tde_token_renewal_interval;

/* -----------------------------------------------------------------------
 * v1.5 GUCs
 * -----------------------------------------------------------------------*/

/*
 * KMS provider selector (PGC_POSTMASTER).
 * Valid values: "vault" (default), "local".
 * Future: "pkcs11" (v1.7), "kmip" (v1.8).
 * Controls which TdeKmsProvider vtable is loaded into
 * tde_active_kms_provider at startup.
 */
extern char       *pg_vault_tde_kms_provider;

/*
 * Local wallet path (PGC_SUSET).
 * Absolute path to the PKCS#12 wallet file.
 * Default: $PGDATA/base/<DB_OID>/pg_vault_tde/wallet.p12 (resolved at runtime).
 * Used only when kms_provider = 'local'.
 */
extern char       *pg_vault_tde_wallet_path;

/*
 * show_hook for pg_vault_tde.wallet_path.
 * Returns the effective wallet path (computed default when GUC is empty).
 * Registered in DefineCustomStringVariable so SHOW works immediately on connect.
 */
extern const char *wallet_path_show_hook(void);

/*
 * Environment variable name that holds the wallet passphrase
 * (PGC_POSTMASTER).  NEVER the passphrase itself — only the NAME of the
 * environment variable.  Example: "PG_TDE_WALLET_PASS".
 * Used only when kms_provider = 'local'.
 */
extern char       *pg_vault_tde_wallet_passphrase_env;

/*
 * Auto-open wallet on startup if the passphrase env var is set
 * (PGC_POSTMASTER, default: true).
 * When false, the wallet is opened on the first DEK request.
 */
extern bool        pg_vault_tde_wallet_auto_open;

/*
 * Maximum number of independently-keyed encrypted_heap relations that may
 * be cached in shmem simultaneously (PGC_POSTMASTER, range 64–65536,
 * default 1024).  Determines the size of TdeRelDekCache at startup.
 */
extern int         pg_vault_tde_max_encrypted_relations;

/*
 * TOAST-level encryption switch (PGC_SIGHUP, default: true).
 * When true, TOAST tables for encrypted_heap relations use encrypted_heap
 * AM and their chunk_data columns are AES-256-GCM encrypted.
 * Set to false only for debugging or backward compatibility testing.
 */
extern bool        pg_vault_tde_toast_encryption;

/* -----------------------------------------------------------------------
 * v1.6 GUCs — Flexible wallet passphrase ingestion
 * -----------------------------------------------------------------------*/

/*
 * Path to a file that contains the wallet passphrase (PGC_POSTMASTER).
 * The file is read once at startup and its contents trimmed of whitespace.
 * Permission must be 0400 or 0600 (owner-only); wider permissions are
 * rejected with ereport(FATAL).
 * Incompatible with wallet_passphrase_env if both are non-empty.
 */
extern char       *pg_vault_tde_wallet_passphrase_file;

/*
 * Shell command whose stdout is the wallet passphrase (PGC_POSTMASTER).
 * Analogous to PostgreSQL's ssl_passphrase_command.  Output is trimmed
 * to at most 4095 characters and NUL-terminated.  Command runs in a
 * popen() subprocess with a reduced environment; stdout is the passphrase.
 * Example: "systemd-creds decrypt pg-tde-pass"
 * Example: "aws secretsmanager get-secret-value --query SecretString --output text --secret-id pg-tde-wallet"
 * Takes priority over wallet_passphrase_env and wallet_passphrase_file
 * when non-empty.
 */
extern char       *pg_vault_tde_wallet_passphrase_command;

/*
 * Dev-mode inline passphrase (PGC_USERSET).
 * ONLY honoured when pg_vault_tde.dev_mode = on.
 * Emits ereport(WARNING) on every use.  Never set in production configs.
 */
extern char       *pg_vault_tde_wallet_dev_mode_passphrase;

/*
 * Dev-mode enable flag (PGC_POSTMASTER, default false).
 * When false, wallet_dev_mode_passphrase is silently ignored.
 * When true, ereport(WARNING) is emitted on every dev-mode passphrase use.
 */
extern bool        pg_vault_tde_dev_mode;

extern char*       pg_vault_tde_extension_name;

#endif /* PG_VAULT_TDE_GUC_H */
