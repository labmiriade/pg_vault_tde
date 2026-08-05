/*
 * pg_vault_tde_guc.h - Audit interface extern declaration
 *
 * Copyright (c) 2026 Miriade S.r.l.  
 * Licensed under the PostgreSQL License.
 *
 */
#ifndef PG_VAULT_TDE_AUDIT_H
#define PG_VAULT_TDE_AUDIT_H

typedef enum TdeAuditEvent {
    KMS_DEK_ACCESS,         /* DEK read from cache/KMS */
    KMS_DEK_CREATE,         /* new DEK generated */
    KMS_DEK_UPDATE,         /* DEK metadata updated */
    KMS_DEK_ROTATE,         /* per-relation DEK rotated */
    KMS_DEK_DELETE,         /* DEK revoked/removed from catalog — PCI 10.2.1.7 */
    KMS_KEK_ROTATE,         /* KEK rotated */
    KMS_AUTH_SUCCESS,       /* KMS/Vault authentication succeeded — PCI 10.2.1.5 */
    KMS_AUTH_FAILURE,       /* KMS/Vault authentication failed — PCI 10.2.1.5 */
    WALLET_OPEN,
    WALLET_CLOSE,
    RELATION_ENCRYPT,       /* relation converted to encrypted_heap — PCI 10.2.1.7 */
    RELATION_DECRYPT,       /* encryption removed from relation — PCI 10.2.1.7 */
    ACCESS_DENIED,          /* decryption auth failure (wrong key / no permission) — PCI 10.2.1.4 */
    AUDIT_LOG_START,        /* audit subsystem initialised — PCI 10.2.1.6 */
    AUDIT_LOG_STOP,         /* audit subsystem shut down — PCI 10.2.1.6 */
    INTEGRITY_VIOLATION,    /* GCM tag / checksum failure */
} TdeAuditEvent;

typedef void(*tde_audit_hook)(TdeAuditEvent event, 
                              const char*   reloid, 
                              bool          success);

extern tde_audit_hook audit_hook_ptr;

static inline void
tde_audit(TdeAuditEvent event, const char *reloid, bool success)
{
    if (audit_hook_ptr)
        (*audit_hook_ptr)(event, reloid, success);
}

#endif