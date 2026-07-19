/*
 * pg_vault_tde_cryptoki.h — UNIX bindings for the vendored OASIS PKCS#11 headers
 *
 * Copyright (c) 2026 Miriade S.r.l.
 * Licensed under the PostgreSQL License (BSD).
 *
 * This is the ONLY PKCS#11 header pg_vault_tde code may include.  It defines
 * the five platform-specific macros the OASIS specification requires the
 * includer to provide, then pulls in the unmodified official headers
 * (pkcs11.h → pkcs11t.h/pkcs11f.h, OASIS PKCS#11 v3.2 OS, vendored
 * verbatim under src/include/pkcs11/ per the OASIS IPR Policy — third-party
 * files keep their canonical names because pkcs11.h includes the other two
 * by those exact names).
 *
 * On UNIX no structure packing pragma is needed: the Cryptoki v2.40 spec
 * leaves packing to the platform default outside Win32 (see the comment
 * block at the top of pkcs11.h).
 */
#ifndef PG_VAULT_TDE_CRYPTOKI_H
#define PG_VAULT_TDE_CRYPTOKI_H

#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#include "src/include/pkcs11/pkcs11.h"

#endif							/* PG_VAULT_TDE_CRYPTOKI_H */
