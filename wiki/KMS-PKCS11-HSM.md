# KMS: PKCS#11 / HSM

The PKCS#11 provider (`pg_vault_tde.kms_provider = 'pkcs11'`, added in v1.7)
keeps the KEK inside a hardware security module — any device exposing a
PKCS#11 module (Thales, Utimaco, YubiHSM, AWS CloudHSM, or SoftHSM2 for
testing). pg_vault_tde talks to the vendor's module directly and wraps every
per-table DEK with `C_WrapKey` (`CKM_AES_KEY_WRAP`, RFC 3394) against an
AES-256 KEK that **never leaves the token**.

## When to Use It

Regulatory or compliance requirements for hardware key custody (the KEK must
never exist outside a certified hardware boundary), or an existing
enterprise HSM deployment.

## Key Hierarchy and Threat Model

```
HSM token (user PIN via env var)
  └── KEK: AES-256, CKO_SECRET_KEY, CKA_SENSITIVE, CKA_EXTRACTABLE=FALSE
        └── C_WrapKey (CKM_AES_KEY_WRAP) → per-table DEK  (wrapped blob
              │                             in pg_vault_tde_catalog)
              └── encrypts tuple data (AES-256-GCM, in-process)
```

Only the **KEK** is confined to the HSM: tuple crypto runs in-process on the
PostgreSQL server, so the plaintext DEK necessarily transits backend memory
(stack buffers, wiped after use) — the same operational model as the Vault
Transit provider. An attacker with the disk (or a catalog dump) holds only
DEKs wrapped by a key that exists exclusively inside the device.

## Setup

1. Configure the module and token in `postgresql.conf`:

   ```ini
   pg_vault_tde.kms_provider       = 'pkcs11'
   pg_vault_tde.pkcs11_library     = '/usr/lib/softhsm/libsofthsm2.so'  # vendor module
   pg_vault_tde.pkcs11_token_label = 'pgtde'      # preferred over pkcs11_slot_id
   pg_vault_tde.enabled            = on
   ```

   `pkcs11_token_label` is preferred over `pkcs11_slot_id`: slot IDs are not
   guaranteed stable across restarts on some modules (e.g. SoftHSM2).

2. Export the token user PIN in the server's environment **before starting
   PostgreSQL** — the GUC (`pkcs11_pin_env`, default `PG_TDE_PKCS11_PIN`)
   holds only the environment variable **name**, never the PIN itself:

   ```bash
   export PG_TDE_PKCS11_PIN='1234'
   ```

3. Generate the KEK on the token, once, as superuser:

   ```sql
   SELECT pg_vault_tde_pkcs11_keygen();
   ```

   The KEK is created with `CKA_SENSITIVE` and `CKA_EXTRACTABLE=FALSE`: it
   can never be read out of the device by any caller. `pkcs11_keygen()`
   refuses to overwrite an existing key — you cannot run it twice by
   accident. Alternatively, provision the key using your HSM vendor's own
   tooling with equivalent attributes (`CKA_WRAP`, `CKA_UNWRAP`,
   `CKA_EXTRACTABLE=FALSE`).

Per-database HSM isolation works like every other provider: all `pkcs11_*`
GUCs are `suset`, so different databases can point at different tokens or
key labels via `ALTER DATABASE ... SET`.

## Testing Without a Physical HSM (SoftHSM2)

```bash
softhsm2-util --init-token --free --label pgtde --pin 1234 --so-pin 12345
```

(package `softhsm2`; set `SOFTHSM2_CONF` to point at a custom token
directory.) `tap/16_pkcs11.t` in the source repository is a complete,
self-contained example covering keygen, round-trip, restart, health check,
KEK rotation, and cross-backend rotation propagation.

`pkcs11-tool` (package `opensc`) is useful for inspecting a token directly:

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --list-objects
```

## KEK Rotation

`SELECT pg_vault_tde_rotate_kek();` works with this provider too, with one
important operational difference from Vault/local: **every KEK generation is
kept on the token forever**, as an immutable object labeled
`<pkcs11_key_label>.v<N>` — rotation never renames or destroys a key. "The
current KEK" is simply whichever `<N>` is highest; every wrapped DEK in the
catalog carries its own version tag, so unwrap always uses the exact KEK
generation that produced it, regardless of what is "current" at the time.
Practical implications:

- Old data always decrypts correctly, even years after multiple rotations —
  there is no window where a rotation can strand old ciphertext.
- A backend that is already connected when a rotation completes elsewhere
  **picks it up automatically** on its next encrypt/decrypt call — no
  reconnect required.
- A crash or a rolled-back rotation simply leaves an unused
  `<label>.v<N+1>` key on the token — harmless, and reused or superseded by
  the next rotation attempt.

## Process Model Notes (Why PKCS#11 "Just Works" Across Backends)

Every PostgreSQL backend is a forked child of the postmaster, and the
PKCS#11 specification makes session state unusable across `fork()`. You
don't need to do anything about this operationally, but it explains behavior
you may observe:

- The HSM session is **not** opened at server startup — each backend opens
  its own session lazily on first use (login happens on the first encrypt/
  decrypt/rotate call in that backend, not at connection time).
- If the HSM session or device is lost mid-operation, pg_vault_tde retries
  once through a freshly opened session before raising an error.

## Limitations

- The standalone backup tools (`pg_dump_tde` / `pg_restore_tde`) do **not**
  support `kms_provider = 'pkcs11'` yet; they exit with a clear error. Use
  `pg_basebackup` / `pg_basebackup_tde` instead — see
  [Backup and Restore](Backup-and-Restore).
- `pg_vault_tde_health_check()` may exceed its usual latency budget on the
  **first** touch of a *network* HSM in a given backend (the lazy attach
  performs the full login sequence).
- PKCS#11 labels are not guaranteed unique by the standard: keep exactly one
  KEK under `pkcs11_key_label` on a given token — the provider warns and
  picks the first match if there is more than one.

## See Also
- [Key Management Overview](Key-Management-Overview)
- [Key Rotation](Key-Rotation)
- [Backup and Restore](Backup-and-Restore)
- [GUC Reference](GUC-Reference)
