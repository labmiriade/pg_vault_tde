# Auditing and Monitoring

pg_vault_tde emits an audit record for every security-relevant KMS and DDL
event, and exposes several SQL functions for health checks and integrity
verification. Auditing is **always active** — there is no GUC to disable it,
so it cannot be turned off by mistake or by an attacker with SQL access.

## Audit Log Format

Every audited event is written to the PostgreSQL server log at `LOG`
severity, with the originating SQL statement and context stack suppressed
(`errhidestmt`/`errhidecontext`), so only the audit fields appear:

```
AUDIT: event=<name>, oid=<relation_oid_or_dash>, user=<role_name>, success=<t|f>, pid=<pid>
```

- `oid` — the relation OID affected by the event, or `-` for cluster-level
  events.
- `success` — `t` on success, `f` on failure (e.g. authentication error, GCM
  tag mismatch).

## Logged Events

| `event=` value | Trigger | PCI DSS ref |
|---|---|---|
| `AUDIT_LOG_START` | Audit subsystem initialized at server start | 10.2.1.6 |
| `AUDIT_LOG_STOP` | Audit subsystem shut down | 10.2.1.6 |
| `DEK_ACCESS` | DEK read from shared-memory cache or KMS | — |
| `DEK_CREATE` | New per-relation DEK generated | — |
| `DEK_ROTATE` | Per-relation DEK rotated (`pg_vault_tde_rotate_online`) | 10.2.1.7 |
| `DEK_DELETE` | DEK revoked/removed from catalog (`DROP TABLE`) | 10.2.1.7 |
| `KEK_ROTATE` | KEK rotated (`pg_vault_tde_rotate_kek`) | 10.2.1.7 |
| `KMS_AUTH_SUCCESS` | KMS/Vault authentication succeeded | 10.2.1.5 |
| `KMS_AUTH_FAILURE` | KMS/Vault authentication failed | 10.2.1.5 |
| `WALLET_OPEN` | Local wallet opened (`pg_vault_tde_wallet_unlock`) | — |
| `WALLET_CLOSE` | Local wallet closed (`pg_vault_tde_wallet_lock`) | — |
| `RELATION_ENCRYPT` | Relation converted to `encrypted_heap` | 10.2.1.7 |
| `RELATION_DECRYPT` | `encrypted_heap` converted back to plain heap | 10.2.1.7 |
| `ACCESS_DENIED` | Decryption failed — wrong key or missing permission | 10.2.1.4 |

(`DEK_UPDATE` and `INTEGRITY_VIOLATION` are reserved in the audit enum for a
future release and are not emitted by any code path yet.)

## Routing Audit Logs to a SIEM

Because audit records are ordinary PostgreSQL `LOG` messages, they flow
through the standard `log_destination`/`logging_collector` pipeline. To
separate them out, filter on the `AUDIT:` prefix:

```ini
# postgresql.conf — route everything to a file so it can be shipped/tailed
log_destination   = 'stderr'
logging_collector = on
log_filename      = 'postgresql-%Y-%m-%d.log'
```

External sinks (syslog, Splunk, Datadog, Elastic, …) can filter on `AUDIT:`
directly from the standard log stream, or from the file above, with no
extension-level configuration needed — this is a plain-text grep/filter
problem, not an API integration.

## Health and Integrity Checks

```sql
-- Overall extension health: version, enabled, kms_provider, enc_ops_available, checked_at
SELECT * FROM pg_vault_tde_health_check();

-- GCM tag audit scan over every tuple in a table
SELECT * FROM pg_vault_tde_verify_integrity('mytable');
-- returns (total_tuples, failed_tuples)

-- Storage overhead added by encryption
SELECT * FROM pg_vault_tde_encrypted_size('mytable');

-- tde_btree indexes still built with a pre-v1.6 plaintext operator class
-- (superuser / pg_monitor only) — includes a ready-to-run REINDEX suggestion
SELECT * FROM pg_vault_tde_check_plaintext_index_keys();

-- OpenSSL provider/cipher diagnostics — confirms hardware acceleration is active
SELECT * FROM pg_vault_tde_hw_accel_info();
```

Run `pg_vault_tde_verify_integrity()` periodically (e.g. alongside routine
`VACUUM`/backup jobs) as a tamper-detection check: any bit flip in stored
ciphertext, whether from disk corruption or interference, fails GCM
authentication and shows up as a `failed_tuples` count rather than silently
returning wrong data.

## Rotation Progress Monitoring

```sql
-- All in-progress/completed key rotations across the cluster
-- (readable by the pg_monitor role, not just superuser)
SELECT * FROM pg_vault_tde_rotation_status;

-- Detail for one relation
SELECT * FROM pg_vault_tde_get_rotation_status('mytable');
```

Grant your monitoring role membership in `pg_monitor` to allow it to read
rotation status and other diagnostic views without superuser privileges.

## Recommended Monitoring Checklist

- Alert on `AUDIT: event=KMS_AUTH_FAILURE` and `event=ACCESS_DENIED` — both
  indicate either a misconfiguration or an active attack.
- Alert on `pg_vault_tde_verify_integrity()` returning any `failed_tuples >
  0` — this indicates corruption or tampering, not a transient error.
- Periodically run `pg_vault_tde_check_plaintext_index_keys()` after
  upgrading from a pre-v1.6 release to confirm no index still needs a
  `REINDEX`.
- Watch `pg_vault_tde_rotation_status` for rotations that appear stuck — an
  online DEK rotation on a very large table takes time proportional to the
  batch size chosen (see [Key Rotation](Key-Rotation)).

## See Also
- [Security Considerations](Security-Considerations)
- [Key Rotation](Key-Rotation)
- [SQL Function Reference](SQL-Function-Reference)
