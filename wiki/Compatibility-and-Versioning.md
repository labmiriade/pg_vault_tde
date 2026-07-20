# Compatibility and Versioning

## PostgreSQL Version Support

| PG Major | Status | Notes |
|----------|--------|-------|
| 17 | ✅ Supported | Baseline API set |
| 18 | ✅ Supported | `scan_bitmap_next_tuple` signature change, handled internally — no operator action needed |
| 19 | 🔜 Planned | Infrastructure ready; will be audited at release |

## pg_vault_tde / PostgreSQL / OpenSSL Matrix

| pg_vault_tde | PostgreSQL | OpenSSL | Status |
|---|---|---|---|
| 1.6.x | 17.x, 18.x | 3.x | ✅ Superseded |
| 1.7.x | 17.x, 18.x | 3.x | 🔄 Current |
| 1.8.x | 17.x, 18.x, 19.x | 3.x | 📋 Planned |

OpenSSL 3.x is required in every case — pg_vault_tde uses the EVP/provider
API for AES-256-GCM and AES-256-SIV dispatch, including hardware-acceleration
selection (see [Performance and Tuning](Performance-and-Tuning)).

## Packages

Every release is built for both supported PostgreSQL majors as a single DEB
and a single RPM package — there is no CPU-specific package variant.
Hardware-accelerated AES dispatch (AES-NI/VAES/ARM CE/SVE2) is provided
automatically by OpenSSL on this one package; see
[Performance and Tuning](Performance-and-Tuning) for why a CPU-specific build
would not add anything.

See [Installation](Installation) for install commands.

## Upgrading pg_vault_tde Itself

- Read the limitations table for the version you're upgrading **to** in
  [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
  before upgrading — several past limitations (TOAST encryption, fixed-size
  `tde_btree` index key encryption, TOAST logical replication) were resolved
  in specific releases and may change behavior you have worked around.
- After upgrading from a pre-v1.6 release, run
  `SELECT * FROM pg_vault_tde_check_plaintext_index_keys();` to find any
  `tde_btree` index still using a plaintext operator class, and apply the
  suggested `REINDEX`.
- Extension version upgrades follow the normal PostgreSQL extension upgrade
  path (`ALTER EXTENSION pg_vault_tde UPDATE`), applying the packaged
  upgrade-script chain.

## What's Next

pg_vault_tde's roadmap tracks upcoming KMS providers and encryption
coverage. As of this writing:

| Version | Theme | Target |
|---------|-------|--------|
| v1.8 | Column-level encryption, GIN/Hash/GiST/BRIN index encryption, KMIP 1.2 client, HA improvements | Future release |

Treat anything not yet reflected in this wiki's other pages as **not yet
available** — the pages here describe the current v1.7 feature set only.
Check with your pg_vault_tde maintainers for the authoritative delivery
schedule.

## See Also
- [Installation](Installation)
- [Performance and Tuning](Performance-and-Tuning)
- [Known Limitations and Troubleshooting](Known-Limitations-and-Troubleshooting)
