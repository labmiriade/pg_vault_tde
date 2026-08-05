# Default PG major version; override at build time with:
#   rpmbuild --define 'pgmajorversion 17' -ba pg_vault_tde.spec
# or via build_rpm.sh --pg-version 17
%{!?pgmajorversion: %global pgmajorversion 18}
%global pgpackageversion %{pgmajorversion}
%global sname pg_vault_tde
%global pginstdir /usr/pgsql-%{pgmajorversion}

Name:           postgresql%{pgmajorversion}-%{sname}
Version:        1.7
Release:        1%{?dist}
Summary:        Transparent Data Encryption (TDE) extension for PostgreSQL %{pgmajorversion}
License:        BSD
URL:            https://github.com/miriade/pg_vault_tde
Source0:        %{sname}-%{version}.tar.gz

BuildRequires:  postgresql%{pgmajorversion}-devel
BuildRequires:  openssl-devel
BuildRequires:  libcurl-devel
BuildRequires:  pkgconfig
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  chrpath

Requires:       postgresql%{pgmajorversion}-server
Requires:       openssl-libs
Requires:       libcurl

%description
pg_vault_tde provides plug-and-play Transparent Data Encryption (TDE)
for PostgreSQL %{pgmajorversion} via the Table Access Method (TAM) and Index Access
Method (IAM) APIs.

All user data in encrypted_heap tables is encrypted at rest using
AES-256-GCM (AEAD). Encryption keys are managed via HashiCorp Vault
or OpenBao and cached in shared memory with generation-based rotation.

Features:
- AES-256-GCM per-tuple encryption with authenticated integrity
- Hardware-accelerated (AES-NI) via OpenSSL 3.x EVP dispatch
- Zero-config key rotation with lazy generation-epoch detection
- Compatible with MVCC, HOT chains, VACUUM, ANALYZE, COPY, pg_dump
- Compatible with page-level checksums (initdb --data-checksums)
- TOAST tables use standard heap AM (large values handled safely)
- Zero core PostgreSQL modifications required

%prep
%setup -q -n %{sname}-%{version}

%build
PG_CONFIG=%{pginstdir}/bin/pg_config
export PG_CONFIG
%{__make} PG_CONFIG="$PG_CONFIG" \
    CFLAGS="%{optflags} -fno-lto" \
    %{?_smp_mflags}

%install
PG_CONFIG=%{pginstdir}/bin/pg_config
export PG_CONFIG
%{__make} PG_CONFIG="$PG_CONFIG" \
    DESTDIR=%{buildroot} \
    install

# pg_config --ldflags bakes -Wl,-rpath,%{pginstdir}/lib into every PGXS
# module (all of PGDG's own packages link the same way). The .so never
# actually resolves anything through it — it links only against libssl/
# libcrypto/libcurl from the standard system libdirs — so the RUNPATH is
# dead weight that only trips rpmbuild's check-rpaths (fatal on EL10;
# %{pginstdir} isn't a "standard" libdir it recognizes). Drop it here
# instead of disabling the check wholesale.
chrpath -d %{buildroot}%{pginstdir}/lib/%{sname}.so

%files
%license LICENSE
%doc doc/pg_vault_tde.md README.md
%{pginstdir}/lib/%{sname}.so
%{pginstdir}/share/extension/%{sname}.control
%{pginstdir}/share/extension/%{sname}--*.sql
%{pginstdir}/lib/bitcode/%{sname}*

%changelog
* Mon Jun 08 2026 Miriade S.r.l. <info@miriade.it> - 1.7-1
- v1.7: tde_btree access method — encrypted (AES-256-SIV) index keys for
  bytea/text/int4/int8/numeric/uuid/date/timestamptz operator classes;
  index-only scans disabled by design
- KEK/DEK wrapping hierarchy: provider-agnostic wrap_dek/unwrap_dek/
  rewrap_dek API; wrapped_dek is now the authoritative catalog column
  for every KMS provider (Vault, wallet, PKCS#11)
- PKCS#11/HSM KMS provider: direct Cryptoki wrap/unwrap of DEKs
  (CKM_AES_KEY_WRAP), versioned KEK objects, cross-backend rotation
  propagation via shared memory; CI covered with SoftHSM2
- Logical replication of encrypted_heap TOAST columns via a custom WAL
  resource manager (pg_vault_tde.toast_custom_rmgr, off by default)
- Structured audit event logging (16 event types: DEK/KEK lifecycle,
  wallet open/close, relation encrypt/decrypt, access denied, etc.)
  to the server log for PCI-DSS/HIPAA trails
- Physical backup key handling: pg_vault_tde_seal_keys()/unseal_keys(),
  pg_basebackup_tde wrapper, and pg_restore_tde decrypt-and-pipe restore
- Per-database KMS configuration (PGC_SUSET for all KMS GUCs)
- 137 regression tests passing (52 v1.4 + 20 v1.5 + 38 v1.6 + 27 v1.7)

* Wed Mar 04 2026 Miriade S.r.l. <info@miriade.it> - 1.6-1
- v1.6: Local PKCS#12 wallet KMS provider (offline, no external service)
- Flexible passphrase sources: env, file, command, dev_mode
- wallet_unlock/lock/rotate_kek/export_bundle/import_bundle SQL functions
- Online Vault-to-wallet migration function
- Support for PostgreSQL 17 and 18
- 72 regression tests passing

* Fri Feb 27 2026 Miriade S.r.l. <info@miriade.it> - 1.0-1
- Initial RPM release for PostgreSQL 17-18
- AES-256-GCM transparent encryption via TAM
- 24 regression tests passing including page checksum compatibility
