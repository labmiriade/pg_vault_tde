%global pgmajorversion 18
%global pgpackageversion 18
%global sname pg_vault_tde

Name:           postgresql%{pgmajorversion}-%{sname}
Version:        1.0
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
PG_CONFIG=/usr/pgsql-%{pgmajorversion}/bin/pg_config
export PG_CONFIG
%{__make} PG_CONFIG="$PG_CONFIG" \
    CFLAGS="%{optflags} -fno-lto" \
    %{?_smp_mflags}

%install
PG_CONFIG=/usr/pgsql-%{pgmajorversion}/bin/pg_config
export PG_CONFIG
%{__make} PG_CONFIG="$PG_CONFIG" \
    DESTDIR=%{buildroot} \
    install

%files
%license LICENSE
%doc doc/pg_vault_tde.md README.md
%{_libdir}/pgsql/%{sname}.so
%{_datadir}/pgsql/extension/%{sname}.control
%{_datadir}/pgsql/extension/%{sname}--*.sql

%changelog
* Fri Feb 27 2026 Miriade Srl <info@miriade.it> - 1.0-1
- Initial RPM release for PostgreSQL 17-18
- AES-256-GCM transparent encryption via TAM
- 24 regression tests passing including page checksum compatibility
