%global pgmajorversion 18
%global pgpackageversion 18
%global sname pg_vault_tde

Name:           postgresql%{pgmajorversion}-%{sname}-armce
Version:        1.0
Release:        1%{?dist}
Summary:        pg_vault_tde ARM Crypto Extensions optimized build for aarch64 (PostgreSQL %{pgmajorversion})
License:        BSD
URL:            https://github.com/miriade/pg_vault_tde
Source0:        %{sname}-%{version}.tar.gz

# This package targets exclusively aarch64 CPUs with ARM Crypto Extensions.
# It cannot be built or installed on any other architecture.
ExclusiveArch:  aarch64

BuildRequires:  postgresql%{pgmajorversion}-devel
BuildRequires:  openssl-devel
BuildRequires:  libcurl-devel
BuildRequires:  pkgconfig
BuildRequires:  gcc
BuildRequires:  make

# The base package must be installed first: it provides the control file,
# SQL scripts, and default .so.  This package only adds the ARM CE .so.
Requires:       postgresql%{pgmajorversion}-%{sname}

%description
ARM Crypto Extensions optimized build of pg_vault_tde for aarch64 CPUs.

This package recompiles the pg_vault_tde shared library with:
  -march=armv8-a+crypto+crc -O3 -funroll-loops

These flags enable the GCC back-end to emit inline AES/SHA/PMULL
instructions from the ARMv8-A Cryptographic Extensions and allow
OpenSSL 3.x EVP to dispatch to the hardware-accelerated code path.

CPU requirement: ARM Cortex-A53 (ARMv8-A) or later with the Crypto
Extension feature set.  This covers Apple M1/M2, AWS Graviton 2/3,
Ampere Altra, NVIDIA Grace, and most modern server-class ARM SoCs.

The .so is installed alongside the base library as pg_vault_tde_armce.so.
A sample postgresql.conf snippet is provided in the extension share directory.

%prep
%setup -q -n %{sname}-%{version}

%build
PG_CONFIG=/usr/pgsql-%{pgmajorversion}/bin/pg_config
export PG_CONFIG
%{__make} PG_CONFIG="$PG_CONFIG" \
    TDE_TARGET_ARCH=aarch64-ce \
    TDE_OPTIMIZE=max \
    CFLAGS="%{optflags} -fno-lto" \
    %{?_smp_mflags}

%install
# Install the ARM CE .so under a distinct name so it can coexist with
# the generic build installed by the base package.
install -D -m 755 pg_vault_tde.so \
    %{buildroot}/usr/pgsql-%{pgmajorversion}/lib/pg_vault_tde_armce.so

# Install the sample GUC hint file
install -D -m 644 /dev/stdin \
    %{buildroot}/usr/pgsql-%{pgmajorversion}/share/extension/pg_vault_tde_armce.conf.sample <<'EOF'
# pg_vault_tde ARM Crypto Extensions optimized build
# Copy these overrides to postgresql.conf to use the ARM CE variant
# (requires aarch64 CPU with ARMv8-A Cryptographic Extensions)
EOF

%files
/usr/pgsql-%{pgmajorversion}/lib/pg_vault_tde_armce.so
/usr/pgsql-%{pgmajorversion}/share/extension/pg_vault_tde_armce.conf.sample

%changelog
* Fri Feb 27 2026 Miriade Srl <info@miriade.it> - 1.0-1
- Initial ARM Crypto Extensions optimized RPM for PostgreSQL %{pgmajorversion} (aarch64 only)
- Built with TDE_TARGET_ARCH=aarch64-ce TDE_OPTIMIZE=max
- Requires base postgresql18-pg_vault_tde package
