%global pgmajorversion 18
%global pgpackageversion 18
%global sname pg_vault_tde

Name:           postgresql%{pgmajorversion}-%{sname}-aesni
Version:        1.0
Release:        1%{?dist}
Summary:        pg_vault_tde AES-NI optimized build for x86_64 (PostgreSQL %{pgmajorversion})
License:        BSD
URL:            https://github.com/miriade/pg_vault_tde
Source0:        %{sname}-%{version}.tar.gz

# This package targets exclusively x86_64 CPUs with AES-NI support.
# It cannot be built or installed on any other architecture.
ExclusiveArch:  x86_64

BuildRequires:  postgresql%{pgmajorversion}-devel
BuildRequires:  openssl-devel
BuildRequires:  libcurl-devel
BuildRequires:  pkgconfig
BuildRequires:  gcc
BuildRequires:  make

# The base package must be installed first: it provides the control file,
# SQL scripts, and default .so.  This package only adds the AES-NI .so.
Requires:       postgresql%{pgmajorversion}-%{sname}

%description
AES-NI optimized build of pg_vault_tde for x86_64 CPUs.

This package recompiles the pg_vault_tde shared library with:
  -maes -mpclmul -msse4.1 -msse4.2 -O3 -funroll-loops

These flags enable the GCC back-end to emit inline AES-NI instructions
and allow OpenSSL 3.x EVP to dispatch to the hardware-accelerated code
path without a function-call overhead layer.

CPU requirement: Intel Core 2010+ (Westmere), AMD Bulldozer (2011+) or later.
Any CPU listed in "flags" /proc/cpuinfo with the "aes" feature bit qualifies.

The .so is installed alongside the base library as pg_vault_tde_aesni.so.
A sample postgresql.conf snippet is provided in the extension share directory.

%prep
%setup -q -n %{sname}-%{version}

%build
PG_CONFIG=/usr/pgsql-%{pgmajorversion}/bin/pg_config
export PG_CONFIG
%{__make} PG_CONFIG="$PG_CONFIG" \
    TDE_TARGET_ARCH=x86_64-aesni \
    TDE_OPTIMIZE=max \
    CFLAGS="%{optflags} -fno-lto" \
    %{?_smp_mflags}

%install
# Install the AES-NI .so under a distinct name so it can coexist with
# the generic build installed by the base package.
install -D -m 755 pg_vault_tde.so \
    %{buildroot}/usr/pgsql-%{pgmajorversion}/lib/pg_vault_tde_aesni.so

# Install the sample GUC hint file
install -D -m 644 /dev/stdin \
    %{buildroot}/usr/pgsql-%{pgmajorversion}/share/extension/pg_vault_tde_aesni.conf.sample <<'EOF'
# pg_vault_tde AES-NI optimized build
# Copy these overrides to postgresql.conf to use the AES-NI variant
# (requires x86_64 CPU with AES-NI support)
EOF

%files
/usr/pgsql-%{pgmajorversion}/lib/pg_vault_tde_aesni.so
/usr/pgsql-%{pgmajorversion}/share/extension/pg_vault_tde_aesni.conf.sample

%changelog
* Fri Feb 27 2026 Miriade Srl <info@miriade.it> - 1.0-1
- Initial AES-NI optimized RPM for PostgreSQL %{pgmajorversion} (x86_64 only)
- Built with TDE_TARGET_ARCH=x86_64-aesni TDE_OPTIMIZE=max
- Requires base postgresql18-pg_vault_tde package
