# Installation

pg_vault_tde supports **PostgreSQL 17 and 18** (19 is planned). It ships as
pre-built DEB/RPM packages, or can be built from source.

## Prerequisites

pg_vault_tde is a `shared_preload_libraries` extension: it must be loaded at
server start, and it links against OpenSSL 3.x and libcurl.

| Requirement | Notes |
|---|---|
| PostgreSQL | 17.x or 18.x, with server development headers |
| OpenSSL | 3.x (AES-256-GCM / AES-256-SIV via the EVP / provider API) |
| libcurl | Required for the HashiCorp Vault / OpenBao provider |
| CPU | Any x86-64 or AArch64 — AES hardware acceleration (AES-NI/VAES/ARM CE/SVE2) is automatic via OpenSSL on every build; see [Performance and Tuning](Performance-and-Tuning) |

OpenSSL 3.x is required (the KMS layer uses `EVP_EncryptInit_ex2`/AES-256-WRAP
key wrapping, added in OpenSSL 3.0), so OSes that only ship OpenSSL 1.1.1 —
Debian 11 (Bullseye) and EL8 (Rocky/AlmaLinux 8) — are not supported.


## Option A — Install From Package (Recommended)

Pre-built DEB and RPM packages are produced for both PostgreSQL 17 and 18.
There is a single package per (format, PG major) — hardware-accelerated AES
is automatic via OpenSSL on it, no CPU-specific variant is needed (see
[Performance and Tuning](Performance-and-Tuning)). See
[Compatibility and Versioning](Compatibility-and-Versioning) for the full
package/version matrix.

### Debian / Ubuntu

```bash
dpkg -i postgresql-18-pg-vault-tde_<version>_amd64.deb
dpkg -l | grep pg-vault-tde   # verify
```

### RHEL / Rocky / AlmaLinux

```bash
dnf install postgresql18-pg_vault_tde-<version>.rpm
rpm -qi postgresql18-pg_vault_tde   # verify
```

> **Wallet base directory.** If you plan to use the
> [local wallet KMS provider](KMS-Local-Wallet), the package installer
> automatically creates `/var/lib/pg_vault_tde/`, owned by the `postgres` OS
> user with mode `0700`. Source builds (Option B) must create this directory
> manually — see the note at the end of this page.

## Option B — Build From Source

```bash
git clone https://github.com/miriade/pg_vault_tde.git
cd pg_vault_tde
```

**Debian / Ubuntu, PostgreSQL 18:**
```bash
apt-get install -y postgresql-server-dev-18 libssl-dev libcurl4-openssl-dev pkg-config
make && sudo make install
```

**Debian / Ubuntu, PostgreSQL 17:**
```bash
apt-get install -y postgresql-server-dev-17 libssl-dev libcurl4-openssl-dev pkg-config
make PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config && sudo make install
```

**RHEL / Rocky, PostgreSQL 18:**
```bash
dnf install -y postgresql18-devel openssl-devel libcurl-devel
make PG_CONFIG=/usr/pgsql-18/bin/pg_config && make install
```

**RHEL / Rocky, PostgreSQL 17:**
```bash
dnf install -y postgresql17-devel openssl-devel libcurl-devel
make PG_CONFIG=/usr/pgsql-17/bin/pg_config && make install
```

Hardware-accelerated crypto (AES-NI, VAES, ARM CE, SVE2) is automatic via
OpenSSL on this same build — see
[Performance and Tuning](Performance-and-Tuning#hardware-acceleration).

> **Wallet base directory (source builds only).** Package installers create
> `/var/lib/pg_vault_tde/` automatically; a source build does not. If you
> intend to use the local wallet provider, create it once as root before
> calling `pg_vault_tde_wallet_init()`:
> ```bash
> mkdir -p /var/lib/pg_vault_tde
> chown postgres:postgres /var/lib/pg_vault_tde
> chmod 0700 /var/lib/pg_vault_tde
> ```
> This directory must **not** live inside `PGDATA` — see
> [Security Considerations](Security-Considerations).

## Option C — Install via PGXN

pg_vault_tde is distributed on the
[PostgreSQL Extension Network](https://pgxn.org/) (PGXN). This is
essentially a source build (Option B) driven for you by the PGXN client, so
the same OS packages (`postgresql-server-dev-<ver>`, `libssl-dev`,
`libcurl4-openssl-dev`, `pkg-config` / their RHEL equivalents) must already
be installed.

```bash
# Install the client once, if you don't already have it
pip install pgxnclient    # or: apt-get install pgxnclient / dnf install pgxnclient

pgxn install pg_vault_tde
pgxn load    pg_vault_tde -d yourdatabase   # runs CREATE EXTENSION
```

`pgxn install` downloads the latest release from PGXN, then runs
`make USE_PGXS=1 && make USE_PGXS=1 install` against whichever `pg_config`
is first on `PATH` — pass `--pg_config /path/to/pg_config` explicitly if you
need to target a specific PostgreSQL 17/18 install. `pgxn load` only runs
`CREATE EXTENSION`; you still need to add `pg_vault_tde` to
`shared_preload_libraries` and restart PostgreSQL yourself (below) before
`CREATE EXTENSION` will succeed — `pgxn load` does not edit
`postgresql.conf`.

## Load and Enable the Extension

1. Add to `postgresql.conf`:

   ```
   shared_preload_libraries = 'pg_vault_tde'
   ```

2. **Restart** PostgreSQL — this GUC is `PGC_POSTMASTER` and cannot be
   reloaded with `pg_reload_conf()`.

3. Create the extension in each database that needs it:

   ```sql
   CREATE EXTENSION pg_vault_tde;
   ```

4. Verify:

   ```sql
   SELECT * FROM pg_vault_tde_health_check();
   ```

At this point the extension is loaded but has **no key backend configured
yet** — go to [Key Management Overview](Key-Management-Overview) to choose
and configure one before creating any encrypted table.

## See Also
- [Getting Started](Getting-Started)
- [Key Management Overview](Key-Management-Overview)
- [Compatibility and Versioning](Compatibility-and-Versioning)
