# pg_vault_tde

[![build main](https://img.shields.io/github/actions/workflow/status/labmiriade/pg_vault_tde/ci.yml?branch=main&label=build%20main)](https://github.com/labmiriade/pg_vault_tde/actions/workflows/ci.yml?query=branch%3Amain)
[![build develop](https://img.shields.io/github/actions/workflow/status/labmiriade/pg_vault_tde/ci.yml?branch=develop&label=build%20develop)](https://github.com/labmiriade/pg_vault_tde/actions/workflows/ci.yml?query=branch%3Adevelop)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/labmiriade/pg_vault_tde/codeql.yml?branch=develop&label=CodeQL)](https://github.com/labmiriade/pg_vault_tde/security/code-scanning)
[![packages](https://img.shields.io/github/actions/workflow/status/labmiriade/pg_vault_tde/build-packages.yml?label=packages)](https://github.com/labmiriade/pg_vault_tde/actions/workflows/build-packages.yml)
[![PGXN](https://img.shields.io/badge/PGXN-pg__vault__tde-blue)](https://pgxn.org/dist/pg_vault_tde/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17%20%7C%2018-336791)](#compatibility)
[![License](https://img.shields.io/badge/license-PostgreSQL-blue)](LICENSE)

**Transparent Data Encryption (TDE) for PostgreSQL 17+** — Open-source (PostgreSQL License), plug-and-play, zero core modifications.

pg_vault_tde encrypts every tuple with **AES-256-GCM** at the Table Access
Method layer. Data is encrypted before it reaches the storage manager and
decrypted after it leaves. Encryption keys are managed by **HashiCorp Vault** /
**OpenBao** or a **local PKCS#12 wallet** and cached in shared memory with
automatic rotation.

**Current release: v1.7** — 137 regression tests (45 v1.4 + 20 v1.5 + 36 v1.6 + 36 v1.7), zero compiler warnings on PG 17 + PG 18.

### Commercial Support

Looking for professional support for `pg_vault_tde` in production? At [Miriade](https://miriade.it), we offer dedicated enterprise services, including:

* **24/7 Production Support & SLA Guarantees**
* **Custom Feature Development & Vault Integration**
* **Performance Tuning & Security Audits**
* **Managed Setup & Migration Assistance**

Learn more about our enterprise encryption solutions at [Mircrypt](https://www.miriade.it/en/products/mircrypt-it)

Contact our engineering team at [marketing@miriade.it](mailto:marketing@miriade.it) to discuss your requirements.

### Compatibility

PostgreSQL 17 and 18, 19 planned; OpenSSL 3.x required. Per-major API notes in
[Version Compatibility](doc/pg_vault_tde.md#postgresql-version-compatibility);
packaged (OS, PG) combinations and what CI exercises on each in the
[Support Matrix](doc/pg_vault_tde.md#support-matrix).

---

## Quick Start

> **Already running 1.7.0 or earlier?** Do not upgrade to 1.7.1 or later before
> reading [Upgrading to 1.7.1](#upgrading-to-171). Tables holding out-of-line
> TOAST values must be dumped *before* the new binary is installed.
>
> **Upgrading from 1.7.1?** Nothing has to be done before installing 1.7.2, but
> existing encrypted tables need one `VACUUM FULL` afterwards — see
> [Upgrading to 1.7.2](#upgrading-to-172). Rows stay readable either way; until
> they are rewritten, `UPDATE` on some of them can take the backend down.

### 1. Install

```bash
# Build and install into your PostgreSQL instance
git clone https://github.com/labmiriade/pg_vault_tde.git
cd pg_vault_tde

# The PostgreSQL packages below come from the PGDG repository for any major your
# distribution does not ship itself — PG 18 on Debian 13, every major on
# RHEL/Rocky. Set it up first if you have not already:
#   https://www.postgresql.org/download/
# On RHEL/Rocky also run:  dnf -qy module disable postgresql

# On Debian/Ubuntu (PG 18) — server-dev pulls in the clang/llvm PGXS needs for bitcode
apt-get install -y build-essential postgresql-server-dev-18 \
                   libssl-dev libcurl4-openssl-dev pkg-config
make && sudo make install

# On Debian/Ubuntu (PG 17)
apt-get install -y build-essential postgresql-server-dev-17 \
                   libssl-dev libcurl4-openssl-dev pkg-config
make PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config && sudo make install

# On RHEL/Rocky — EPEL and CRB first: postgresqlNN-devel needs perl(IPC::Run)
dnf install -y epel-release
dnf config-manager --set-enabled crb

# On RHEL/Rocky (PG 18) — clang/llvm-devel are NOT pulled in by postgresqlNN-devel,
# and redhat-rpm-config provides the hardening spec file pg_config injects
dnf install -y postgresql18-devel openssl-devel libcurl-devel \
               gcc make redhat-rpm-config clang llvm-devel
make PG_CONFIG=/usr/pgsql-18/bin/pg_config && make install

# On RHEL/Rocky (PG 17)
dnf install -y postgresql17-devel openssl-devel libcurl-devel \
               gcc make redhat-rpm-config clang llvm-devel
make PG_CONFIG=/usr/pgsql-17/bin/pg_config && make install
```

**Or via [PGXN](https://pgxn.org/dist/pg_vault_tde/)** (same OS build
dependencies as above are still required — `pgxn install` just runs the
build for you):

```bash
pip install pgxnclient   # or: apt-get install pgxnclient / dnf install pgxnclient
pgxn install pg_vault_tde
```

See [wiki: Installation](https://github.com/labmiriade/pg_vault_tde/wiki/Installation)
for package-based (`.deb`/`.rpm`) installs and full per-OS prerequisites.

### 2. Configure PostgreSQL

Add to `postgresql.conf`:

```
shared_preload_libraries = 'pg_vault_tde'
```

> **Check the WAL resource manager id first.** pg_vault_tde registers a custom WAL
> resource manager under id **161**, reserved for it on the PostgreSQL *Custom WAL
> Resource Managers* wiki. Extensions that follow the registry never use it, but an
> unregistered one — typically in-house or proprietary — can. On every node that
> will load pg_vault_tde or replay its WAL (primary, standbys, PITR restore hosts),
> this must return **no rows** before you add it:
>
> ```sql
> SELECT rm_id, rm_name FROM pg_get_wal_resource_managers()
> WHERE rm_id = 161 OR rm_name = 'pg_vault_tde';
> ```
>
> If it returns one, the server will refuse to start once pg_vault_tde is preloaded
> (`failed to register custom resource manager "pg_vault_tde" with ID 161`). After the
> restart the same query must return exactly `161 | pg_vault_tde`. Any role can run it.

Restart PostgreSQL and create the extension in your database:

```sql
CREATE EXTENSION pg_vault_tde;
```

### 3. Configure Key Access


#### a) HashiCorp Vault / OpenBao

`kms_provider` has no built-in default — it must be set explicitly. Set GUC
parameters in `postgresql.conf` (or `ALTER SYSTEM`) to point at your Vault /
OpenBao instance:

```ini
pg_vault_tde.kms_provider          = 'vault'
pg_vault_tde.vault_url            = 'https://vault.example.com:8200'
pg_vault_tde.vault_namespace      = ''          # leave empty for community edition
pg_vault_tde.vault_token          = 'hvs.TOKEN' # or use AppRole (1.1)
pg_vault_tde.vault_transit_mount  = 'transit'
pg_vault_tde.vault_key_name       = 'pg-tde-dek'
pg_vault_tde.vault_ca_cert        = '/etc/ssl/vault/ca.pem'
pg_vault_tde.vault_timeout_ms     = 5000
pg_vault_tde.enabled              = on          # PGC_POSTMASTER: requires a full restart to change
```

> **⚠️ Warning — do not toggle `pg_vault_tde.enabled` on a live database.**
> Rows are written using the wire format active at the time of the write
> (encrypted v4 trailer when `on`, verbatim heap tuple when `off`). Changing
> the setting and restarting does **not** retroactively convert existing
> rows: reads use whatever format is currently active for the *entire*
> table, so any `encrypted_heap` table containing rows written under the
> other setting will have those old rows misread (silent data corruption,
> not an error). Only toggle this setting on databases where `encrypted_heap`
> tables are empty or have been fully migrated (e.g. rewritten via
> `CREATE TABLE ... AS SELECT` under the target setting) beforehand.

#### b) Local Wallet (keypass locale, v1.6+)

To use a local PKCS#12 wallet (no external KMS, suitable for offline/air-gapped/standalone):

1. Set the following in `postgresql.conf`:

```ini
pg_vault_tde.kms_provider          = 'local'
# wallet_path defaults to /var/lib/pg_vault_tde/<DB_OID>/wallet.p12 — omit unless overriding:
# pg_vault_tde.wallet_path         = '/custom/path/to/wallet.p12'
pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_PASSPHRASE'   # env var name only
pg_vault_tde.wallet_auto_open      = on
pg_vault_tde.enabled               = on
```

2. Set the passphrase in the environment before starting PostgreSQL:

```bash
export TDE_WALLET_PASSPHRASE='my-strong-wallet-passphrase'
```

3. Initialize the wallet (first time only, as superuser):

```sql
-- In psql: \set reads the shell variable without exposing the value in
-- pg_stat_activity or server logs (note: backslash-set is a psql meta-command)
\set PASSPHRASE `echo $TDE_WALLET_PASSPHRASE`
SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
```

4. Check wallet status:

```sql
SELECT * FROM pg_vault_tde_wallet_status();
```

5. Unlock/lock wallet interactively (no restart needed):

```sql
SELECT pg_vault_tde_wallet_unlock('my-strong-wallet-passphrase');
SELECT pg_vault_tde_wallet_lock();
```

> **Tip:** You can also use `wallet_passphrase_file` or `wallet_passphrase_command` instead of an environment variable. See the [GUC Parameters](#guc-parameters) section for details.

#### c) PKCS#11 / HSM (v1.7)

To keep the KEK inside a hardware security module (or any device exposing a
PKCS#11 module — Thales, Utimaco, YubiHSM, AWS CloudHSM, SoftHSM2 for
testing). The extension loads the vendor's module directly and wraps every
per-table DEK with `C_WrapKey` (`CKM_AES_KEY_WRAP`, RFC 3394) against an
AES-256 KEK that never leaves the token.

1. Set the following in `postgresql.conf`:

```ini
pg_vault_tde.kms_provider       = 'pkcs11'
pg_vault_tde.pkcs11_library     = '/usr/lib/softhsm/libsofthsm2.so'  # vendor module
pg_vault_tde.pkcs11_token_label = 'pgtde'      # preferred over pkcs11_slot_id
# pg_vault_tde.pkcs11_pin_env   = 'PG_TDE_PKCS11_PIN'   # env var NAME (default)
# pg_vault_tde.pkcs11_key_label = 'pg_vault_tde_kek'    # KEK CKA_LABEL (default)
pg_vault_tde.enabled            = on
```

2. Export the token user PIN in the server environment before starting
   PostgreSQL (the GUC holds the env var *name*, never the PIN itself):

```bash
export PG_TDE_PKCS11_PIN='1234'
```

3. Generate the KEK on the token (first time only, as superuser):

```sql
SELECT pg_vault_tde_pkcs11_keygen();
```

The KEK is created with `CKA_SENSITIVE` and `CKA_EXTRACTABLE=FALSE`: it can
never be read out of the device. KEK rotation goes through the standard
`SELECT pg_vault_tde_rotate_kek();` — each generation is kept on the token
forever as an immutable object labelled `<pkcs11_key_label>.v<N>` (never
renamed or destroyed), so old data always decrypts regardless of which
version is "current". A backend that is already connected when a rotation
completes elsewhere picks it up automatically, on its next encrypt/decrypt
call — no reconnect required.

> **Testing without an HSM:** initialize a SoftHSM2 token with
> `softhsm2-util --init-token --free --label pgtde --pin 1234 --so-pin 12345`
> (package `softhsm2`; set `SOFTHSM2_CONF` for a custom token directory).
> See `tap/16_pkcs11.t` for a complete self-contained example.

> **Limitation:** the standalone backup tools (`pg_dump_tde` /
> `pg_restore_tde`) do not support `kms_provider = 'pkcs11'` yet and exit
> with a clear error.

### 4. Create an Encrypted Table

```sql
CREATE TABLE users (
    id     bigserial PRIMARY KEY,
    email  text,
    ssn    text,
    dob    date
) USING encrypted_heap;

INSERT INTO users (email, ssn, dob)
VALUES ('alice@example.com', '123-45-6789', '1990-01-15');

-- Data is transparently decrypted on read
SELECT email, ssn FROM users WHERE id = 1;
```

Before going to production, read [Running pg_vault_tde in Production](#running-pg_vault_tde-in-production):
primary keys, partitions, statistics, temporary files and backups all have ways of
putting plaintext on disk.

---

## What Gets Encrypted

| Layer | Encrypted? | Notes |
|---|---|---|
| Tuple user data | ✅ **Yes** — AES-256-GCM | All column values in `encrypted_heap` tables |
| HeapTupleHeader | ✗ No | xmin, xmax, ctid, infomask — required for MVCC |
| Index keys (B-Tree) | ⚠️ Optional — `tde_btree` | AES-256-SIV — equality only; all types encrypted (v1.7); index-only scans not supported |
| Index keys (GIN, Hash) | 🔜 v1.8 | GIN for jsonb/arrays; Hash for equality hashing |
| Index keys (GiST equality) | 🔜 v1.8 | Equality-only GiST (`inet_ops`); range/geometric GiST permanently deferred |
| Index keys (BRIN bloom) | 🔜 v1.8 | Equality-only block-range pruning via a bloom filter over ciphertext hashes; `minmax` BRIN permanently deferred (needs a spike — see doc/ROADMAP.md) |
| TOAST values | ✅ **Yes** | Heap-level round-trips functional; per-chunk storage encryption |
| Column-level granularity | 🔜 v1.8 | Per-column `ENABLE COLUMN ENCRYPTION` DDL |
| WAL / redo log | ✅ **Yes** | Data encrypted before `heap_insert()` |
| pg_statistic | 🔜 v1.8 | Statistics stored plaintext; MCVs/histograms expose value distribution |

> **Column-level**: Only tables created with `USING encrypted_heap` are
> encrypted. Regular `heap` tables are unaffected.

> **Index access method whitelist**: `CREATE INDEX`/`CREATE UNIQUE INDEX`
> with any access method other than `tde_btree` (so also `gin`, `gist`,
> `hash`, `brin`) against an `encrypted_heap` table is rejected with `ERROR`
> by default — the indexed column's plaintext value would otherwise sit
> unencrypted on disk. Set `pg_vault_tde.allow_plaintext_index = on` to allow
> it anyway (with a `WARNING`) until GIN/Hash/GiST encryption ships in v1.8.
> `PRIMARY KEY`/`UNIQUE` **table constraints** are a separate, unavoidable
> case — PostgreSQL core always backs them with a native btree index — and
> are always allowed with a `WARNING`, regardless of this setting.

---

## Architecture

```
SQL Layer
   │
   ▼
Table Access Method (TAM) — encrypted_heap            src/tam/
   │  ┌─ tuple_insert ──► tde_encrypt_heap_tuple ──► heap_insert
   │  ├─ tuple_update ──► tde_encrypt_heap_tuple ──► heap_update
   │  ├─ multi_insert ──► tde_encrypt × N ──────► heap_insert × N
   │  ├─ scan_getnextslot     ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ index_fetch_tuple    ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ scan_bitmap_next_tuple ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ scan_analyze_next_tuple ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ scan_sample_next_tuple  ──► heapam ──► decode_slot ──► tde_decrypt
   │  ├─ tuple_fetch_row_version ──► heapam ──► decode_slot ──► tde_decrypt
   │  └─ tuple_lock             ──► heapam ──► decode_slot ──► tde_decrypt
   │
   ▼
Index Access Method (IAM) — tde_btree                  src/iam/
   │  AES-256-SIV (OpenSSL 3.x EVP_CIPHER_fetch) — deterministic equality
   │  64-byte double-key via PBKDF2-SHA256 from DEK
   │
   ▼
Crypto Layer — AES-256-GCM (OpenSSL 3.x EVP)           src/crypto/
   │  [attributes, values encrypted | IV(12) | GCM-TAG(16) | VER(1) | GEN(8)]
   │  Per-backend EVP_CIPHER_CTX cached & keyed by (relid, generation):
   │  AES key schedule reused across tuples, only the IV rearmed per call
   │  IV batch generation: 256 IVs per pg_strong_random() call
   │
   ▼
KMS Layer — per-relation DEK cache                     src/kms/
   │  ┌─ TdeRelDekMap (shmem HTAB keyed by (dbid, relid), one shared LWLock)
   │  └─ pg_vault_tde_catalog (on-disk wrapped DEKs, one row per relation,
   │     one table per database — see "DEK Cache (Shared Memory)")
   │
   ▼
HashiCorp Vault / OpenBao (GUC-configurable endpoint)
```

### Wire Format (on disk, per tuple)

**v5 format** (written by `encrypted_heap` tables; v4 is still read):

```
┌─────────────────────────────────┬───────────────────────────────────────────────────────┐
│  HeapTupleHeader (t_hoff bytes) │  attributes, VALUES encrypted │ IV(12) │ Tag(16) │V│G│
│  PLAINTEXT — MVCC fields        │  (attribute layout preserved) │                       │
└─────────────────────────────────┴───────────────────────────────────────────────────────┘
                                                                  ←──── 37 bytes ────→
```

Overhead: **37 bytes per tuple** (12-byte IV + 16-byte GCM authentication tag +
1-byte version `0x05` + 8-byte DEK generation counter) — the same as v4, so a v5
tuple is exactly as long as the v4 tuple for the same row.

v5 is **structure preserving**: every attribute keeps its offset and its length,
and only the bytes of the values are ciphertext. The structural bytes — varlena
length headers, the external-datum tag, alignment padding — stay in clear,
because PostgreSQL itself walks the on-disk tuple: `heap_update()` reads the
indexed attributes straight off the page to decide HOT and index maintenance.
Under v4 that walk read attribute boundaries out of one opaque blob and crashed
the backend (PSQLE-165). The cost of v5 is that the **exact byte length of each
variable-length column** is visible on disk; fixed-length columns leak nothing,
and the row length and null bitmap were already visible under v4.

v4 tuples are read transparently, but an existing table only moves to v5 when its
rows are rewritten — `VACUUM FULL` does it.

Both versions pass `[database_oid(4) | relid(4) | generation(8)]` as AEAD Additional
Authenticated Data (AAD) — zero wire overhead; prevents cross-table ciphertext smuggling.

---

## Key Management

### KMS Provider Selection

pg_vault_tde supports multiple KMS backends via a provider abstraction layer
(introduced in v1.5). `kms_provider` has **no built-in default** — it is an
empty string until set, which the extension treats as "not yet configured."
Select the provider explicitly with:

```ini
pg_vault_tde.kms_provider = 'vault'   # HashiCorp Vault / OpenBao
# pg_vault_tde.kms_provider = 'local'  # Local wallet (PKCS#12, no external service) (v1.6)
# pg_vault_tde.kms_provider = 'pkcs11' # HSM via a PKCS#11 module (v1.7)
# pg_vault_tde.kms_provider = 'kmip'   # KMIP 1.2 (v1.8, not implemented yet)
```

### Per-Database KMS Configuration

Because all `pg_vault_tde` KMS-provider GUC parameters are declared `PGC_SUSET` (the master `enabled` switch and a couple of shared-memory-sizing parameters are `PGC_POSTMASTER` and cannot be scoped per database — see [doc/pg_vault_tde.md](doc/pg_vault_tde.md#guc-parameters)), a superuser can assign **different KMS settings to individual databases** in the same cluster without restarting PostgreSQL.
Each connection picks up the effective GUC value for its own database, so `postgres` can use a central Vault instance while `tenant_a` uses a dedicated transit key and `tenant_b` uses a local wallet:

```sql
-- cluster-level default (postgresql.conf / ALTER SYSTEM)
-- pg_vault_tde.kms_provider = 'vault'

-- database "tenant_a" uses a dedicated Vault transit key
ALTER DATABASE tenant_a SET pg_vault_tde.vault_key_name     = 'tde-dek-tenant-a';
ALTER DATABASE tenant_a SET pg_vault_tde.vault_transit_mount = 'transit-tenants';

-- database "tenant_b" uses a local wallet (no Vault dependency)
ALTER DATABASE tenant_b SET pg_vault_tde.kms_provider = 'local';
ALTER DATABASE tenant_b SET pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_B';

-- verify effective settings for a database
\connect tenant_b
SHOW pg_vault_tde.kms_provider;        -- 'local'
SELECT pg_vault_tde_health_check();
```

Settings applied with `ALTER DATABASE SET` take effect for **new connections**
to that database and do not require a server restart.  The cluster-level defaults
in `postgresql.conf` (or `ALTER SYSTEM`) act as the fallback for any database
that does not override a parameter.

#### Order and scope do not matter

Every `pg_vault_tde` KMS parameter is an ordinary, independent GUC:

- a value set at database level **always overrides** the cluster-level one, and
- the **order** in which the `ALTER DATABASE SET` statements are issued, and the
  **scope** each one is set at, are irrelevant.

You can therefore set `kms_provider` first, last, or in the middle, and mix
`ALTER SYSTEM`, `ALTER DATABASE SET` and `ALTER ROLE … IN DATABASE … SET`
freely.  The provider reads its configuration when it is first used to wrap or
unwrap a key — after PostgreSQL has finished applying every setting that
applies to the connection — not at the moment `kms_provider` is assigned.

> **Versions before this fix** initialised the provider from the
> `kms_provider` GUC assign hook, i.e. while PostgreSQL was still applying the
> database's settings one at a time.  Setting `kms_provider` before the wallet
> parameters produced a spurious
> `local wallet passphrase env var "" not set` WARNING on every connection and,
> worse, silently froze `wallet_path` to the per-database default.  If you are
> upgrading and had worked around this by re-ordering your `ALTER DATABASE SET`
> statements, that workaround is no longer needed (and was never reliable at
> mixed scopes).  Regression coverage:
> [`tap/18_guc_order_independence.t`](tap/18_guc_order_independence.t).

To inspect where each effective value comes from, use PostgreSQL's own
`pg_settings.source` (`database`, `configuration file`, `session`, …):

```sql
SELECT name, setting, source
FROM   pg_settings
WHERE  name LIKE 'pg_vault_tde.%' AND source <> 'default'
ORDER  BY name;
```

### Local Wallet Provider (v1.6 — Offline, No External Service)

A PKCS#12-based encrypted file at
`/var/lib/pg_vault_tde/<DB_OID>/wallet.p12` protects the KEK — deliberately
outside `PGDATA`, so a plain `pg_basebackup` does not copy it alongside the
wrapped DEKs it protects. No network dependency.
Suitable for single-server deployments, air-gapped environments, and development.

```ini
pg_vault_tde.kms_provider          = 'local'
# wallet_path defaults to /var/lib/pg_vault_tde/<DB_OID>/wallet.p12 — omit unless overriding:
# pg_vault_tde.wallet_path         = '/custom/path/to/wallet.p12'
pg_vault_tde.wallet_passphrase_env = 'TDE_WALLET_PASSPHRASE'   # env var, never postgresql.conf
pg_vault_tde.wallet_auto_open      = on
```

```sql
-- First-time wallet setup (\set reads the shell var without exposing it in logs):
\set PASSPHRASE `echo $TDE_WALLET_PASSPHRASE`
SELECT pg_vault_tde_wallet_init(:'PASSPHRASE');
-- Check status (5-column SRF):
SELECT * FROM pg_vault_tde_wallet_status();
-- Interactive unlock (without PG restart):
SELECT pg_vault_tde_wallet_unlock('my_passphrase');
-- Lock wallet (evict DEKs from shmem):
SELECT pg_vault_tde_wallet_lock();
-- Rotate KEK: generates a new KEK and re-wraps all per-table DEKs (works for the local, vault, and pkcs11 providers):
SELECT pg_vault_tde_rotate_kek();
```

#### Keeping the wallet on a network share

The wallet file is read far more often than its size suggests. The KEK is
**not** cached between operations — it is re-derived from the file on every
wrap and unwrap, deliberately, so that it does not sit in process memory
between them. A backend that gets its passphrase from
`wallet_passphrase_env` / `_command` (rather than from an interactive
`pg_vault_tde_wallet_unlock()`, which does cache it for that session)
therefore opens and parses the PKCS#12 once per DEK. A startup warm-up with
`preload_keys` does it once per relation.

On local storage that is unremarkable. On NFS or SMB it means one network
round-trip per unwrap, so:

- **Mount it with client-side caching enabled** — the file changes only on
  `wallet_init`, `wallet_change_passphrase` and `rotate_kek`, so it caches
  well. On NFS keep the default attribute and data caching (do not mount
  `noac` or `actimeo=0`); `fsc` with `cachefilesd` helps further on a slow
  link.
- **Know what caching does not fix.** It removes the network round-trip, not
  the PBKDF2 derivation, which is CPU and runs every time regardless. If the
  warm-up is slow on local disk too, that is what you are measuring.
- **Invalidate after a key operation.** A cached copy is a *stale KEK* after
  `wallet_change_passphrase()` or `rotate_kek()`. On a single server the
  writes invalidate the local cache. If several hosts read the same wallet
  file, drop their caches before they next touch an encrypted table — and see
  the warning under "Key Rotation" first, because a wallet shared between
  databases cannot have its KEK rotated safely at all.
- **Raise `preload_max_failures`.** A network share has transient failures a
  local disk does not, and the default of 5 is tuned for the local case.

If none of that is appealing, keep the wallet on local storage and replicate
it out of band — it is one small file that changes only when you rotate.

### Production (HashiCorp Vault / OpenBao)

The KMS layer calls Vault's Transit secrets engine:

```hcl
# Vault policy
path "transit/decrypt/pg-tde-dek" {
  capabilities = ["update"]
}
path "transit/encrypt/pg-tde-dek" {
  capabilities = ["update"]
}
```

The Vault endpoint, namespace, token, transit mount, key name, CA certificate
and timeout are all configurable via GUC parameters registered at startup
(see [Configure Key Access](#3-configure-key-access)).

### DEK Cache (Shared Memory)

Since v1.7 the cache is a shared-memory hash table (`HTAB`), not a fixed array.
A single `LWLock` from the `"pg_vault_tde_rel_dek_map"` named tranche guards the whole table
(no per-entry lock).

```
TdeRelDekMap (shmem HTAB, ShmemInitHash, capacity = pg_vault_tde.max_encrypted_relations, default 1024)
 └─ TdeRelDekMap entry, keyed by (dbid, relid):
     ├─ key            : TdeRelDekMapKey  (hash key)
     ├─ dek[32]        : AES-256 key bytes (OPENSSL_cleanse'd on rotation)
     ├─ prev_dek[32]   : previous DEK (rotation window fallback)
     ├─ generation     : uint64 per-relation counter
     └─ dek_valid / prev_dek_valid : bool
```

**The key is `(dbid, relid)`, not `relid` alone.**  A relid is unique only
*within* a database — never across databases, and never cluster-wide — while
this HTAB is one segment read by the backends of every database.  `CREATE
DATABASE` is a physical copy of the template's directory, so a cloned database
hands out pg_class OIDs identical to its template's; two unrelated databases
sharing a relid is normal, not a corner case.

```c
typedef struct TdeRelDekMapKey
{
    Oid dbid;      /* always MyDatabaseId */
    Oid relid;     /* effective relid: TOAST → parent, relrewrite → base */
} TdeRelDekMapKey;
```

`dbid` is not part of any public signature: the catalog module fills it from
`MyDatabaseId` when it builds the key.  Every path that reaches the cache runs
connected to the database that owns both the relation and its
`pg_vault_tde_catalog` row — a regular backend, the rotation BGW after
`BackgroundWorkerInitializeConnectionByOid()`, a walsender during logical
decoding — so deriving it in one place makes "caller passed the wrong dbid"
unrepresentable.

The on-disk side needs no such key.  `pg_vault_tde_catalog` is an ordinary
table created by `CREATE EXTENSION` in the extension's schema, so it already
exists once per database and its `relid` primary key is unambiguous there; the
local wallet is likewise per-database, at
`/var/lib/pg_vault_tde/<db_oid>/wallet.p12`.  Shared memory was the one place
where per-database namespaces met, and the one place that needed the dbid.

Note that `max_encrypted_relations` sizes a single cluster-wide segment: with
encrypted tables in several databases, budget for their sum.

DEK access via `pg_vault_tde_kms_get_rel_dek(relid)`:
1. **Fast path**: `hash_search(HASH_FIND)` under `LW_SHARED` — O(1) average; cache hit returns immediately.
2. **Slow path** (cache miss): catalog read (`pg_vault_tde_catalog`) -> KMS unwrap -> `hash_search(HASH_ENTER)` under `LW_EXCLUSIVE`.

### Key Rotation

**Per-table DEK rotation** (re-encrypts all tuples with a new DEK, no exclusive lock):

```sql
SELECT pg_vault_tde_rotate_online('mytable', 1000);
-- Monitor progress:
SELECT * FROM pg_vault_tde_rotation_status('mytable');
```

`rotate_online` accepts both table relations and `tde_btree` index relations:

| Target | What happens |
|--------|-------------|
| `encrypted_heap` table | Generates a new table DEK, re-encrypts every tuple in-place (`RowExclusiveLock`), then rebuilds any `tde_btree` indexes on the table so their SIV ciphertexts match the new DEK. Standard `btree` indexes on encrypted columns need no rebuild. |
| `tde_btree` index | Generates a new index DEK, then calls `reindex_index` (`AccessExclusiveLock` on the index only) to rebuild the index with keys encrypted under the new DEK. The parent table's DEK and heap data are untouched. Passing a non-`tde_btree` index raises an error before touching shmem or the catalog. |

When a table with `tde_btree` indexes is rotated, the index rebuild uses the new table DEK
implicitly because the heap rows the scan reads are re-encrypted first; the index keys
are then produced from the decrypted values and re-encrypted under the (unchanged) index DEK.
To also rotate the index DEK, call `rotate_online` on the index relation directly afterwards.

**KEK rotation** (re-wraps all per-table DEKs under a new KEK — tuple data untouched):

```sql
-- Unified function — works for the local wallet, Vault Transit, and PKCS#11 providers:
SELECT pg_vault_tde_rotate_kek();
```

> **Note on `pg_vault_tde_wallet_change_passphrase(old, new)`**: this function
> automatically rotates the KEK as part of the passphrase change. A separate
> `pg_vault_tde_rotate_kek()` call is unnecessary afterwards. The rationale: if an
> attacker already holds the old passphrase, they already have the old KEK — changing
> the passphrase without rotating the KEK provides no additional protection.

> **KEK rotation is per-database, so never share one wallet between databases
> you intend to rotate.**  Both `pg_vault_tde_rotate_kek()` and
> `pg_vault_tde_wallet_change_passphrase()` rewrap only the
> `pg_vault_tde_catalog` of the database they run in — that table is
> per-database and no backend can reach another database's copy — and then
> replace the wallet file.  With the default per-database `wallet_path`
> (`/var/lib/pg_vault_tde/<DB_OID>/wallet.p12`) the two always match.  Set
> `wallet_path` to one shared file in `postgresql.conf` and they no longer do:
> the first database to rotate strands every other database's wrapped DEKs
> under a KEK that no longer exists anywhere, and their data becomes
> permanently unreadable.  Running the rotation in each database afterwards
> does not repair it — the old KEK is gone after the first commit.
>
> Since `pg_vault_tde_wallet_init()` persists the resolved path per database
> (`ALTER DATABASE ... SET FROM CURRENT`), and a database-level setting wins
> over `postgresql.conf`, sharing a wallet is something you have to ask for
> explicitly on each database rather than something you fall into. When the
> effective wallet is not this database's own default file, both rotation
> paths emit a `WARNING` naming the database they actually covered.

> Note this is about the *KEK*, not about relids.  Per-table DEKs never
> collide across databases: each is 32 independent random bytes in its own
> database's catalog, and the GCM AAD binds `MyDatabaseId`, so one database's
> key can never silently decrypt another's rows.

---

## GUC Parameters

All parameters are in the `pg_vault_tde` namespace.

Most parameters have context `suset` (superuser-settable), meaning a superuser
can change them without restarting PostgreSQL and can scope them per-database
with `ALTER DATABASE SET`.  The only exception is `max_encrypted_relations`,
which has context `postmaster` because it controls shared memory allocation at
startup.

**Context summary:**
- `suset` — superuser can `SET` at session level or via `ALTER DATABASE SET` /
  `ALTER ROLE SET`; takes effect for new connections with no restart required.
- `postmaster` — requires a server restart; set in `postgresql.conf` or via
  `ALTER SYSTEM`.

### KMS Provider (v1.5+)

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `kms_provider` | string | `''` (unset — must be configured) | suset | Active KMS backend: `vault`, `local` (v1.6), `pkcs11` (v1.7), `kmip` (v1.8). No default is shipped; encrypted tables cannot be used until this is set. Settable per-database via `ALTER DATABASE SET`. |
| `wallet_path` | string | `/var/lib/pg_vault_tde/<DB_OID>/wallet.p12` | suset | Local wallet PKCS#12 file path (`kms_provider = 'local'`). Default computed at runtime — `SHOW` returns the effective path even when not set in `postgresql.conf`. Deliberately outside `PGDATA` so a plain `pg_basebackup` does not copy it. **Setting this in `postgresql.conf` makes every database share one KEK — see the warning under "Key Rotation" before doing so.** |
| `wallet_passphrase_env` | string | `''` | suset | Env var name holding wallet passphrase — env var NAME only, never the value |
| `wallet_passphrase_file` | string | `''` | suset | File path containing wallet passphrase (trimmed; `0400` permission enforced) **(v1.6)** |
| `wallet_passphrase_command` | string | `''` | suset | Shell command to retrieve passphrase (analogous to PG's `ssl_passphrase_command`) **(v1.6)** |
| `wallet_dev_mode_passphrase` | string | `''` | suset | Convenience passphrase for dev/CI (only honoured when `dev_mode = on`) **(v1.6)** |
| `dev_mode` | boolean | `off` | suset | Enable development mode features (wallet_dev_mode_passphrase) **(v1.6)** |
| `wallet_auto_open` | boolean | `on` | suset | Auto-open wallet on startup if passphrase env var is set |
| `preload_keys` | boolean | `off` | suset | Warm this database's DEK cache at startup: a background worker per database unwraps every DEK in `pg_vault_tde_catalog` once the server accepts connections, so the first query on a table does not pay a KMS round-trip. Needs a KMS usable without an interactive unlock (`wallet_passphrase_command` / `wallet_passphrase_env`). Stops at `max_encrypted_relations`. Scope it with `ALTER DATABASE SET`. |
| `preload_max_failures` | integer | `5` | suset | Consecutive DEK unwrap failures the startup preload tolerates in one database before giving up on it. Consecutive, so a missing passphrase stops the pass at once while a one-off does not. Relevant to the local wallet too: the KEK is re-derived from the wallet file on every unwrap rather than cached, so a wallet on NFS or SMB is reopened once per relation. `0` stops at the first failure. |
| `max_encrypted_relations` | integer | `1024` | postmaster | Maximum number of per-table DEK entries in shmem (64–65536), **cluster-wide**: entries are keyed by `(dbid, relid)`, so budget for the sum across all databases. Enforced since 1.7.2 — before that the cache silently grew past it (ShmemInitHash's size is not a cap), so count your encrypted relations across all databases before upgrading. ~112 bytes per relation, reserved at startup. Max 1048576. Requires restart. |
| `toast_encryption` | boolean | `on` | suset | Encrypt TOAST chunks with the parent relation's DEK (v1.5) |

### Vault / OpenBao (`kms_provider = 'vault'`)

All parameters are `suset` — settable per-database with `ALTER DATABASE SET`.

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `vault_url` | string | `''` | suset | Vault / OpenBao base URL |
| `vault_namespace` | string | `''` | suset | Vault namespace (enterprise; empty for community) |
| `vault_token` | string | `''` | suset | Auth token — hidden from `pg_settings` (superuser only) |
| `vault_role_id` | string | `''` | suset | AppRole role_id UUID |
| `vault_secret_id` | string | `''` | suset | AppRole secret_id — hidden from `pg_settings` (superuser only) |
| `vault_role_name` | string | `''` | suset | AppRole role name for secret_id rotation after login **(v1.4)** |
| `vault_k8s_role` | string | `''` | suset | Kubernetes JWT auth role name |
| `vault_transit_mount` | string | `transit` | suset | Transit secrets engine mount path |
| `vault_key_name` | string | `pg-tde-dek` | suset | Transit key name for DEK wrapping. Override per-database to isolate tenant keys. |
| `vault_ca_cert` | string | `''` | suset | Path to CA bundle for Vault TLS verification |
| `vault_timeout_ms` | integer | `5000` | suset | Vault HTTP timeout in ms (0 = no timeout) |

### PKCS#11 / HSM (`kms_provider = 'pkcs11'`) (v1.7)

All parameters are `suset` — settable per-database with `ALTER DATABASE SET`.

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `pkcs11_library` | string | `''` | suset | Absolute path to the vendor's PKCS#11 module (`.so`). Loaded lazily per backend. |
| `pkcs11_token_label` | string | `''` | suset | Token label for slot discovery. Preferred over `pkcs11_slot_id` (slot IDs are not stable across restarts on some modules, e.g. SoftHSM2). |
| `pkcs11_slot_id` | integer | `-1` | suset | Explicit slot ID, used only when `pkcs11_token_label` is empty (`-1` = unset) |
| `pkcs11_pin_env` | string | `PG_TDE_PKCS11_PIN` | suset | Env var name holding the token user PIN — env var NAME only, never the value |
| `pkcs11_key_label` | string | `pg_vault_tde_kek` | suset | `CKA_LABEL` of the AES-256 KEK object on the token (create with `pg_vault_tde_pkcs11_keygen()`) |

### Background Worker

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `bgw_enabled` | boolean | `off` | suset | Enable background worker for automatic token renewal |
| `token_renewal_interval` | integer | `3600` | suset | Token renewal interval in seconds (60–86400) |

### General

| Parameter | Type | Default | Context | Description |
|---|---|---|---|---|
| `enabled` | boolean | `on` | suset | Master switch — set `off` to measure TAM overhead without crypto. Settable per-database. |
| `allow_plaintext_index` | boolean | `off` | suset | When `off` (default), `CREATE INDEX`/`CREATE UNIQUE INDEX` with a non-`tde_btree` access method on an `encrypted_heap` table is rejected with `ERROR`. When `on`, allowed after a `WARNING` — the indexed column's plaintext value is then stored unencrypted on disk. Does not affect `PRIMARY KEY`/`UNIQUE` table constraints (always allowed, always warned — see "What Gets Encrypted" above). |

---

## Auditing

pg_vault_tde emits an audit record for every security-relevant KMS and DDL event.
Auditing is **always active**: the audit handler is registered unconditionally at
`_PG_init` time and there is no GUC to disable it.

Each event is written to the PostgreSQL server log at `LOG` severity via
`ereport(LOG)` with `errhidestmt` and `errhidecontext` set, so the originating
SQL statement and context stack are suppressed — only the audit fields appear.

### Log format

```
AUDIT: event=<name>, oid=<relation_oid_or_dash>, user=<role_name>, success=<t|f>, pid=<pid>
```

- `oid` — relation OID affected by the event, or `-` for cluster-level events.
- `success` — `t` on success, `f` on failure (e.g. authentication error, GCM tag mismatch).

### Logged events

The `event=` field carries the value below (note the DEK/KEK events drop the `KMS_` prefix in the log line):

| `event=` value | Trigger | PCI DSS ref |
|---|---|---|
| `AUDIT_LOG_START` | Audit subsystem initialised at server start | 10.2.1.6 |
| `AUDIT_LOG_STOP` | Audit subsystem shut down | 10.2.1.6 |
| `DEK_ACCESS` | DEK read from shared-memory cache or KMS | — |
| `DEK_CREATE` | New per-relation DEK generated | — |
| `DEK_ROTATE` | Per-relation DEK rotated (`pg_vault_tde_rotate_online`) | 10.2.1.7 |
| `DEK_DELETE` | DEK revoked / removed from catalog (`DROP TABLE`) | 10.2.1.7 |
| `KEK_ROTATE` | KEK rotated (`pg_vault_tde_rotate_kek`) | 10.2.1.7 |
| `KMS_AUTH_SUCCESS` | KMS / Vault authentication succeeded | 10.2.1.5 |
| `KMS_AUTH_FAILURE` | KMS / Vault authentication failed | 10.2.1.5 |
| `WALLET_OPEN` | Local wallet opened (`pg_vault_tde_wallet_unlock`) | — |
| `WALLET_CLOSE` | Local wallet closed (`pg_vault_tde_wallet_lock`) | — |
| `RELATION_ENCRYPT` | Relation converted to `encrypted_heap` | 10.2.1.7 |
| `RELATION_DECRYPT` | `encrypted_heap` converted back to plain heap | 10.2.1.7 |
| `ACCESS_DENIED` | Decryption failed — wrong key or missing permission | 10.2.1.4 |

`DEK_UPDATE` and `INTEGRITY_VIOLATION` are defined in the audit enum but not yet
emitted by any code path (reserved for a future release).

### Routing audit logs

Because audit records are written as PostgreSQL `LOG` messages they flow through
the standard `log_destination` / `logging_collector` pipeline.  To route them to
a dedicated file or to an external SIEM, match on the `AUDIT:` prefix:

```
# postgresql.conf — route AUDIT lines to a separate file (requires logging_collector = on)
log_destination = 'stderr'
logging_collector = on
log_filename = 'postgresql-%Y-%m-%d.log'
```

External sinks (syslog, Splunk, Datadog) can filter on `AUDIT:` from the standard
log stream without any extension-level configuration.

---

## SQL Functions

| Function | Returns | Description |
|---|---|---|
| `pg_vault_tde_health_check()` | composite | Status (6 columns: version, build_version, enabled, kms_provider, enc_ops_available, checked_at) |
| `pg_vault_tde_verify_integrity(regclass)` | record | GCM tag audit scan of all tuples — returns `(total_tuples, failed_tuples)` |
| `pg_vault_tde_encrypted_size(regclass)` | record | Encryption storage overhead — returns `(total_tuples, encryption_overhead_bytes)` |
| `pg_vault_tde_reencrypt_table(regclass, int)` | void | Batch re-encrypt with current DEK (locks table); `int` = batch size, default 1000 |
| `pg_vault_tde_rotate_online(regclass, int)` | void | BGW-based online rotation, no exclusive lock; accepts both `encrypted_heap` tables and `tde_btree` indexes **(v1.5)** |
| `pg_vault_tde_get_rotation_status(regclass)` | table | Online rotation progress for one relation (status, tuples_done/total, pct_complete, timestamps) **(v1.5)** |
| `pg_vault_tde_rotation_status` | view | All in-progress/completed rotations across the cluster; readable by `pg_monitor` **(v1.5)** |
| `pg_vault_tde_check_plaintext_index_keys()` | table | Lists `tde_btree` indexes still using a pre-v1.6 plaintext operator class, with a ready-to-run `REINDEX` suggestion; `pg_monitor`/superuser only |
| `pg_vault_tde_wallet_init(text)` | void | Create local wallet and generate KEK **(v1.5)** |
| `pg_vault_tde_wallet_change_passphrase(text, text)` | void | Re-protect wallet with new passphrase and automatically rotate the KEK (`local` provider only); no separate `rotate_kek()` needed **(v1.6)** |
| `pg_vault_tde_wallet_status()` | composite | Wallet existence, open state, algorithm, last opened, file perms (5 cols) **(v1.6)** |
| `pg_vault_tde_wallet_unlock(text)` | void | Interactive wallet unlock without PG restart **(v1.6)** |
| `pg_vault_tde_wallet_lock()` | void | Evict all DEKs from shmem, mark wallet closed **(v1.6)** |
| `pg_vault_tde_rotate_kek()` | void | Rotate the KEK and re-wrap all per-table DEKs under a new key; works for the `local`, `vault`, and `pkcs11` providers; no tuple data re-encrypted **(v1.7)** |
| `pg_vault_tde_pkcs11_keygen()` | void | One-time AES-256 KEK provisioning on the PKCS#11 token under `pkcs11_key_label`; refuses to overwrite an existing key **(v1.7)** |
| `pg_vault_tde_seal_keys(text, text, text)` | void | Write an HMAC-SHA256-signed bundle of **all** wrapped DEKs (every provider) to a file, to accompany a physical backup (`pg_basebackup`); the KEK is never included **(v1.7)** |
| `pg_vault_tde_seal_keys_bytea(text, text)` | bytea | Same signed bundle as `pg_vault_tde_seal_keys()`, returned as `bytea` instead of written server-side — used by `pg_basebackup_tde` to store the bundle on the client host **(v1.7)** |
| `pg_vault_tde_unseal_keys(text, text)` | void | Verify (HMAC) and re-import a bundle written by `pg_vault_tde_seal_keys()`; rejects a tampered file or wrong passphrase before writing anything **(v1.7)** |
| `pg_vault_tde_migrate_vault_to_wallet(text)` | void | Online Vault→local wallet migration **(v1.6)** |
| `pg_vault_tde_vault_status()` | table | Vault provider diagnostics — `(configured, auth_method, reachable)` |
| `pg_vault_tde_refresh_token()` | boolean | Manually renew the current Vault token lease |
| `pg_vault_tde_hw_accel_info()` | record | OpenSSL provider/cipher diagnostics — `(openssl_version, configured_provider, provider_loaded, gcm_cipher, siv_cipher, aes_ni_available)` |

---

## Access Methods

| Name | Type | Purpose |
|---|---|---|
| `encrypted_heap` | TABLE | Encrypts all user-data columns of every stored tuple |
| `tde_btree` | INDEX | AES-256-SIV deterministic encryption for B-Tree index keys |

```sql
-- Table with encrypted heap storage
CREATE TABLE secrets (id serial, token text) USING encrypted_heap;

-- B-Tree index with deterministic key encryption
CREATE INDEX ON secrets USING tde_btree (id);
```

---

## Upgrading to 1.7.1

1.7.1 fixes `ALTER TABLE ... SET ACCESS METHOD encrypted_heap` on a populated
table by binding the AEAD tag to the relation's *effective* OID — the same OID
the DEK and generation counter were already looked up under. For a TOAST
relation that effective OID is the parent table's, where releases up to 1.7.0
used the TOAST relation's own OID.

The AAD is never written to disk, so the reader has to reproduce the writer's
derivation exactly. **Out-of-line TOAST values written by 1.7.0 or earlier
therefore do not authenticate under 1.7.1.** The two schemes cannot coexist:
during a table rewrite the transient TOAST relation gets a fresh OID, so the
parent hop is what makes the ALTER work in the first place.

**What is and is not affected** (verified by writing under 1.7.0 and reading
back under 1.7.1 on the same data directory):

| | Under 1.7.1 |
|---|---|
| `encrypted_heap` tables with no TOAST data | ✅ readable, byte-identical |
| Inline values (below the ≈2 kB TOAST threshold) | ✅ readable, byte-identical |
| Non-TOASTed columns of a table that has TOAST data | ✅ readable |
| **Out-of-line TOAST values** | ❌ `AES-256-GCM authentication FAILED` |
| **`pg_dump` of an affected table** | ❌ exits 1 |

Nothing is lost: the ciphertext on disk is untouched, and reinstalling 1.7.0
makes it readable again. But `pg_dump` stops working *after* the upgrade, so
the export has to come first.

### Step 1 — while still on 1.7.0, find the affected tables

```sql
SELECT c.oid::regclass                             AS table_to_export,
       pg_size_pretty(pg_relation_size(c.reltoastrelid)) AS toast_size
FROM   pg_class c
JOIN   pg_am    a ON a.oid = c.relam
WHERE  a.amname = 'encrypted_heap'
  AND  c.reltoastrelid <> 0
  AND  pg_relation_size(c.reltoastrelid) > 0;
```

No rows means nothing to do — install 1.7.1 and carry on.

This only applies with `pg_vault_tde.toast_encryption = on`, which is the
default. If it was turned off, TOAST chunks were never encrypted by this
extension and the upgrade is unaffected either way.

### Step 2 — dump those tables, still on 1.7.0

```bash
pg_dump -U postgres -d yourdb -t schema.affected_table --data-only \
        -f affected_table.sql
```

### Step 3 — install 1.7.1, then truncate and restore

```bash
psql -U postgres -d yourdb -c 'TRUNCATE schema.affected_table;'
psql -U postgres -d yourdb -f affected_table.sql
```

Confirm the running binary with `SELECT pg_vault_tde_build_version();` — it
reports `1.7.1` while `pg_extension.extversion` stays at `1.7`, because 1.7.1
ships no SQL changes.

### If you upgraded first

You will get:

```
ERROR:  [CRYPTO] AES-256-GCM authentication FAILED: data integrity violation or wrong DEK
DETAIL:  The AEAD tag for relation 16541 is bound to relation 16537.
HINT:  If this data was written by pg_vault_tde 1.7.0 or earlier it is not corrupt: ...
```

This is not corruption and not a key problem. Reinstall the 1.7.0 package,
verify with `pg_vault_tde_build_version()`, then start from Step 1.

### Also check your PostgreSQL minor

Unrelated to 1.7.1, but it lands on the same people: PostgreSQL 17.11 / 18.x
and newer refuse to load this extension's logical decoding output plugin unless
it is listed in `output_plugin_libraries`. If you replicate encrypted tables,
see [Logical replication on PostgreSQL 17.11 / 18.x and
newer](#logical-replication-on-postgresql-1711--18x-and-newer) below.

---

## Upgrading to 1.7.2

1.7.2 changes the on-disk tuple layout (**v5**). Nothing has to be exported
first — every row written by 1.7.0 or 1.7.1 keeps reading, byte for byte — but
**each encrypted table needs one `VACUUM FULL` after the upgrade**, and until it
has had one, `UPDATE` on some of its rows can crash the backend.

### Why

The encrypted region used to be one opaque blob, while the tuple header — which
stays in plaintext, because MVCC and VACUUM need it — went on declaring that the
row held `natts` attributes laid out per the table's tuple descriptor. Every core
path that reads a raw on-disk tuple believes that header, and `heap_update()`
does it on **every** `UPDATE`: it reads the indexed attributes straight off the
page to decide whether the update can be HOT and which indexes to maintain.

Past the first variable-length column an attribute's offset is not cached, so
reaching it means walking the row — and the walk was reading varlena length
headers out of ciphertext. A four-byte header of random bytes yields a length of
up to 1 GB, the cursor leaves the page, and the backend dies with SIGSEGV.
Any index on such a column is enough, `tde_btree` included: what matters is that
the column is indexed, not which access method indexes it.

v5 keeps the row physically valid — every attribute at its own offset with its
own length, only the *values* replaced by ciphertext — so that walk is safe. The
AEAD is unchanged: same cipher, same tag, same AAD, and the same 37 bytes of
overhead per tuple.

### What to run

Rows written before the upgrade keep the old layout until something rewrites
them, and no layout can be made walkable after the fact. `VACUUM FULL` (or
`CLUSTER`) rewrites every row through the extension and migrates the table:

```sql
-- every encrypted table in the current database
SELECT format('VACUUM FULL %s;', c.oid::regclass)
FROM   pg_class c
JOIN   pg_am    a ON a.oid = c.relam
WHERE  a.amname = 'encrypted_heap'
  AND  c.relkind = 'r';
```

Run the statements it prints. `VACUUM FULL` takes an `ACCESS EXCLUSIVE` lock and
needs room for a second copy of the table, so treat it as a maintenance window.
Verified to leave the data byte-identical (`make ci-upgrade`).

Tables created *after* the upgrade are in v5 from the first row and need nothing.

### Also fixed: an all-NULL row made its table unreadable

Independent of the layout change, and present in every release up to 1.7.1: a row
whose columns are **all** NULL has no user data at all, so its encrypted region is
the AEAD framing and nothing else. That is a well-formed encoding of a
zero-length plaintext, and the decrypt path rejected it:

```
ERROR:  [CRYPTO] Ciphertext too short for AES-256-GCM
```

One such row is enough to make the whole table fail on any sequential scan from
that `INSERT` onwards. The row is not corrupt — the ciphertext on disk is fine —
and 1.7.2 reads it without any migration step. If you have hit this, upgrading is
the whole fix.

### Custom WAL resource manager id: 128 → 161

1.7.2 moves the custom WAL resource manager from `RM_EXPERIMENTAL_ID` (128) — the
id upstream reserves for experimentation, and so the one every prototype uses — to
**161**, registered for pg_vault_tde on the PostgreSQL *Custom WAL Resource
Managers* wiki. That is what keeps pg_vault_tde from colliding with another
extension loaded in the same cluster.

**If `pg_vault_tde.toast_custom_rmgr` is off — the default — there is nothing to
do.** No WAL record is ever written under the extension's id, so none carries 128.

**If it is on**, WAL written by 1.7.1 carries id 128, which 1.7.2 no longer knows:
replaying it fails with `resource manager with ID 128 not registered`, which is
fatal in the startup process. WAL carries the number, not the name, so this is not
something a restart can work around. Before switching binaries:

- stop the primary with a **clean** shutdown (`pg_ctl stop -m fast` or `smart`,
  never `immediate`), so nothing is left to replay on the next start;
- let every **physical standby** replay up to that shutdown checkpoint, then stop
  and upgrade it together with the primary. **No rolling upgrade**: a 1.7.2 standby
  cannot replay a 1.7.1 primary's records, and a 1.7.1 standby cannot replay a
  1.7.2 primary's;
- drain every **logical replication slot** that decodes TOAST through the custom
  resource manager;
- take a **new base backup** after the upgrade if you keep a WAL archive for PITR.
  Recovering into the pre-upgrade window needs the 1.7.1 binaries.

**Whatever the GUC says, check the id before upgrading.** 1.7.1 claimed 128, so a
cluster running it alongside an extension that uses 161 worked; with 1.7.2 the same
cluster will not start. Run the check in [2. Configure PostgreSQL](#2-configure-postgresql)
on every node first — it must return only pg_vault_tde's own row, under 128 while
1.7.1 is still running, and nothing else.

### Renamed shared-memory objects

The DEK cache's shared hash table and its LWLock tranche were both called
`TdeRelDekMap`. Both names live in cluster-wide namespaces shared with every other
preloaded extension, and PostgreSQL reports a clash in neither: a second extension
using the same name would silently share the lock, or attach to the existing hash
table and read it through its own layout. In 1.7.2 both are
**`pg_vault_tde_rel_dek_map`**, prefixed like the extension's other shared-memory
objects.

Nothing on disk changes — shared memory is rebuilt at every start. Update only
monitoring that matches the old name in `pg_stat_activity.wait_event` or in
`pg_shmem_allocations.name`.

---

## Compatibility

| Feature | Status | Notes |
|---|---|---|
| Sequential scan | ✅ Full | `scan_getnextslot` override |
| Index scan | ✅ Full | `index_fetch_tuple` override + `rd_tableam` impersonation |
| Bitmap heap scan | ✅ Full | `scan_bitmap_next_tuple` override |
| ANALYZE | ✅ Full | `scan_analyze_next_tuple` override |
| TABLESAMPLE | ✅ Full | `scan_sample_next_tuple` override |
| SELECT FOR UPDATE | ✅ Full | `tuple_lock` override |
| INSERT / COPY | ✅ Full | `tuple_insert` + `multi_insert` override |
| UPDATE | ✅ Full | `tuple_update` override + ctid preservation |
| DELETE | ✅ Full | No-op (heapam header-only delete, no column data touched) |
| HOT updates | ❌ Disabled by design | A fresh IV per row version makes every indexed column look changed, so `heap_update` never chooses HOT; every `UPDATE` writes all indexes. See [Limitation 7](#limitations-v17) and [Running in Production](#running-pg_vault_tde-in-production) |
| VACUUM | ✅ Full | Inherited from heapam (dead-tuple header only) |
| CTAS   | ✅ Full | Per-table DEK registration before SELECT is executed |
| `pg_dump` (plain) | ⚠️ Dump is plaintext | pg_dump reads via scan_getnextslot → decrypted. Use `pg_dump_tde` to re-encrypt the output. |
| `pg_dump_tde` / `pg_restore_tde` | ⚠️ Full, except `pkcs11` | Encrypted logical backup: dump wrapped with AES-256-GCM + DEK sealed in backup header. Standalone tools have no PKCS#11 session/PIN handling yet — see "Configure Key Access → PKCS#11 / HSM" above. |
| Streaming replication | ✅ Full | WAL ships encrypted bytes; standby decrypts at TAM layer |
| Page checksums | ✅ Full | Checksums over encrypted content (complementary to GCM) |
| Logical replication (non-TOAST) | ✅ Full (v1.2) | `pg_vault_tde_pgoutput` plugin decrypts tuples before streaming. On PG ≥ 17.11 / 18.x the publisher must allow the plugin — see below |
| TOAST (large values > ≈2 kB) | ✅ Full | Heap-level round-trips functional; per-chunk storage encryption |
| Logical replication (TOAST columns) | ✅ Full (v1.7) | Custom WAL rmgr (`toast_custom_rmgr`) routes encrypted chunks past the reorder buffer; stitched in `change_cb`. UPDATE/DELETE need `REPLICA IDENTITY FULL` + PK. Same publisher requirement as above |
| Range scans / ordering / `IN` on TDE indexes | ❌ Known defects | `tde_btree` is meant for equality only (AES-SIV preserves equality, not order). Ranges, `ORDER BY` and `min`/`max` return wrong rows on `text`/`bytea`/`numeric`; `IN`/`= ANY` fail on every type; `numeric` misses rows even on `=` — see [Limitation 2](#limitations-v17) |
| `CREATE INDEX USING gin/gist/hash/brin/btree` on `encrypted_heap` | ⚠️ `ERROR` by default | Not encrypted AMs; rejected unless `pg_vault_tde.allow_plaintext_index = on` (then allowed with `WARNING`) |
| Column-level encryption | 🔜 v1.8 | Per-column `ENABLE COLUMN ENCRYPTION` DDL |

### Logical replication on PostgreSQL 17.11 / 18.x and newer

Those minors added the `output_plugin_libraries` GUC (default
`pgoutput, test_decoding`): PostgreSQL now refuses to load any library outside
that list as a logical decoding output plugin. Creating a slot with this
extension's plugin therefore fails with:

```
ERROR:  library "pg_vault_tde" may not be used as an output plugin
HINT:   ... add it to "output_plugin_libraries" and reload the server configuration.
```

Add the plugin on the **publisher** and reload — no restart needed:

```conf
# postgresql.conf on the publisher
output_plugin_libraries = 'pgoutput, pg_vault_tde'
```

It has to be in the server configuration: the process that loads the plugin is
the walsender, so a session-level `SET` does not reach it. Older minors have no
such GUC, and an unrecognised parameter in `postgresql.conf` is fatal at
startup — add the line only where `SELECT ... FROM pg_settings WHERE name =
'output_plugin_libraries'` returns a row. Details in
[doc/pg_vault_tde.md](doc/pg_vault_tde.md) → *Logical Decoding and Replication →
Server configuration*.

---

## Testing

Two entry points, for two different needs.

**Building from source, or packaging?** One command, no container, no KMS
service, no cluster to configure:

```bash
make install            # into the tree your pg_config points at
make check-standalone   # creates a throwaway cluster, runs the test, tears it down
```

`make installcheck` on its own fails against a stock cluster: the extension
registers a Table Access Method from `_PG_init` and must be preloaded.
`check-standalone` supplies that (and nothing else) through
[test/regress.conf](test/regress.conf), so it needs no existing server and
touches none.

**Working on the extension?** The containerised suites cover what the smoke
test above does not — the KMS providers, TAP, isolation, checksums, benchmarks:

```bash
# Full local CI pipeline (build + all tests + bench):
make ci-all

# Test against a specific PG version:
PG_VERSION=17 make ci-all

# Individual test stages:
make ci-regress          # 137 SQL regression tests (vault provider) — numbered 1-140 + 154-159, with gaps
make ci-errorpath        # 13 error-path tests (141-153) — exercises the PG_CATCH handlers
make ci-matrix           # regress + TAP on the other supported PG majors (17, 19 when published)
make ci-scan-build       # Clang static analyzer over the sources (compile only, ~1 min)
make ci-ubsan            # Extension built with -fsanitize=undefined
make ci-valgrind         # Valgrind memcheck over the full TDE workload (slow: 10-50x)
make ci-cassert          # PostgreSQL built --enable-cassert -DUSE_VALGRIND (builds PG from source)
make ci-wallet           # SQL regression tests (local wallet provider)
make ci-checksums        # regression tests + page checksum compatibility
make ci-tap              # 28 TAP test files (starts a real Vault container for the Vault-dependent ones)
make ci-isolation        # 2 isolation specs: DEK rotation under load, relation rewrite under a concurrent reader
make ci-vault            # Vault integration (Compose-based)
make ci-openbao          # OpenBao Raft 3-node HA integration (12 tests)
make ci-upgrade          # Read data written by the previous release tag (upgrade compatibility)
make ci-bench            # Performance benchmark (encrypted vs plain heap)
make ci-bench BENCH_ROWS=100000  # with custom row count

# Cleanup:
make ci-clean            # Remove test containers and images
```

Test coverage — 150 SQL regression tests (45 v1.4 + 20 v1.5 + 36 v1.6 + 36 v1.7 + 13 error-path), plus 306 assertions across 28 TAP files. Numbers are one sequence shared by every file and have gaps: 5-9, 11 and 49 no longer exist, 80 was removed in v1.7, and 110 is disabled (the `WITH HOLD` cursor spill is a permanent limitation):
- Tests 1-4, 10: extension loaded, access methods and SQL functions registered, wallet unlock, backup status function
- Tests 12-14: TAM INSERT/SELECT/UPDATE end-to-end
- Test 15: DELETE
- Test 16: All-NULL rows (zero-length user data)
- Test 17: Index scan (`index_fetch_tuple` path)
- Test 18: COPY/bulk insert (`multi_insert` path)
- Test 19: Multi-column table (int, text, bool, numeric, timestamptz)
- Test 20: Per-table DEK isolation (two tables independently readable)
- Test 21: ANALYZE produces correct statistics on decrypted data
- Test 22: SELECT FOR UPDATE (`tuple_lock` path)
- Test 23: BitmapHeapScan (`scan_bitmap_next_tuple` path)
- Test 24: TABLESAMPLE (`scan_sample_next_tuple` path)
- Tests 25-48: UPSERT, MERGE, TRUNCATE, REINDEX, ALTER, JOINs, CTEs, HW accel, Vault, logical decoding
- Test 50: tde_btree CREATE INDEX + equality index scan **(v1.4)**
- Test 51: health_check() `kms_provider` column coherence with GUC **(v1.6 realignment)**
- Test 52: tde_btree UNIQUE constraint **(v1.4)**
- Tests 53-56: Per-table DEK catalog, wallet SQL stubs, rotation progress schema **(v1.5)**
- Tests 57-61: TOAST large-value round-trips (4 kB text, 8 kB jsonb, UPDATE, bulk COPY, raw-page check) **(v1.5)**
- Tests 62-64: Per-table DEK isolation (two tables; DEK-A cannot decrypt table-B), DROP TABLE catalog cleanup **(v1.5)**
- Tests 65-67: tde_btree native type operator classes (text, int4, uuid) **(v1.5)**
- Tests 68-69: Wire format v3 AEAD AAD — cross-table paste attack rejected **(v1.5)**
- Tests 70-72: Online key rotation BGW — concurrent SELECTs, progress tracking, BGW completion **(v1.5)**
- Tests 73-77: Wallet provider — init/unlock/lock, `wallet_status()` 5-col schema (`wallet_exists`, `wallet_open`, `kek_algorithm`, `last_opened`, `file_perms`), DEK round-trip with wallet KEK **(v1.6)**
- Tests 78-79: Wallet `change_passphrase` re-wraps under new KEK; `rotate_kek` re-wraps all per-table DEKs (catalog ciphertext changes; both tables remain readable) **(v1.6 patch)**
- Test 81: DDL hook registers BOTH parent and `reltoastrelid` in `pg_vault_tde_catalog`; DROP deregisters both **(v1.6)**
- Test 82: 64 KB compressible payload (pglz keeps it inline) — heap-level pre-TOAST + encrypt round-trip **(v1.6)**
- Test 83: Transactional rollback after pre-TOAST + encrypt keeps the table consistent and restores `reltoastrelid` **(v1.6)**
- Test 84: `pg_vault_tde_verify_plaintext_on_disk()` on STORAGE EXTERNAL payload — forensic helper confirms ciphertext on disk **(v1.6)**
- Test 85: STORAGE EXTERNAL round-trip — incompressible 80 KB payload produces real TOAST chunks (~41 in pg_toast_NNN); validates the TAM `RELKIND_TOASTVALUE` read-path bypass that allows plaintext chunks to round-trip through the encrypted parent table **(v1.6 patch)**
- Test 86: `pg_vault_tde_verify_plaintext_on_disk()` on STORAGE EXTERNAL incompressible payload (real TOAST chunk path; test-only helper, requires `pg_vault_tde.dev_mode=on`) **(v1.6 patch)**
- Test 87: `pg_vault_tde_verify_toast_by_comparison()` byte-for-byte TOAST forensic helper on STORAGE EXTERNAL incompressible payload (test-only helper, requires `pg_vault_tde.dev_mode=on`) **(v1.6 patch)**
- Test 88: STORAGE EXTERNAL — no compression, real TOAST chunks, plaintext visible via SELECT but absent on disk **(v1.6)**
- Test 89: STORAGE EXTENDED — compression + TOAST chunks + transparent DML **(v1.6)**
- Test 90: Storage metadata sanity — `attstorage` flags and TOAST presence **(v1.6)**
- Test 91: STORAGE EXTERNAL DELETE removes visible TOAST entries **(v1.6)**
- Test 92: VACUUM FULL on plain `encrypted_heap` table **(v1.6)**
- Test 93: VACUUM FULL on `encrypted_heap` table with TOAST data **(v1.6)**
- Test 94: CLUSTER on `encrypted_heap` with TOAST data **(v1.6)**
- Test 95: TOAST data readable via index scan (`index_fetch_tuple`) **(v1.6)**
- Test 96: TOAST data readable via BitmapHeapScan **(v1.6)**
- Test 97: TOAST data readable via SELECT FOR UPDATE (`tuple_lock`) **(v1.6)**
- Test 98: TOAST data readable via TABLESAMPLE (`scan_sample_next_tuple`) **(v1.6)**
- Test 99: TOAST data — ANALYZE computes statistics correctly **(v1.6)**
- Test 100: `multi_insert` (COPY path) with TOAST-triggering values **(v1.6)**
- Test 101: Multi-column TOAST — two large varlena attributes **(v1.6)**
- Test 102: UPDATE large→large exercises `old_has_external` branch in `tuple_update` **(v1.6)**
- Test 103: `pg_vault_tde.toast_encryption=on` — TOAST table uses `encrypted_heap` AM (`pg_vault_tde_toast_am` callback) **(v1.6)**
- Test 104: TOAST header overflow edge case **(v1.6)**
- Test 105: `ALTER TABLE x SET ACCESS METHOD heap` — convert encrypted to plain heap **(v1.6)**
- Test 106: `ALTER TABLE x SET ACCESS METHOD encrypted_heap` — convert plain heap to encrypted **(v1.6)**
- Test 107: Tuple readable after `pg_vault_tde_rotation_online()` completes **(v1.6)**
- Test 108: `CREATE TABLE AS` with `encrypted_heap` **(v1.6)**
- Test 109: VACUUM FULL on table with STORAGE EXTERNAL columns **(v1.6)**
- Tests 111-137: `tde_btree` native-type operator classes (int4/int8/uuid/date/timestamptz), DEK rotation + REINDEX, partitioned tables (routing, per-leaf DEK isolation, ATTACH/DETACH), FK relationships, `CREATE`/`REINDEX INDEX CONCURRENTLY` **(v1.7 — `sql/regression_test_v17.sql`)**
- Test 138: `ALTER TABLE x SET ACCESS METHOD encrypted_heap` on a **populated** table with genuinely out-of-line TOAST data (~13 KB, high-entropy so PGLZ can't compress it back inline) — verifies an exact byte-for-byte round-trip via `SELECT` (Tests 105/106 only check on-disk bytes, never read the row back) plus post-ALTER `UPDATE`/`DELETE` across all four small/large transitions **(v1.7, PSQLE-135 regression coverage)**
- Test 139: `ALTER TABLE x SET ACCESS METHOD heap` — reverse direction of Test 138, same coverage **(v1.7, PSQLE-135 regression coverage)**
- Test 140: `CREATE TABLE AS SELECT` from an `encrypted_heap` table with genuinely out-of-line TOAST data must re-externalize into the **destination's own** TOAST table; verifies the destination survives the (unrelated, from its own point of view) source table being dropped **(v1.7, PSQLE-135 regression coverage)**
- Test 154: `UPDATE` on a table whose index sits on an attribute **behind a variable-length column** — the statement that segfaulted. `heap_update()` reads the indexed attributes straight off the page; under the v4 layout that walk took a varlena length header out of ciphertext and left the page. Also asserts no HOT update was chosen and that index and sequential scan agree after the indexed column changes **(v1.7.2, PSQLE-165 regression coverage)**
- Test 155: a row whose columns are **all NULL** round-trips. Its encrypted region is the AEAD framing and nothing else — a well-formed encoding of a zero-length plaintext that used to be rejected, making the row unreadable for good **(v1.7.2)**
- Test 156: the v5 layout keeps attribute **values** off disk while leaving the tuple structure readable; a plain-heap control proves the search would have found the needle if it were there **(v1.7.2)**
- Test 157: every on-disk tuple is **physically walkable** with the relation's tuple descriptor — the invariant PSQLE-165 broke, asserted directly via `pageinspect` instead of through its symptom, plus a per-attribute plaintext check. Skips when `pageinspect` is unavailable **(v1.7.2)**
- Test 158: the indexed column's **position** must not affect correctness — 8 combinations (attnum 1 / behind a varlena / behind a NULL varlena / behind a dropped column, × `tde_btree` and plaintext `btree`). PSQLE-165 hid for four releases because 38 of 38 regression tables put the key on the first column, the one position whose offset is cached and never walked **(v1.7.2)**
- Test 159: `pg_get_wal_resource_managers()` reports id **161** as `pg_vault_tde` — the id reserved on the PostgreSQL *Custom WAL Resource Managers* wiki. Fails on any change to `TDE_RMGR_ID`, which would make the previous release's WAL unreplayable; `tap/19` pins the same id in the WAL records and the startup log **(v1.7.2, PSQLE-172)**

Error-path coverage — tests 141-153 (`sql/regression_test_errorpath.sql`, `make ci-errorpath`):

Every other test file exercises the success path. These exercise the `PG_CATCH` handlers in the TAM write paths — code that only ever runs after a `longjmp`, and that cleanses plaintext key material and frees intermediates. No success-path test can reach it. The suite locks the wallet so `tde_gcm_encrypt()` raises from inside `tde_encrypt_heap_tuple()`, i.e. from inside the `PG_TRY` of every write path, then forces 145 aborted writes through those handlers.

- Test 141: `pg_vault_tde_tuple_insert` handler ×25 — also the guard that the DEK really is unreachable (a vacuous run is a failure, not a pass)
- Test 142: `pg_vault_tde_multi_insert` handler ×10 batched COPY of 100 **small** rows — the aliasing case where `toasted_inflight == plain_inflight`
- Test 143: `pg_vault_tde_multi_insert` + `pg_vault_tde_toast_save_datum` handlers ×5 via the custom TOAST chunk writer
- Test 144: `pg_vault_tde_tuple_update` handler ×25
- Test 145: `pg_vault_tde_tuple_insert_speculative` handler ×25 (ON CONFLICT)
- Tests 146-147: `pg_vault_tde_relation_copy_for_cluster` handler ×20 (VACUUM FULL, CLUSTER)
- Test 148: fixture is byte-identical after the error storm — this is what proves 142/143/146/147 aborted rather than committed
- Test 149: TOAST payloads still decrypt byte-for-byte
- Tests 150-151: no plaintext in the main fork or the TOAST relation afterwards (`STORAGE EXTERNAL` is required, and asserted, so the TOAST scan cannot pass vacuously on a 0-byte file)
- Test 152: every write path, plus VACUUM FULL and CLUSTER, healthy again after 145 longjmps
- Test 153: core must not re-TOAST the ciphertext — sweeps 29 payload sizes across `TOAST_TUPLE_THRESHOLD` plus UPDATE, UPSERT and COPY at the boundary. Guards a segfault: `heap_toast_insert_or_update()` fires on tuple *size* as well as on external attributes, so clearing `HEAP_HASEXTERNAL` alone leaves a window as wide as the AES-GCM overhead in which core deforms ciphertext as varlena and `toast_save_datum()` crashes

Deep-checking stages — four tools, four different bug classes. `run-all.sh --skip-deep` skips all of them; they are the only stages that cost more than a couple of minutes.

| stage | sees | cost |
|---|---|---|
| `ci-scan-build` | per-path symbolic execution: NULL deref on one branch, sizes from a length that can be zero | ~1 min, compile only |
| `ci-ubsan` | undefined behaviour: signed overflow, oversized shifts, misaligned loads, `nonnull` violations | minutes, no PG rebuild |
| `ci-valgrind` | memory ownership: invalid/double `free()` of malloc'd state, out-of-bounds, uninitialised reads | 10-50x runtime |
| `ci-cassert` | `Assert()` calls that run nowhere else, plus `MEMORY_CONTEXT_CHECKING` — the only stage that catches a double `pfree()` of a palloc chunk | builds PostgreSQL from source |

`ci-cassert` is the one worth the wall-clock. `--enable-cassert` executes the `Assert()` calls this codebase is full of — none of which run in any packaged build — and turns on `MEMORY_CONTEXT_CHECKING`, which poisons freed chunks and validates the header on every `pfree()`. A double free in a `PG_CATCH` handler becomes a loud failure instead of a silent no-op that the aborting transaction covers up moments later. Neither flag exists in a PGDG or Debian package, which is why the image builds the server from source.

`ci-ubsan` uses the `TDE_SANITIZE` Makefile knob (`make TDE_SANITIZE=undefined`), which instruments only our objects — the server binary stays stock, so no PostgreSQL rebuild is needed.

Concurrency — `make ci-isolation` (`test/isolation/specs/`):

- `per_table_dek_rotation.spec` — online DEK rotation racing readers, writers and VACUUM
- `encrypted_rewrite_concurrency.spec` — `VACUUM FULL` / `CLUSTER` (i.e. `pg_vault_tde_relation_copy_for_cluster`) with a second backend holding a `REPEATABLE READ` snapshot across the relfilenode change, and with an uncommitted writer the rewrite must wait for. Payloads are `STORAGE EXTERNAL` so the rewrite has real TOAST chunks to migrate. This spec found the `toast_save_datum()` segfault that TEST 153 now guards; it does **not** cover `wallet_lock()`, because the stage sets `wallet_dev_mode_passphrase` and those permutations would pass vacuously — the spec says so in a comment rather than shipping a test that checks nothing

On-disk corruption — `tap/20_ondisk_fuzz.t`:

Flips 72 random bits across the heap file over 6 rounds (fixed seed, so a failure reproduces) and classifies every row afterwards. The property under test is that the layer has exactly two behaviours under arbitrary damage — correct data, or a refusal — and never hands the client a value derived from damaged ciphertext. Data page checksums are **disabled** for this test on purpose: with them on, PostgreSQL rejects the page before the extension is asked to decrypt anything, and the test would measure core's checksums instead of AES-256-GCM.

A third outcome is counted separately and accepted: the row *vanishing*. Our wire format keeps the `HeapTupleHeader` in plaintext and authenticates only `[t_hoff .. t_len)`, so a flip in xmin, infomask or the null bitmap is outside the GCM tag by construction and can make the tuple invisible. That is data loss from unauthenticated-header damage, not a forged value — the test distinguishes the two rather than conflating them.

Cross-version — `make ci-matrix`:

Every other stage runs on PG 18 only. This one runs the SQL regression suite **and** the TAP suite on the remaining supported majors, so a change that compiles everywhere but misbehaves on 17 cannot ship green. Not hypothetical here: `pg_vault_tde_ambuild` carries a PG17-specific impersonation, and the TAM notes a PG17 read-stream requirement in `heapgettup`.

TAP is in the matrix because it is the stage that needed it most. `tap/20_ondisk_fuzz.t` passed locally on PG 18 and broke CI on PG 17: `initdb --no-data-checksums` only exists from PG 18. TAP tests depend on the `PostgreSQL::Test` framework and on `initdb`/`pg_ctl` option spellings, all of which move between majors far more than SQL does.

A major whose base image is not published yet is skipped rather than failed, so PG 19 starts being covered on its own the day `postgres:19` ships.

Memory safety — `make ci-valgrind` (`sql/valgrind_workload.sql`, `ci/scripts/run-valgrind.sh`):

Runs the postmaster under Valgrind memcheck with `.valgrind.supp`, over a workload covering every crypto-touching path on both the success and error side, then filters findings to stacks naming `pg_vault_tde`. Costs 10-50x, so `--skip-valgrind` is available in `run-all.sh`.

Note what it can and cannot see: the stock server package is not built with `-DUSE_VALGRIND` or `--enable-cassert`, so memcheck cannot see inside `palloc` — a use-after-`pfree` looks like a valid access into a malloc'd arena. It does catch invalid/double `free()` of malloc'd state (libcurl handles on the `vault_transit_request` error path), out-of-bounds access, uninitialised reads, and definite leaks. That limitation is why `ci-errorpath` exists alongside it rather than being replaced by it.

> Test runner notes:
> - `make ci-regress` (vault provider): 145/145 PASS, with conditional skips for `wal_level` (test 48) and wallet-only assertions (tests 74–80 when `kms_provider=local` is required). `pageinspect` is installed by `ci/scripts/run-regress.sh`, so the storage-level tests (61, 157) run rather than skip — until that line existed they asserted nothing in CI.
> - `make ci-errorpath` (local provider, **no** `wallet_dev_mode_passphrase`): 13/13 PASS. The absent GUC is load-bearing — with it set, `wallet_lock()` silently re-opens on the next DEK request and every statement succeeds, so the handlers are never entered. Test 141 detects that and fails rather than passing vacuously.
> - `make ci-wallet` (local provider): tests 73–79 PASS; test 80 SKIPS unless `wallet_passphrase_env` is wired up; tests 81–109 also PASS in wallet mode.
> - Test 110 (WITH HOLD cursor plaintext spill) is permanently deferred — the executor's tuplestore layer bypasses the TAM write path, so pg_vault_tde cannot intercept it without core modifications. The test is commented out in `regression_test_v16.sql`.
> - Tests 138–140 exist because Tests 105/106 didn't catch two real bugs, both stemming from the same underlying cause: `tde_decrypt_heap_tuple()` copied the on-disk tuple header verbatim, including the `HEAP_HASEXTERNAL` bit that `tde_encrypt_heap_tuple()` deliberately clears so core never dereferences a TOAST pointer inside ciphertext — leaving that bit WRONG on the decrypted tuple whenever the attribute genuinely is out-of-line. (1) The AAD was also bound to the wrong (transient) relation OID during `ALTER TABLE`'s row-by-row rewrite — fixed via `resolve_effective_relid()` in `tde_compute_aad()`. (2) Any consumer trusting the stale `HEAP_HASEXTERNAL` bit instead of re-deriving it — `pg_vault_tde_toast_insert_or_update()`'s size-only gate, but also, more broadly, `CREATE TABLE AS SELECT`/`INSERT ... SELECT` reading out of an `encrypted_heap` table — silently skips re-externalizing the value, leaving it pointing at storage that later disappears. Fixed at the source: `tde_decrypt_heap_tuple()` now recomputes the bit from the actual decrypted attributes (`tde_tuple_has_external_desc()`) before returning, so every consumer sees a truthful tuple. Both only reproduce with a populated source table and a genuinely out-of-line (not just inline-compressed) value.

---

## Building

```bash
make && sudo make install

# Optional: -O3 -funroll-loops -fomit-frame-pointer instead of -O2
make TDE_OPTIMIZE=max && sudo make install
```

There is a single build. Hardware-accelerated AES (AES-NI, VAES, ARM Crypto
Extensions, SVE2) is provided automatically at runtime by OpenSSL's own
default provider, based on the CPU the server is actually running on — this
requires no special compiler flags and no separate build. pg_vault_tde never
implements AES itself; it always calls into OpenSSL's EVP API
(`src/crypto/pg_vault_tde_hw_accel.c`), which does its own CPUID/HWCAP
detection independent of how pg_vault_tde.so was compiled. Confirm what's
actually active at runtime with:

```bash
make check-cpu     # detect this machine's available CPU crypto extensions
make bench-cpu     # OpenSSL AES throughput microbenchmark
```

```sql
SELECT * FROM pg_vault_tde_hw_accel_info();
```

### Packages

The easiest way — no local build toolchain required (only `podman` or `docker`):

```bash
# Build all four packages (deb+rpm × pg17+pg18) into ./dist/
bash packaging/build_in_container.sh --all

# Single package (defaults: DEB, PG18, Ubuntu 22.04)
bash packaging/build_in_container.sh
bash packaging/build_in_container.sh --format rpm             # RPM PG18
bash packaging/build_in_container.sh --pg-version 17          # DEB PG17
bash packaging/build_in_container.sh --format rpm --pg-version 17  # RPM PG17
```

#### OS version selection

Choose the base OS image for the build container:

```bash
# DEB — Ubuntu or Debian
bash packaging/build_in_container.sh --os-version ubuntu:22.04   # default (Jammy LTS)
bash packaging/build_in_container.sh --os-version ubuntu:24.04   # Noble LTS
bash packaging/build_in_container.sh --os-version debian:12      # Bookworm
bash packaging/build_in_container.sh --os-version debian:13      # Trixie

# RPM — Rocky Linux or AlmaLinux (EL-compatible)
bash packaging/build_in_container.sh --format rpm --os-version rockylinux:9   # default (EL9)
bash packaging/build_in_container.sh --format rpm --os-version rockylinux:10  # EL10
bash packaging/build_in_container.sh --format rpm --os-version almalinux:9    # EL9 (AlmaLinux)
bash packaging/build_in_container.sh --format rpm --os-version almalinux:10   # EL10 (AlmaLinux)
```

OpenSSL 3.x is required (the KMS layer uses `EVP_EncryptInit_ex2`/AES-256-WRAP
key wrapping, added in OpenSSL 3.0), so OSes that only ship OpenSSL 1.1.1 —
Debian 11 (Bullseye) and EL8 (Rocky/AlmaLinux 8) — are not supported.

Options compose freely:

```bash
# RPM for PG17 on Rocky Linux 9
bash packaging/build_in_container.sh \
    --format rpm --pg-version 17 --os-version rockylinux:9

# DEB for PG18 on Debian 12
bash packaging/build_in_container.sh --os-version debian:12
```

If you have a local build environment, invoke the underlying scripts directly:

```bash
# Debian / Ubuntu
bash packaging/build_deb.sh --no-sign

# RHEL / Rocky / Fedora
bash packaging/build_rpm.sh
```

---

## Encrypted Backups

### `pg_dump_tde` / `pg_restore_tde`
Plain `pg_dump` decrypts rows at read time (via the TAM), so the dump file is
**plaintext**.  `pg_dump_tde` closes this gap by piping the dump through
AES-256-GCM before touching disk:

```bash
# Encrypted dump
pg_dump_tde -h localhost -U postgres -d mydb -o /backup/mydb.tde

# Restore encrypted dump
pg_restore_tde -h localhost -U postgres -d mydb -i /backup/mydb.tde
```

>All other `pg_dump` options are fed directly to it.

### `pg_basebackup`
It's possible to use `pg_basebackup` to create a base backup of the cluster and use it for a standby creation.

#### Primary configuration

No special configuration is needed on the primary: encrypted relations are copied as-is by `pg_basebackup`, and the wrapped DEKs travel inside `pg_vault_tde_catalog` (part of the data directory). The **KEK never travels with the backup** — it stays in the KMS/wallet, exactly as with Oracle RMAN, SQL Server and Percona pg_tde.

#### Standby / restore configuration

The wrapped DEKs arrive with the base backup, but the KEK must be made available on the target separately:

- **`local` provider** — copy the primary's `wallet.p12` to the standby (it lives outside `PGDATA`, so it is *not* in the base backup).
- **`vault` provider** — point the standby at the **same** Vault; nothing to copy.

#### Sealing the DEK catalog (key sealing)

`pg_vault_tde_seal_keys()` writes a signed, point-in-time snapshot of every wrapped DEK to accompany the backup `pg_vault_tde_unseal_keys()` verifies and re-imports it on the target. This makes the key state **tamper-evident** and guards against key-rotation drift between primary and standby.

```sql
-- On the primary, before pg_basebackup:
SELECT pg_vault_tde_seal_keys('/backup/keys.sealed', 'a-seal-passphrase');
```
```bash
pg_basebackup -h primary -D /backup/data -X stream
# local provider only: also transport the wallet, e.g.
#   scp /path/to/wallet.p12 standby:/path/to/wallet.p12
```
```sql
-- On the standby, after restoring the data dir and providing the KEK:
SELECT pg_vault_tde_unseal_keys('/backup/keys.sealed', 'a-seal-passphrase');
```
The HMAC key is derived from the seal passphrase (PBKDF2-SHA256); it isindependent of the KMS provider, so the same bundle works for local and vault. unseal_keys verifies the HMAC before touching the catalog: a tampered bundle or wrong passphrase is rejected and nothing is written.

> Key-rotation note: if the KEK/DEK is rotated after a backup, primary and standby can drift. Re-running seal_keys after a rotation (and unseal_keys on the standby) realigns the sealed key state with the data.

> Concurrency note: don't run `unseal_keys()` while `pg_vault_tde_rotate_online()` is rotating the same table. Postgres's own MVCC checks make this fail safely — you'll see a `tuple concurrently updated` or duplicate-key error and nothing will have been imported — just re-run `unseal_keys()` once the rotation finishes.

#### `pg_basebackup_tde` (automatic key sealing)

`pg_basebackup_tde` wraps `pg_basebackup` and performs the sealing step
automatically, for **every database** in the cluster that has the extension
(the DEK catalog is per-database, while `pg_basebackup` is cluster-wide):

```bash
# passphrase from a 0600 file (the ~/.pgpass pattern) ...
pg_basebackup_tde -h primary -D /backup/data -X stream \
    --seal-passphrase-file /etc/pg_vault_tde/seal.pass
# ... or from the environment
export PG_VAULT_TDE_SEAL_PASSPHRASE='a-seal-passphrase'
pg_basebackup_tde -h primary -D /backup/data -X stream
```

The passphrase is never accepted as a command-line value: it would leak in
`ps` output and shell history. `--seal-passphrase-file` reads the first line
of the file and takes precedence over the environment variable.

All options are forwarded verbatim to `pg_basebackup`. For each database with
`pg_vault_tde`, the wrapper calls `pg_vault_tde_seal_keys_bytea()` **before**
the backup starts (point-in-time key snapshot) and, **only if the backup
succeeds**, writes one bundle per database next to it:

```
/backup/data/pg_vault_tde_keys.<datname>.sealed   (mode 0600)
```

Use `--keys-dir DIR` to store the bundles elsewhere (e.g. outside `PGDATA`).
Databases without the extension are skipped; a failed backup leaves no bundle
files behind. The tar format (`-Ft`) is not supported — use the plain format
or run `pg_vault_tde_seal_keys()` manually.

Restore stays manual, exactly as above: restore the data dir, provision the
KEK, then per database
`SELECT pg_vault_tde_unseal_keys('/backup/data/pg_vault_tde_keys.<db>.sealed', '...');`

### How it works

1. `pg_dump_tde` forks `pg_dump -Fc` with stdout redirected to a pipe.
2. It connects to PostgreSQL to read `pg_vault_tde.kms_provider` from GUCs.
3. Generates a fresh DEK, wraps it via the active KMS provider, writes a
   `tde_backup_header` (magic + format_version + wrapped_dek) to the output file.
4. Reads the `pg_dump` stream in 64 KB blocks; encrypts each block as:

   `[ Block length (4) | 0x02 (1) | IV (12) | Ciphertext | GCM-TAG (16) ]`

   Block sequence number is bound as GCM AAD — reordering blocks is detectable.
   
   (Reading from a stream with `fread` not guarantee that the block is 64 KB every time,
   that's why the block length is stored)
5. If `pg_dump` fails mid-stream the partial output file is deleted automatically.

### Block wire format

```
[ tde_backup_header ]
[ Block 0: Block length (4) | 0x02 | IV(12) | CT(64 KB) | TAG(16) ]
[ Block 1: Block length (4) | 0x02 | IV(12) | CT(64 KB) | TAG(16) ]
...
```

Each block is independently authenticated — corruption is detected at the block
level, not only at EOF.

### Current limitations

1. Only `-Fc` format is supported.

2. `-j` option is **NOT** supported. Parallel jobs are only supported by `pg_dump`
if the directory format (`-Fd`) is set.

3. Fixed block size: 64 KB.

4. Restore is locked to the original KEK used for DEK wrapping. This means that if we need to restore a dump into a new database that is using a different wallet (KMS local speaking) from the original, we can't. The old wallet or a new wallet containing the old KEK is needed.

   Currently (v1.7) deleting a database (`DROP DATABASE`) deletes his .p12 wallet file. Dump files previous created from this database becomes undecryptable (if wallet file is lost).

5. File-only output and input. The option `--output` or `-o` (for `pg_dump_tde`) and `--input`
or `-i` (for `pg_restore_tde`) are mandatory. Neither piping nor reading from `stdin` are supported.

6. Executing `pg_dump` still produces a plain-text backup
---

## Running pg_vault_tde in Production

A checklist for setting up and administering a cluster that keeps data in
`encrypted_heap`. Each item links to the section with the detail; the queries were
run against 1.7.2.

### Before the first encrypted table

- **Check the WAL resource manager id** on every node that will load pg_vault_tde or
  replay its WAL — see [2. Configure PostgreSQL](#2-configure-postgresql).
- **Pick a real KMS.** Vault/OpenBao, PKCS#11 or the local wallet — see
  [KMS Provider Selection](#kms-provider-selection). `pg_vault_tde.dev_mode` and
  `wallet_dev_mode_passphrase` are for tests: the extension logs a WARNING on every use.
- **Size the DEK cache.** `pg_vault_tde.max_encrypted_relations` (default 1024, restart
  required) is one budget for the whole cluster. Every encrypted table, every partition
  *and* its partitioned parent, and every `tde_btree` index takes an entry. Past the
  budget nothing fails, but each access to an uncached relation goes back to the KMS —
  and the budget is also the cap on how many plaintext DEKs sit in shared memory. Count
  in every database, sum, add headroom:

  ```sql
  SELECT count(*) FROM pg_vault_tde_catalog;
  ```

- **Warm the cache after a restart** with `pg_vault_tde.preload_keys = on` if
  first-query latency matters — it needs a KMS that opens without an interactive unlock
  (see [GUC Parameters](#guc-parameters)).
- **Put temporary files on encrypted storage.** Any query that spills past `work_mem` —
  a sort, a hash, a `WITH HOLD` cursor — writes rows that are already decrypted to a
  temporary file, and no extension hook can intercept it
  ([Limitation 6](#limitations-v17)). Point `temp_tablespaces` at an encrypted
  filesystem, and set `log_temp_files` to see how much spills.
- **Treat the server log as sensitive.** Statement text is logged with its literals: with
  `log_statement = 'mod'` or `'all'`, and by default for every statement that fails
  (`log_min_error_statement = error`).

### Designing encrypted tables

- **Keep sensitive values out of `PRIMARY KEY` and `UNIQUE` constraints.** PostgreSQL
  backs them with a native btree, so the key column is stored **in plaintext** in that
  index; pg_vault_tde warns when you create one. Use a surrogate primary key (`bigserial`,
  `uuid`) and enforce uniqueness of a sensitive column with
  `CREATE UNIQUE INDEX … USING tde_btree`. A violation of that index reports the key in
  `DETAIL` as ciphertext, not as the value.
- **Use `tde_btree` for single-value equality lookups only, and know its known defects**
  ([Limitation 2](#limitations-v17)):
  - `int4`, `int8`, `uuid`, `date`, `timestamptz`, and `text`/`bytea` with a deterministic
    collation: `col = value` is correct.
  - **`IN (…)` and `= ANY (…)` fail** on every `tde_btree` index
    (`cache lookup failed for type …`).
  - **`numeric`: do not index with `tde_btree`.** Even `=` misses rows (555 of 2,000 values
    in one test).
  - **`text` with a nondeterministic collation**: `=` through the index misses rows.
  - `text`, `bytea`, `numeric`: range predicates, `ORDER BY … LIMIT`, `min()`/`max()` and
    merge joins use the index and return **wrong rows, or fail with
    `mergejoin input data is out of order`**, with default planner settings.

  Where a query must do any of these on an indexed column, `SET enable_indexscan = off`
  and `SET enable_bitmapscan = off` for it.
- **Every index costs on every `UPDATE`.** HOT updates are off
  ([Limitation 7](#limitations-v17)), so each `UPDATE` adds an entry to every index on the
  table, whether or not its columns changed. Keep indexes to what queries need, and don't
  lower `fillfactor` to make room for HOT: there is none to make room for.
- **Encrypt every partition.** Encryption is per leaf. A `heap` partition under an
  `encrypted_heap` parent stores its rows in plaintext without any error (regression
  test 127 asserts it). Find them:

  ```sql
  SELECT p.relid::regclass AS unencrypted_leaf, parent.oid::regclass AS encrypted_parent
  FROM pg_class parent
  JOIN pg_am pa ON pa.oid = parent.relam AND pa.amname = 'encrypted_heap'
  CROSS JOIN LATERAL pg_partition_tree(parent.oid) p
  JOIN pg_class c ON c.oid = p.relid
  LEFT JOIN pg_am a ON a.oid = c.relam
  WHERE parent.relkind = 'p' AND p.isleaf
    AND a.amname IS DISTINCT FROM 'encrypted_heap';
  ```

- **Keep sensitive columns out of `pg_statistic`.** `ANALYZE` computes statistics on the
  decrypted values, so most-common values and histogram bounds land in `pg_statistic` in
  plaintext, on disk. `ALTER TABLE t ALTER COLUMN c SET STATISTICS 0` stops that — but only
  for future runs: a row `ANALYZE` already wrote stays. Set it right after `CREATE TABLE`,
  before data and autovacuum's first analyze arrive. The planner then has no statistics
  for that column. See `doc/pg_vault_tde.md` → Security Considerations.
- **Logical replication** needs `REPLICA IDENTITY FULL` plus a primary key for
  `UPDATE`/`DELETE`, and `pg_vault_tde.toast_custom_rmgr = on` for TOAST columns
  ([Limitation 3](#limitations-v17)). The stream leaves the publisher **decrypted**: use
  TLS on the subscription connection and `encrypted_heap` on the subscriber.

### Routine administration

- **Vacuum more, table by table.** Every `UPDATE` leaves a dead heap tuple and a dead
  entry in every index, and autovacuum's defaults assume HOT absorbs much of that. Lower
  the thresholds on update-heavy encrypted tables; start from something like:

  ```sql
  ALTER TABLE orders SET (autovacuum_vacuum_scale_factor  = 0.02,
                          autovacuum_analyze_scale_factor = 0.02);
  ```

- **Measure bloat without `pgstattuple`.** `pgstattuple()` and `pgstattuple_approx()`
  reject `encrypted_heap` ("only heap AM is supported"), and `pgstatindex()` rejects
  `tde_btree` ("is not a btree index"). Watch the statistics views and the size trend
  instead; `n_tup_hot_upd` is always 0 here, by design:

  ```sql
  SELECT s.relid::regclass AS table_name, s.n_live_tup, s.n_dead_tup,
         s.n_tup_upd, s.n_tup_hot_upd, s.last_autovacuum, s.autovacuum_count
  FROM pg_stat_user_tables s
  JOIN pg_class c ON c.oid = s.relid
  JOIN pg_am    a ON a.oid = c.relam
  WHERE a.amname = 'encrypted_heap'
  ORDER BY s.n_dead_tup DESC;

  SELECT i.indexrelid::regclass AS index_name, i.indrelid::regclass AS table_name,
         pg_size_pretty(pg_relation_size(i.indexrelid)) AS index_size
  FROM pg_index i
  JOIN pg_class ic ON ic.oid = i.indexrelid
  JOIN pg_am    a  ON a.oid  = ic.relam
  WHERE a.amname = 'tde_btree'
  ORDER BY pg_relation_size(i.indexrelid) DESC;
  ```

- **Rebuild bloated indexes online** with `REINDEX INDEX CONCURRENTLY`. It works on
  `tde_btree` but never in parallel ([Limitation 8](#limitations-v17)), so it takes longer
  than on a plain btree. btree's bottom-up deletion already removes most dead versions
  for updates that don't touch the key; what vacuum cannot give back is pages that have
  split. `tde_btree` indexes also never deduplicate, so on low-cardinality keys they are
  larger than a plain btree even right after a rebuild.
- **Rotate keys on a schedule** — see [Key Rotation](#key-rotation). Online rotations are
  tracked in the `pg_vault_tde_rotation_status` view, readable by `pg_monitor`.
- **Check integrity off-peak.** `pg_vault_tde_verify_integrity('t')` verifies the GCM
  tag of every tuple — a full scan.
- **Check health.** `pg_vault_tde_health_check()`, `pg_vault_tde_hw_accel_info()` (is
  AES-NI in use?), and `pg_vault_tde_vault_status()` or `pg_vault_tde_wallet_status()`
  for the KMS — see [SQL Functions](#sql-functions).

### Backups, standbys and upgrades

- **Don't rely on plain `pg_dump`**: it writes decrypted rows. Use `pg_dump_tde` and
  `pg_basebackup_tde` — see [Encrypted Backups](#encrypted-backups).
- **Back up the key material separately.** A base backup carries the wrapped DEKs, never
  the KEK. With the local provider the wallet lives outside `PGDATA`, at
  `/var/lib/pg_vault_tde/<db_oid>/wallet.p12`, and `DROP DATABASE` deletes it. Back up the
  wallet file and its passphrase on their own schedule: without them, every dump of that
  database is undecryptable.
- **Standbys** need pg_vault_tde preloaded, the id check above, and access to the KEK —
  a copy of the wallet, or the same Vault or HSM.
- **Upgrades**: follow the notes for each release. [Upgrading to 1.7.2](#upgrading-to-172)
  needs one `VACUUM FULL` per encrypted table and, with `toast_custom_rmgr` on, every
  node stopped cleanly and upgraded together.

---

## Performance

### Overhead vs Plain Heap

pg_vault_tde adds AES-256-GCM encryption/decryption and IV generation on every
tuple read and write.  The expected overhead depends on workload and row size:

| Workload | Typical Overhead | Notes |
|----------|-----------------|-------|
| OLTP (mixed R/W, 100–500 B rows) | **< 15%** | Design target for this workload |
| Bulk INSERT (1M rows) | **25–40%** | AES-GCM + `pg_strong_random` per tuple |
| Sequential scan (1M rows, read-only) | **20–35%** | Decrypt + palloc copy per tuple |
| Index scan (point lookups) | **< 5%** | Single tuple decrypt per fetch |

### Buffer Pin Behaviour

`decode_slot` copies the encrypted tuple from the shared buffer page and decrypts
it into a palloc'd plaintext tuple.  The shared buffer pin is held until
`ExecForceStoreHeapTuple()` releases it internally — this preserves the
page-at-a-time access pattern of heapam's sequential scan.  Buffer hit counts
for encrypted tables should be comparable to plain heap (proportional to the
number of **pages**, not rows).

---

## Limitations (v1.7)

See [doc/ROADMAP.md](doc/ROADMAP.md) for the full gap-closure roadmap.

1. **tde_btree fixed-size type index key encryption** — ✅ **Resolved in v1.7**: `int4`,
   `int8`, `uuid`, `date`, `timestamptz` columns now have their btree index keys encrypted
   with AES-256-SIV, identical to varlena types. **Index-only scans are not supported**
   (by design, for security — see `doc/pg_vault_tde.md` § Index-Only Scans).

2. **Range scans and ordering on TDE indexes** (equality-only by design; **wrong results on
   `text`, `bytea` and `numeric` — known defect**): The `tde_btree` AM uses AES-256-SIV,
   which preserves equality but not order. For `int4`, `int8`, `uuid`, `date` and
   `timestamptz` the default operator classes declare equality only, so range predicates,
   `ORDER BY` and `min()`/`max()` never use the index and are answered correctly by a
   sequential scan. For `text`, `bytea` and `numeric` the default operator classes
   (`tde_text_ops`, `tde_bytea_ops`, `tde_numeric_ops`) also declare `<` `<=` `>=` `>`,
   applied to the **ciphertext**: with default planner settings PostgreSQL uses the index
   for range predicates, `ORDER BY … LIMIT` and `min()`/`max()`, and returns wrong rows
   without an error — on 2,000 rows, `max()` returned a value from the middle of the table,
   and a range meant to match 8 rows matched 416; a merge join fails with
   `mergejoin input data is out of order`. Three further defects of the same family:
   `IN (…)` / `= ANY (…)` fail on **every** `tde_btree` index with
   `cache lookup failed for type …`; on `numeric` even `=` misses rows, because the
   comparator is `numeric_cmp` applied to ciphertext (555 of 2,000 values in one test);
   and on `text` with a nondeterministic collation `=` misses rows, because AES-SIV can
   only match identical bytes. Until these are fixed: do not index `numeric` with
   `tde_btree`, use it for single-value `=` lookups only, and for any other query on an
   indexed column `SET enable_indexscan = off` and `SET enable_bitmapscan = off` first.

3. **Logical replication of TOAST columns** (✅ resolved in v1.7): Enable
   `pg_vault_tde.toast_custom_rmgr` (PGC_POSTMASTER, default off) to publish
   externally-TOASTed columns to subscribers. UPDATE/DELETE require
   `REPLICA IDENTITY FULL` **and** a primary key; `REPLICA IDENTITY DEFAULT` and
   PK-less tables remain unsupported (the replica identity would be read from
   ciphertext). See doc/pg_vault_tde.md → "Logical Decoding and Replication".

4. **All-or-nothing table encryption** (→ v1.8): All columns in an `encrypted_heap`
   table are encrypted. Per-column `ENABLE COLUMN ENCRYPTION` DDL is planned for v1.8.

5. **WAL unencrypted** (permanently deferred): Full WAL encryption requires a hook in
   `XLogInsert()` / `XLogWrite()` — not achievable as a PostgreSQL extension.

6. **`WITH HOLD` cursor temporary file is unencrypted** (permanently deferred): PostgreSQL
   materializes a `CURSOR WITH HOLD`'s entire result set into a tuplestore when the declaring
   transaction commits, so the cursor can still be fetched from afterward. Once that result set
   exceeds `work_mem`, the tuplestore spills to a temporary file on disk, and that file is written
   in **plaintext**. The tuplestore is populated directly by the executor, bypassing the table
   access method write path entirely, so `pg_vault_tde` never gets a chance to encrypt the data
   before it reaches disk — there is no extension hook anywhere in the `WITH HOLD` cursor
   lifecycle (parse, plan, portal start, commit-time persist) that can intercept it. This is an
   inherent limit of the extension APIs, not of this implementation: temporary files produced by
   query execution that exceed `work_mem` are not covered by table-level encryption. The spilled
   file can outlive the query that created it — it persists for as long as
   the held cursor remains open, and, like any other PostgreSQL temp file, is not guaranteed to be
   cleaned up if the server crashes before the owning session ends normally.

   **Mitigation:** set `work_mem` large enough that cursor result sets are expected to stay
   in memory, and avoid declaring `WITH HOLD` cursors over queries that touch `encrypted_heap`
   tables (directly or through a view) in memory-constrained environments or wherever the
   result set size can't be bounded in advance.

7. **HOT updates are disabled by design** (so that updating an indexed column always
   maintains the index): On an `encrypted_heap` table `heap_update` never chooses a HOT
   (heap-only) update — every UPDATE writes new index entries, keeping `tde_btree` indexes
   coherent without a `REINDEX`.
   **How:** `heap_update` decides whether an update is HOT by comparing the indexed columns
   between the old and the new tuple, on disk. Both images are encrypted under a fresh
   random GCM IV, so no attribute is byte-stable across an update: `heap_update` sees the
   indexed column as modified and skips the HOT path. The constant `[VERSION | GENERATION]`
   bytes sit at the **end** of the region, outside every attribute, so they cannot create a
   byte-stable window. See [doc/pg_vault_tde.md](doc/pg_vault_tde.md) § Known Limitations for
   the full analysis (including the v3 and v4 bugs this resolved).
   **Operational cost:** every `UPDATE` writes every index and leaves dead entries in all
   of them — vacuum, bloat monitoring and `REINDEX CONCURRENTLY` are covered in
   [Running pg_vault_tde in Production](#running-pg_vault_tde-in-production).

8. **Parallel index build/rebuild is disabled by design**: the parallel workers that
   PostgreSQL uses to build or rebuild an index run in separate processes that are not
   intercepted by the TAM/IAM wrappers, so a parallel worker would read raw ciphertext
   as if it were plaintext. This is disabled via `amcanbuildparallel = false` on
   `tde_btree`.

9. **Only `tde_btree` is an encrypted index AM** (→ v1.8 for GIN/Hash/GiST): `CREATE
   INDEX`/`CREATE UNIQUE INDEX USING gin/gist/hash/brin/btree` against an
   `encrypted_heap` table is rejected with `ERROR` by default, because none of those
   access methods encrypt the key they store — only `tde_btree` (AES-256-SIV) does.
   Set `pg_vault_tde.allow_plaintext_index = on` to allow it anyway (with a
   `WARNING`) when you need trigram/full-text/spatial search or a plain range-scan
   index on an encrypted table and have accepted that the indexed values will sit in
   plaintext on disk in that one index. This has caught out users trying to build a
   `PRIMARY KEY`/`UNIQUE` index as two separate steps (`CREATE UNIQUE INDEX ... USING
   btree` then `ALTER TABLE ... ADD CONSTRAINT ... USING INDEX`, the pattern used with
   `CREATE INDEX CONCURRENTLY`): the first statement fails outright, so the table ends
   up with **no index at all** — not a broken one — and duplicate inserts go through
   unblocked simply because there is nothing left to enforce them. `PRIMARY
   KEY`/`UNIQUE` declared as a normal table constraint (inline in `CREATE TABLE`, or
   `ALTER TABLE ... ADD CONSTRAINT ... PRIMARY KEY (col)` without `USING INDEX`) is
   unaffected by this setting and always works — PostgreSQL core forces those onto a
   native btree index regardless, so pg_vault_tde can only warn about it, never block
   it.

10. **Plain `COPY ... TO` / `pg_dump` produce a plaintext dump, with no warning** (→ v1.8):
    encryption in `pg_vault_tde` lives entirely in the table access method's read
    callbacks (`scan_getnextslot` and friends), which decrypt unconditionally and have
    no way to tell a `SELECT` apart from a `COPY <table> TO ...` — both dispatch through
    the same `table_scan_getnextslot()` call. `pg_dump`'s default table-data path is
    exactly this form of `COPY ... TO stdout`, so a plain `pg_dump` (or a manual
    `COPY sensitive_table TO '/path'`) on an `encrypted_heap` table silently returns
    fully decrypted rows — there is currently no `ProcessUtility_hook` guard or GUC-gated
    `WARNING` for this (a "dump plaintext warning" was designed but never implemented).
    **Mitigation:** always use `pg_dump_tde`/`pg_restore_tde` instead of plain
    `pg_dump`/`pg_restore` for logical backups of encrypted tables — see
    [Encrypted Backups](#encrypted-backups).

---

## Community & Contributing

| | |
|---|---|
| **Report a bug** | [Open a bug report](https://github.com/labmiriade/pg_vault_tde/issues/new?template=bug_report.yml) — check [Known Limitations](https://github.com/labmiriade/pg_vault_tde/wiki/Known-Limitations-and-Troubleshooting) first |
| **Request a feature** | [Open a feature request](https://github.com/labmiriade/pg_vault_tde/issues/new?template=feature_request.yml) |
| **Report a vulnerability** | **Privately** — see [SECURITY.md](SECURITY.md). Never in a public issue. |
| **Contribute code** | [CONTRIBUTING.md](CONTRIBUTING.md) explains the GitHub → Bitbucket mirror review flow |
| **Community standards** | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| **Documentation** | [Project wiki](https://github.com/labmiriade/pg_vault_tde/wiki) |
| **Commercial support** | [Miriade / Mircrypt](https://www.miriade.it/en/products/mircrypt-it) — SLAs, custom development, security audits |

Contributions are welcome from anyone. This project is part of the PostgreSQL
community and holds itself to that community's standards of respectful,
professional technical collaboration.

---

## License


BSD License (PostgreSQL License) — see [LICENSE](LICENSE).

Compatible with MIT, BSD, ISC, and Apache 2.0.
Not derived from any GPL- or AGPL-licensed code.

---

## Copyright

Copyright © 2026 Miriade S.r.l.
