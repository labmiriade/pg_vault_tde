# Performance and Tuning

## Overhead vs. Plain Heap

pg_vault_tde adds AES-256-GCM encryption/decryption and IV generation on
every tuple read and write. Expected overhead depends heavily on workload
shape and row size:

| Workload | Typical Overhead | Notes |
|----------|-----------------|-------|
| OLTP (mixed read/write, 100–500 B rows) | **< 15%** | |
| Bulk INSERT (1M rows) | **25–40%** | AES-GCM + random IV generation per tuple |
| Sequential scan (1M rows, read-only) | **20–35%** | Decrypt + palloc copy per tuple |
| Index scan (point lookups) | **< 5%** | Single tuple decrypt per fetch |

These figures assume the **generic** (portable) build; a hardware-accelerated
build closes most of this gap on supported CPUs (see below).

## Hardware Acceleration

pg_vault_tde ships a **generic** package that runs everywhere, plus optional
hardware-accelerated variants. OpenSSL 3.x's EVP/provider dispatch
automatically selects the matching CPU crypto instructions at runtime, once
the binary has been built with the matching compiler intrinsics enabled —
all variants are ABI-compatible and produce a `.so` still named
`pg_vault_tde.so`.

| Variant | Target CPUs | Build flag |
|---------|-------------|------|
| `generic` (default) | All x86-64 / AArch64 | *(none)* |
| `aesni` | Intel Westmere/Core 2010+, AMD Bulldozer+ | `TDE_TARGET_ARCH=x86_64-aesni` |
| `vaes` | AMD Zen 4+, Intel Ice Lake+ (wider vectorized AES) | `TDE_TARGET_ARCH=x86_64-vaes TDE_OPTIMIZE=max` |
| `armce` | AWS Graviton 2/3, Ampere Altra, Apple M-series (ARMv8-A) | `TDE_TARGET_ARCH=aarch64-ce` |
| `sve2` | NVIDIA Grace, Neoverse V2 (ARMv9-A) | `TDE_TARGET_ARCH=aarch64-sve2 TDE_OPTIMIZE=max` |

Building from source:

```bash
make TDE_TARGET_ARCH=x86_64-aesni
make check-cpu     # detect this machine's available CPU crypto extensions
make bench-cpu     # OpenSSL AES throughput microbenchmark
```

Building packages for a specific hardware variant:

```bash
bash packaging/build_in_container.sh --arch-variant aesni
bash packaging/build_in_container.sh --arch-variant vaes
bash packaging/build_in_container.sh --arch-variant armce
bash packaging/build_in_container.sh --arch-variant sve2
```

The ARM Crypto Extensions variant packages as a **separate** `.so`
(`pg_vault_tde_armce.so`) and RPM that can coexist with the generic build on
the same host — see [Installation](Installation) and
[Compatibility and Versioning](Compatibility-and-Versioning).

Confirm which provider is actually active at runtime:

```sql
SELECT * FROM pg_vault_tde_hw_accel_info();
-- (openssl_version, configured_provider, provider_loaded, gcm_cipher, siv_cipher, aes_ni_available)
```

`pg_vault_tde.crypto_provider` selects a specific OpenSSL 3.x provider (e.g.
`qatprovider` for Intel QAT offload, or `fips`); it is `PGC_POSTMASTER` and
requires a restart. Leave it empty for OpenSSL's automatic built-in
dispatch, which is correct for the vast majority of deployments.

## Benchmarking Your Own Workload

```bash
bash bench_tde.sh 100000
```

Runs INSERT, SELECT, UPDATE, index scan, and TABLESAMPLE workloads on a
plain-heap table vs. an `encrypted_heap` table, and prints a side-by-side
overhead comparison.

To isolate pure table-access-method overhead from actual cryptography cost,
you can set `pg_vault_tde.enabled = off` (requires a restart — this GUC is
`PGC_POSTMASTER`) and re-run the benchmark. **Read the warning in
[Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes) first** — never
do this against a database that has real `encrypted_heap` data in it.

The local CI pipeline exposes the same benchmark with configurable row
counts and profiles:

```bash
make ci-bench BENCH_ROWS=100000
```

## Why It's Not Slower Than This

Two design choices keep the per-tuple cost down without any tuning required
on your part:

- **Cached cipher contexts.** Each backend keeps one AES-GCM and one AES-SIV
  cipher context alive for its lifetime, keyed by `(relid, generation)`. The
  expensive AES key-schedule installation only happens on the *first* tuple
  of a relation (or right after a rotation) — every subsequent tuple of the
  same relation reuses the installed schedule and only rearms the IV.
- **Batched random IV generation.** Instead of one `pg_strong_random()`
  syscall per tuple, IVs are generated 256 at a time and drawn from an
  in-memory batch, amortizing the syscall cost across many tuples.

## Buffer Pin Behavior

Decrypting a tuple copies it out of the shared buffer into a freshly
allocated plaintext tuple; the shared buffer pin is held until that copy is
handed off internally, preserving the normal page-at-a-time access pattern
of a sequential scan. In practice this means buffer hit counts for
`encrypted_heap` tables should be comparable to plain heap tables —
proportional to the number of **pages** touched, not the number of rows
returned. If you observe buffer statistics wildly out of line with a
plain-heap baseline, that's a signal to investigate, not expected TDE
overhead.

## See Also
- [Installation](Installation)
- [Compatibility and Versioning](Compatibility-and-Versioning)
- [Encrypted Tables and Indexes](Encrypted-Tables-and-Indexes)
