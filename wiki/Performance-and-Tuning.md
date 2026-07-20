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

These figures were measured on pg_vault_tde's one and only build, which
already gets OpenSSL's automatic hardware-accelerated AES dispatch on
supported CPUs (see below).

## Hardware Acceleration

pg_vault_tde ships a single package for each (format, PostgreSQL major)
combination — there is no CPU-specific build variant. Hardware-accelerated
AES (AES-NI, VAES, ARM Crypto Extensions, SVE2) is provided automatically at
runtime by OpenSSL 3.x's EVP/provider layer, based on the CPU the server is
actually running on. This is a property of the OpenSSL library installed on
the host, not of how pg_vault_tde.so was compiled: pg_vault_tde never
implements AES itself, it only calls OpenSSL's EVP API
(`src/crypto/pg_vault_tde_hw_accel.c`), so there is nothing a CPU-specific
compile flag could speed up.

```bash
make check-cpu     # detect this machine's available CPU crypto extensions
make bench-cpu     # OpenSSL AES throughput microbenchmark
```

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
