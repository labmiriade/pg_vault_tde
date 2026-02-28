# AGENTS.md — Subagent Coordination Protocol for pg_vault_tde

> **Purpose**: Define parallel workstreams for AI-assisted development of
> `pg_vault_tde`. Each subagent operates on a distinct module with clear
> boundaries, dependency rules, and validation gates.

---

## Subagent Roster (7 agents + 1 shared role)

| # | Agent ID | Role | Owned Modules | Parallel? |
|---|----------|------|---------------|-----------|
| 1 | **@Coordinator** | Orchestration, gate approval, conflict resolution | `AGENTS.md`, `.github/copilot-instructions.md` | Sequential (gates) |
| 2 | **@Architect** | Database System Architect | `src/tam/`, `src/iam/`, `src/include/pg_vault_tde_tam.h`, `src/include/pg_vault_tde_toast.h`, `src/include/pg_vault_tde_iam.h` | Yes |
| 3 | **@SecurityKMS** | Cryptography & KMS Engineer | `src/crypto/`, `src/kms/`, `src/include/pg_vault_tde_crypto.h`, `src/include/pg_vault_tde_kms.h` | Yes |
| 4 | **@PgCoreDev** | Senior C PostgreSQL Developer | `src/pg_vault_tde.c`, `src/backup/`, `src/include/pg_vault_tde_guc.h`, `Makefile` | Yes |
| 5 | **@QA** | Unit & Regression Testing | `sql/`, `expected/` | Yes |
| 6 | **@IntegrationTest** | Integration, E2E, Performance | `tap/`, `isolation/`, `bench_tde.sh`, `ci/scripts/` | Yes |
| 7 | **@DevOps** | CI/CD & Packaging | `.github/workflows/`, `packaging/`, `Containerfile`, `bitbucket-pipelines.yml` | Yes |
| — | **@DocWriter** (shared) | In-code comments, technical docs | `doc/`, `README.md`, inline comment review across all `.c` files | Parallel with all |

### IAM module ownership

`src/iam/` is **shared** between @Architect (API contract, `amhandler`
registration, callback table) and @SecurityKMS (AES-SIV encrypt/decrypt
logic inside `tde_iam_encrypt_key()` / `tde_iam_decrypt_key()`).

### @DocWriter Shared Role

@DocWriter reviews ALL `.c` and `.h` files for comment quality (pgsql-hackers
style). Any agent may request @DocWriter review via handoff. @DocWriter does
NOT own any `.c` code — only comments and documentation files.

---

## Definition of Done (Per-Agent)

### @Architect — TAM/IAM Callback is "Done" When:
- [ ] Callback compiles with zero warnings (`-Wall -Wextra`)
- [ ] Callback has `PG_TRY/PG_CATCH` on all error paths that hold crypto material or rd_tableam swap
- [ ] `rd_tableam` impersonation (if needed) has guaranteed restore in `PG_CATCH`
- [ ] Corresponding regression test exists in `sql/regression_test.sql`
- [ ] @DocWriter has reviewed function-level comments
- [ ] Callback is listed in the TAM/IAM callback table in `copilot-instructions.md`
- [ ] Callback has `#if PG_VERSION_NUM` guards if signature differs across supported PG versions
- [ ] Version-Specific API Differences table in `copilot-instructions.md` § 0.5 is updated if needed

### @SecurityKMS — Crypto Function is "Done" When:
- [ ] Round-trip test (encrypt → decrypt → compare) passes
- [ ] GCM tag verification failure test exists (tamper detection)
- [ ] `OPENSSL_cleanse` called on all DEK copies before `pfree`
- [ ] `PG_TRY/PG_CATCH` wraps all code between DEK acquisition and cleanse
- [ ] EVP context reuse is correct (`EVP_CIPHER_CTX_reset` between calls)
- [ ] No `RAND_bytes` — only `pg_strong_random`

### @PgCoreDev — Hook/Init Code is "Done" When:
- [ ] `_PG_init` calls hooks in correct order (shmem_request → shmem_startup → TAM init)
- [ ] GUC defaults match README.md documentation
- [ ] Zero compiler warnings
- [ ] Extension loads via `shared_preload_libraries` without crash
- [ ] Builds cleanly against ALL supported PG versions (TDE_PG_MIN .. TDE_PG_MAX)

### @QA — Regression Test is "Done" When:
- [ ] Test is numbered and listed in the test map
- [ ] Test creates `USING encrypted_heap` table
- [ ] Test verifies round-trip (INSERT → SELECT → compare)
- [ ] Test forces specific scan path (if applicable)
- [ ] Expected output file in `expected/` matches
- [ ] Test runs in < 5 seconds

### @IntegrationTest — Integration Test is "Done" When:
- [ ] TAP test follows conventions in `sql/testing.instructions.md`
- [ ] Isolation spec covers at least 2 sessions with explicit permutation
- [ ] `make ci-regress` passes with the new test included
- [ ] `make ci-checksums` passes
- [ ] `make ci-vault` passes (if Vault-related)

### @DevOps — CI/Packaging Change is "Done" When:
- [ ] All 5 CI jobs pass (build, regress, tap, isolation, memcheck)
- [ ] Container build produces working extension
- [ ] Package installs cleanly on target distro
- [ ] CI matrix covers ALL supported PG versions (see § 0.5 Version Registry)
- [ ] Container images are parameterized with `ARG PG_MAJOR` (no hardcoded PG versions)
- [ ] Packaging specs use `%{pgmajorversion}` / `${PG_MAJOR}` variables

### @DocWriter — Documentation is "Done" When:
- [ ] Every exported function has a block comment explaining WHY, not WHAT
- [ ] Every `#define` constant has a comment explaining its derivation
- [ ] `doc/pg_vault_tde.md` reflects current implementation
- [ ] README.md examples are tested and correct

---

## Coordination Rules

### Rule 1: Read Before Write

Before modifying ANY file, every agent MUST read:
1. `.github/copilot-instructions.md` — absolute project laws
2. The relevant `*.instructions.md` file in the target directory
3. All header files in `src/include/` that the target module includes
4. The "Definition of Done" for their agent role (above)

### Rule 2: Interface Contracts Are Immutable Without Consensus

These function signatures are frozen. Changing them requires updating ALL callers:
```c
// Crypto ↔ TAM interface (pg_vault_tde_crypto.h)
HeapTuple tde_encrypt_heap_tuple(HeapTuple plain);
HeapTuple tde_decrypt_heap_tuple(HeapTuple enc);

// KMS ↔ Crypto interface (pg_vault_tde_kms.h)
bool      pg_vault_tde_kms_get_dek(unsigned char *dek_out, int len);
void      pg_vault_tde_kms_set_dek(const unsigned char *dek, int len);
uint64    pg_vault_tde_kms_generation(void);

// TAM decode slot (pg_vault_tde_tam.h) — internal, but called from 7 callbacks
void      pg_vault_tde_decode_slot(TupleTableSlot *slot);

// IAM encrypt/decrypt (pg_vault_tde_iam.h)
bytea    *tde_iam_encrypt_key(const bytea *plainkey);
bytea    *tde_iam_decrypt_key(const bytea *enckey);
```

If an agent needs to change a frozen interface, it MUST:
1. Document the reason in a comment block above the new signature
2. Update ALL call sites across modules
3. Update the corresponding `*.instructions.md` file
4. Add/update regression tests covering the changed path
5. Get @Coordinator approval before merge

### Rule 3: Dependency Direction (DAG — no cycles)

```
src/pg_vault_tde.c  →  src/tam/  →  src/crypto/  →  src/kms/
                        src/iam/  →  src/crypto/  →  src/kms/
```

- `kms/` MUST NOT include headers from `tam/`, `iam/`, or `crypto/`
- `crypto/` MUST NOT include headers from `tam/` or `iam/`
- `tam/` MAY include `crypto/` and `kms/` headers
- `iam/` MAY include `crypto/` and `kms/` headers
- `pg_vault_tde.c` MAY include all project headers (it is the root)

### Rule 4: Header Hygiene

- Constants MUST be defined in exactly ONE header file
- `TDE_DEK_LEN` → `pg_vault_tde_kms.h` only
- `TDE_IV_LEN`, `TDE_TAG_LEN`, `TDE_GCM_OVERHEAD` → `pg_vault_tde_crypto.h` only
- `extern` GUC variables → `pg_vault_tde_guc.h` only
- Never duplicate a `#define` across headers or between a header and a `.c` file

### Rule 5: Validation Before Merge

Every agent's output MUST pass before integration:

| Gate | Command | Owner | Blocks |
|------|---------|-------|--------|
| Compile | `make PG_CONFIG=$(which pg_config)` | @PgCoreDev | All agents |
| Warnings | Verify zero warnings with `-Wall -Wextra` | @PgCoreDev | All agents |
| Regression | `make ci-regress` (24 tests) | @QA | @Architect, @SecurityKMS |
| Checksums | `make ci-checksums` | @QA | @Architect, @SecurityKMS |
| TAP tests | `make ci-tap` | @IntegrationTest | @SecurityKMS (Vault mock) |
| Isolation | `make ci-isolation` | @IntegrationTest | @Architect (concurrency) |
| Vault | `make ci-vault` | @IntegrationTest | @SecurityKMS (Vault connector) |
| Memcheck | Valgrind + ASan (GitHub CI job `memcheck`) | @IntegrationTest | @SecurityKMS (crypto cleanup) |
| Doc review | Comment quality check | @DocWriter | All agents |
| Full local | `make ci-all` | @Coordinator | Final pre-push gate |

### Rule 6: Blast Radius Matrix

Before making a change, check which tests are affected:

| Changed File | Affected Tests | Blast Radius |
|-------------|---------------|--------------|
| `src/crypto/pg_vault_tde_crypto.c` | Tests 1-11, 12-24 (all encrypt/decrypt) | **Critical** — all tests |
| `src/kms/pg_vault_tde_kms.c` | Tests 5-11, 20 (DEK/rotation) | **High** |
| `src/tam/pg_vault_tde_tam.c` | Tests 12-24 (all TAM paths) | **High** |
| `src/tam/pg_vault_tde_toast.c` | Tests 18-19 (COPY, multi-col with TOAST) | **Medium** |
| `src/iam/pg_vault_tde_iam.c` | Test 17 (index scan) | **Low** |
| `src/pg_vault_tde.c` | All tests (extension load) | **Critical** |
| `src/backup/pg_vault_tde_backup.c` | TAP backup tests only | **Low** |

---

## Parallelization Strategy

### Phase 1: Independent Development (Fully Parallel — All 7 Agents)

```
@Architect      ──► TAM callback wiring, TOAST override, rd_tableam workaround
@SecurityKMS    ──► AES-GCM/SIV primitives, IV batching, DEK cache logic
@PgCoreDev      ──► _PG_init, shmem hooks, GUC registration, Makefile
@QA             ──► regression SQL, expected output files
@IntegrationTest──► TAP test framework, isolation specs, bench script
@DevOps         ──► CI pipeline, Containerfile, packaging scripts
@DocWriter      ──► doc/pg_vault_tde.md structure, README.md, comment templates
```

### Phase 2: Integration (3 Sequential Stages, Internally Parallel)

```
Stage 2a (parallel):
  @PgCoreDev completes _PG_init skeleton
  @SecurityKMS completes crypto primitives (standalone unit tests)

Stage 2b (parallel, depends on 2a):
  @SecurityKMS wires KMS shmem init into shmem_startup_hook
  @Architect wires TAM init and registers encrypted_heap AM
      (can work in parallel with KMS — uses mock DEK until KMS is ready)

Stage 2c (parallel, depends on 2b):
  @QA runs full regression suite
  @IntegrationTest runs TAP + isolation
  @DevOps updates CI to match new test targets
  @DocWriter reviews all new code comments
```

### Phase 3: Validation (Fully Parallel)

```
@QA              ──► Regression + expected output verification
@IntegrationTest ──► TAP + isolation + bench + Valgrind/ASan
@DevOps          ──► Container build + CI pipeline dry-run
@SecurityKMS     ──► Crypto self-test (encrypt → decrypt round-trip)
@DocWriter       ──► Final comment quality review
```

---

## Communication Protocol

### Handoff Format

When an agent completes work that another agent depends on, it MUST provide:

```markdown
## Handoff: @SourceAgent → @TargetAgent

**Files modified**: list of changed files
**Interface changes**: any new/changed function signatures
**Test coverage**: which tests cover the change
**Blast radius**: which other tests might be affected
**Definition of Done checklist**: all items checked? (Y/N per item)
**Blockers for next agent**: any known issues or TODOs
```

### Conflict Resolution

If two agents need to modify the same file:
1. The agent whose module OWNS the file has priority
2. The other agent proposes changes as a diff and the owning agent applies them
3. `src/include/*.h` files: whichever agent owns the corresponding `.c` module
4. @Coordinator breaks ties if ownership is unclear

### Error Escalation

If an agent encounters a problem that requires modifying PostgreSQL internals:
1. **STOP** — the plug-and-play mandate forbids core modifications
2. Document the limitation in `doc/pg_vault_tde.md` under "Known Limitations"
3. Find an extension-API workaround (example: `rd_tableam` impersonation pattern)
4. If no workaround exists, add to the Roadmap as "Deferred / Requires PG core patch"
5. @Coordinator must acknowledge the escalation

### @Coordinator — PG Version Audit Workflow

When a new PostgreSQL major version enters beta:

1. @Coordinator creates a "PG N+1 Audit" work item
2. @Architect audits TAM + IAM callbacks (signature and semantic changes)
3. @SecurityKMS audits shmem hooks + crypto API (EVP changes)
4. @PgCoreDev adds `#if PG_VERSION_NUM` guards and updates `TDE_PG_MAX`
5. @DevOps adds PG N+1 to CI matrix, Containerfile, and packaging specs
6. @QA runs full regression on PG N+1
7. @DocWriter updates Version Registry table and compatibility matrix

All 7 steps run **in parallel** where possible (steps 2-4 are independent).
@Coordinator gates merge on all steps passing.

### Status Heartbeat

Each agent MUST report status at the end of each work session:

```markdown
## Status: @AgentName — [TIMESTAMP]

**Phase**: 1/2a/2b/2c/3
**Progress**: X/Y items complete
**Blocked by**: @OtherAgent (if any)
**Next action**: description
```

---

## Module Quick Reference

| Directory | Primary Agent | Secondary | DocWriter? | Purpose |
|-----------|--------------|-----------|------------|---------|
| `src/pg_vault_tde.c` | @PgCoreDev | — | Yes | Entry point, `_PG_init`, hook chain |
| `src/tam/` | @Architect | @PgCoreDev | Yes | TAM callbacks, encrypt/decrypt wiring |
| `src/crypto/` | @SecurityKMS | — | Yes | AES-256-GCM/SIV, IV batch, EVP pool |
| `src/kms/` | @SecurityKMS | — | Yes | Shared-memory DEK cache, Vault HTTP |
| `src/iam/` | @Architect + @SecurityKMS | — | Yes | B-Tree index encryption (AES-SIV) |
| `src/include/` | Per-module owner | — | Yes | Headers (one owner per file) |
| `src/backup/` | @PgCoreDev | @QA | Yes | Backup hook integration |
| `sql/` | @QA | — | No | Regression tests, extension SQL |
| `tap/` | @IntegrationTest | — | No | Perl TAP tests |
| `isolation/` | @IntegrationTest | — | No | Isolation specs for concurrency |
| `packaging/` | @DevOps | — | No | DEB/RPM build scripts and specs |
| `.github/` | @DevOps + @Coordinator | — | No | CI workflows, Copilot instructions |
| `doc/` | @DocWriter | All agents | — | Technical documentation |
