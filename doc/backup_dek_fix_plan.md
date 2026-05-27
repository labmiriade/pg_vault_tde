# Piano di Risoluzione: Bug Backup DEK Mismatch

**Data**: 2026-05-26  
**Versione target**: v1.7  
**Priorità**: 🔥 **CRITICA** — security vulnerability  
**Autore**: @SecurityKMS + @Architect  

---

## 📋 Executive Summary

Il modulo backup (`src/backup/pg_vault_tde_backup.c`) presenta **3 bug critici** e **1 vulnerability**:

1. ❌ **DEK Mismatch**: `tde_backup_header_init()` genera una nuova `backup_dek` e la wrappa nel header, ma `tde_backup_encrypt_block()` usa la DEK globale dallo shmem → **il backup è cifrabile MA NON decifrabile** con la chiave wrappata
2. ❌ **Const buffer modificabili**: `const char backup_dek[32]` viene passato a `generate_dek()` che ci scrive → comportamento indefinito
3. ❌ **Cleanse dopo error**: `ereport(ERROR)` fa longjmp, il cleanse successivo non viene mai eseguito
4. ⚠️ **Tipo sbagliato**: `char` invece di `unsigned char` per materiale crittografico

---

## 🔍 Analisi del Problema

### Flusso Corrente (ERRATO)

```
1. tde_backup_header_init(hdr)
   ├─ generate_dek(backup_dek)           ← genera DEK_A (32 byte random)
   ├─ wrap_dek(backup_dek, wrapped_dek)  ← wrappa DEK_A con KEK di Vault
   ├─ memcpy(hdr->wrapped_dek, ...)      ← salva DEK_A wrappata nel header
   └─ OPENSSL_cleanse(backup_dek)        ← pulisce DEK_A
   
2. pg_dump stream loop:
   for each 64KB block:
       tde_backup_encrypt_block(block_data, ...)
       └─ tde_gcm_encrypt(InvalidOid, block_data, ...)
          └─ pg_vault_tde_kms_get_dek(dek_out, ...)  ← legge DEK_B dallo shmem!
             └─ encrypt with DEK_B                    ← DIVERSA DA DEK_A

3. pg_restore:
   ├─ unwrap_dek(hdr->wrapped_dek) → recupera DEK_A
   └─ tde_gcm_decrypt(block, ...)  → tenta di decifrare con DEK_A
      └─ GCM authentication FAIL   ← era cifrato con DEK_B!
```

### Perché è Critico

- **I backup esistenti sono IRRECUPERABILI** se il file è stato generato con questo codice
- **Non è rilevabile in test superficiali** — serve un full round-trip (dump → restore → verify)
- **Viola il principio di Kerckhoffs**: la sicurezza dipende dalla segretezza della chiave, ma qui stiamo wrappando la chiave sbagliata

---

## 🎯 Soluzione Raccomandata

### Opzione 1: Low-Level Crypto API con DEK Esplicita ✅

**Rationale**: Separare le responsabilità:
- `tde_gcm_encrypt(relid, ...)` → per TAM/IAM (usa DEK da shmem/catalog)
- `tde_gcm_encrypt_with_dek(dek, ...)` → per backup/special-cases (usa DEK esplicita)

**Pro**:
- ✅ Minimizza il blast radius (solo crypto module + backup module)
- ✅ Lascia il TAM/IAM code path invariato
- ✅ Consente test unitari isolati (non serve shmem per testare backup crypto)
- ✅ Segue il pattern PostgreSQL per funzioni "dual mode" (es. `SPI_execute` vs `SPI_execute_with_args`)

**Contro**:
- ⚠️ Aggiunge 2 nuove funzioni pubbliche all'API crypto (minore)

---

## 🛠️ Implementation Plan

### Fase 1: Aggiungere Low-Level Crypto API

#### 1.1 Header (`src/include/pg_vault_tde_crypto.h`)

```c
/*
 * Low-level encrypt/decrypt with explicit DEK.
 * Used by backup module and test utilities.
 * Produces v2 wire format (no AAD, no relid binding).
 * Caller MUST cleanse output: OPENSSL_cleanse + pfree.
 */
char *tde_gcm_encrypt_with_dek(const unsigned char *dek, int dek_len,
                                const char *plaintext, Size plaintext_len,
                                Size *out_len);

char *tde_gcm_decrypt_with_dek(const unsigned char *dek, int dek_len,
                                const char *ciphertext, Size ciphertext_len,
                                Size *out_len);
```

#### 1.2 Implementazione (`src/crypto/pg_vault_tde_crypto.c`)

```c
/*
 * tde_gcm_encrypt_with_dek
 *
 * Low-level encrypt primitive with caller-provided DEK.
 * Wire format: [VERSION(1=0x02) | GENERATION(8=0) | IV(12) | CT | TAG(16)]
 * Generation is always 0 (backup DEKs are ephemeral, not rotatable).
 */
char *
tde_gcm_encrypt_with_dek(const unsigned char *dek, int dek_len,
                          const char *plaintext, Size plaintext_len,
                          Size *out_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char   iv[TDE_GCM_IV_LEN];
    unsigned char   tag[TDE_GCM_TAG_LEN];
    char           *output;
    char           *ct_ptr;
    int             ct_len, final_len;
    Size            total_len;
    uint64          generation = 0;  /* backup DEKs have no generation */

    Assert(dek != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(plaintext != NULL);
    Assert(out_len != NULL);

    /* Generate IV */
    if (!pg_strong_random(iv, TDE_GCM_IV_LEN))
        ereport(ERROR, (errmsg("Failed to generate IV for backup encryption")));

    /* Allocate output: [VERSION(1) | GEN(8) | IV(12) | CT(plaintext_len) | TAG(16)] */
    total_len = TDE_V2_OVERHEAD + plaintext_len;
    output = palloc(total_len);

    /* Assemble header */
    output[0] = TDE_V2_VERSION_BYTE;
    memcpy(output + 1, &generation, TDE_V2_GEN_LEN);
    memcpy(output + 1 + TDE_V2_GEN_LEN, iv, TDE_GCM_IV_LEN);
    ct_ptr = output + 1 + TDE_V2_GEN_LEN + TDE_GCM_IV_LEN;

    /* Init EVP context (new allocation — backup is not hot-path) */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        ereport(ERROR, (errmsg("EVP_CIPHER_CTX_new failed")));

    PG_TRY();
    {
        /* Init AES-256-GCM */
        if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), dek, iv, NULL) != 1)
            ereport(ERROR, (errmsg("EVP_EncryptInit_ex2 failed")));

        /* Encrypt plaintext */
        if (EVP_EncryptUpdate(ctx, (unsigned char *)ct_ptr, &ct_len,
                              (const unsigned char *)plaintext, plaintext_len) != 1)
            ereport(ERROR, (errmsg("EVP_EncryptUpdate failed")));

        /* Finalize */
        if (EVP_EncryptFinal_ex(ctx, (unsigned char *)(ct_ptr + ct_len), &final_len) != 1)
            ereport(ERROR, (errmsg("EVP_EncryptFinal_ex failed")));

        /* Extract GCM tag */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TDE_GCM_TAG_LEN, tag) != 1)
            ereport(ERROR, (errmsg("Failed to extract GCM tag")));

        /* Append tag */
        memcpy(ct_ptr + ct_len + final_len, tag, TDE_GCM_TAG_LEN);

        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(iv, TDE_GCM_IV_LEN);
        OPENSSL_cleanse(tag, TDE_GCM_TAG_LEN);

        *out_len = total_len;
        return output;
    }
    PG_CATCH();
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(iv, TDE_GCM_IV_LEN);
        OPENSSL_cleanse(tag, TDE_GCM_TAG_LEN);
        pfree(output);
        PG_RE_THROW();
    }
    PG_END_TRY();
}

/*
 * tde_gcm_decrypt_with_dek
 *
 * Decrypt a buffer produced by tde_gcm_encrypt_with_dek.
 * Expects v2 wire format. GCM tag MUST verify or ereport(ERROR).
 */
char *
tde_gcm_decrypt_with_dek(const unsigned char *dek, int dek_len,
                          const char *ciphertext, Size ciphertext_len,
                          Size *out_len)
{
    EVP_CIPHER_CTX     *ctx = NULL;
    const unsigned char *iv_ptr;
    const unsigned char *ct_ptr;
    const unsigned char *tag_ptr;
    char               *plaintext;
    Size                ct_len;
    int                 pt_len, final_len;
    uint64              generation;

    Assert(dek != NULL);
    Assert(dek_len == TDE_DEK_LEN);
    Assert(ciphertext != NULL);
    Assert(out_len != NULL);

    /* Parse v2 header */
    if (ciphertext_len < TDE_V2_OVERHEAD)
        ereport(ERROR, (errmsg("Backup ciphertext too short")));

    if ((unsigned char)ciphertext[0] != TDE_V2_VERSION_BYTE)
        ereport(ERROR, (errmsg("Invalid backup wire format version: %d",
                                (unsigned char)ciphertext[0])));

    memcpy(&generation, ciphertext + 1, TDE_V2_GEN_LEN);
    iv_ptr = (const unsigned char *)(ciphertext + 1 + TDE_V2_GEN_LEN);
    ct_ptr = iv_ptr + TDE_GCM_IV_LEN;
    ct_len = ciphertext_len - TDE_V2_OVERHEAD;
    tag_ptr = ct_ptr + ct_len;

    plaintext = palloc(ct_len);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        ereport(ERROR, (errmsg("EVP_CIPHER_CTX_new failed")));

    PG_TRY();
    {
        if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), dek, iv_ptr, NULL) != 1)
            ereport(ERROR, (errmsg("EVP_DecryptInit_ex2 failed")));

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TDE_GCM_TAG_LEN,
                                (void *)tag_ptr) != 1)
            ereport(ERROR, (errmsg("Failed to set GCM tag")));

        if (EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &pt_len,
                              ct_ptr, ct_len) != 1)
            ereport(ERROR, (errmsg("EVP_DecryptUpdate failed")));

        /* GCM tag verification happens here — MUST return 1 */
        if (EVP_DecryptFinal_ex(ctx, (unsigned char *)(plaintext + pt_len),
                                &final_len) != 1)
            ereport(ERROR, (errmsg("GCM authentication failed — backup corrupted or wrong DEK")));

        EVP_CIPHER_CTX_free(ctx);

        *out_len = pt_len + final_len;
        return plaintext;
    }
    PG_CATCH();
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(plaintext, ct_len);
        pfree(plaintext);
        PG_RE_THROW();
    }
    PG_END_TRY();
}
```

---

### Fase 2: Correggere `tde_backup_header_init()`

#### 2.1 Modifiche a `src/backup/pg_vault_tde_backup.c`

```c
bool
tde_backup_header_init(tde_backup_header *hdr, 
                        unsigned char *backup_dek_out)  /* ← NUOVO parametro */
{
    unsigned char backup_dek[TDE_DEK_LEN];        /* rimosso const */
    unsigned char wrapped_dek[TDE_BACKUP_WRAPPED_LEN];  /* rimosso const */

    Assert(hdr != NULL);
    Assert(backup_dek_out != NULL);

    memcpy(hdr->magic, TDE_BACKUP_MAGIC, TDE_BACKUP_MAGIC_LEN);
    hdr->format_version = TDE_BACKUP_FORMAT_VERSION;

    PG_TRY();
    {
        /* Genera DEK per il backup (non usare shmem DEK!) */
        if (!tde_active_kms_provider->generate_dek(backup_dek, TDE_DEK_LEN))
            ereport(ERROR, (errmsg("[BACKUP] Failed to generate backup DEK")));

        /* Wrappa la DEK con la KEK di Vault */
        if (!tde_active_kms_provider->wrap_dek(backup_dek, TDE_DEK_LEN,
                                                wrapped_dek, TDE_BACKUP_WRAPPED_LEN))
            ereport(ERROR, (errmsg("[BACKUP] Failed to wrap backup DEK")));

        /* Genera IV per lo stream (diverso per ogni backup) */
        if (!pg_strong_random(hdr->stream_iv, TDE_GCM_IV_LEN))
            ereport(ERROR, (errmsg("[BACKUP] Failed to generate backup stream IV")));

        /* Salva wrapped DEK nel header */
        memcpy(hdr->wrapped_dek, wrapped_dek, TDE_BACKUP_WRAPPED_LEN);
        hdr->wrapped_dek_len = TDE_BACKUP_WRAPPED_LEN;

        /* Restituisci DEK in chiaro al caller (per encrypt_block) */
        memcpy(backup_dek_out, backup_dek, TDE_DEK_LEN);
    }
    PG_CATCH();
    {
        OPENSSL_cleanse(backup_dek, TDE_DEK_LEN);
        OPENSSL_cleanse(wrapped_dek, TDE_BACKUP_WRAPPED_LEN);
        PG_RE_THROW();
    }
    PG_END_TRY();

    /* Pulisci copie locali (il caller gestirà backup_dek_out) */
    OPENSSL_cleanse(backup_dek, TDE_DEK_LEN);
    OPENSSL_cleanse(wrapped_dek, TDE_BACKUP_WRAPPED_LEN);

    return true;
}
```

#### 2.2 Modifiche a `tde_backup_encrypt_block()`

```c
void
tde_backup_encrypt_block(const unsigned char *backup_dek,  /* ← NUOVO */
                          const char *block_data, Size block_len,
                          uint64 block_seq,
                          char *out_buf, Size *out_len)
{
    char   *encrypted;
    Size    enc_len;

    Assert(backup_dek != NULL);
    Assert(block_data != NULL && out_buf != NULL && out_len != NULL);
    Assert(block_len > 0 && block_len <= TDE_BACKUP_BLOCK_SIZE);

    /*
     * TODO (v1.7): Pass block_seq as GCM AAD to prevent block reordering attacks.
     * Current implementation: block_seq is logged but not cryptographically bound.
     */

    /* Usa la DEK del backup, NON la DEK globale */
    encrypted = tde_gcm_encrypt_with_dek(backup_dek, TDE_DEK_LEN,
                                          block_data, block_len, &enc_len);

    memcpy(out_buf, encrypted, enc_len);
    *out_len = enc_len;

    OPENSSL_cleanse(encrypted, enc_len);
    pfree(encrypted);
}
```

#### 2.3 Aggiornare Header (`src/include/pg_vault_tde_backup.h`)

```c
/* Restituisce backup_dek_out al caller per usarla in encrypt_block */
bool tde_backup_header_init(tde_backup_header *hdr,
                              unsigned char *backup_dek_out);

/* Ora richiede backup_dek esplicita */
void tde_backup_encrypt_block(const unsigned char *backup_dek,
                                const char *block_data, Size block_len,
                                uint64 block_seq,
                                char *out_buf, Size *out_len);
```

---

### Fase 3: Aggiornare Caller (pg_dump_tde Utility — TODO in v1.7)

**NOTA**: Il tool `pg_dump_tde` non esiste ancora nel codebase corrente.  
Questo è un placeholder per quando verrà implementato.

```c
/* Pseudocodice del caller in pg_dump_tde.c */
void
backup_main(FILE *pg_dump_pipe, FILE *output_file)
{
    tde_backup_header    hdr;
    unsigned char        backup_dek[TDE_DEK_LEN];
    char                 block_buf[TDE_BACKUP_BLOCK_SIZE];
    char                 enc_buf[TDE_BACKUP_BLOCK_SIZE + TDE_V2_OVERHEAD];
    Size                 enc_len;
    uint64               block_seq = 0;

    /* Init header + ottieni backup DEK */
    if (!tde_backup_header_init(&hdr, backup_dek))
        ereport(ERROR, (errmsg("Failed to init backup header")));

    /* Scrivi header nel file */
    fwrite(&hdr, sizeof(tde_backup_header), 1, output_file);

    PG_TRY();
    {
        /* Loop su blocchi da 64KB */
        while (fread(block_buf, 1, TDE_BACKUP_BLOCK_SIZE, pg_dump_pipe) > 0)
        {
            tde_backup_encrypt_block(backup_dek,  /* ← passa DEK esplicita */
                                      block_buf, bytes_read,
                                      block_seq++,
                                      enc_buf, &enc_len);

            fwrite(enc_buf, 1, enc_len, output_file);
        }
    }
    PG_CATCH();
    {
        OPENSSL_cleanse(backup_dek, TDE_DEK_LEN);
        PG_RE_THROW();
    }
    PG_END_TRY();

    /* Pulisci DEK al termine */
    OPENSSL_cleanse(backup_dek, TDE_DEK_LEN);
}
```

---

## 🧪 Testing Plan

### Test 1: Unit Test Crypto API

**File**: `sql/regression_test_backup.sql` (NUOVO)

```sql
-- Test 1: Encrypt/decrypt round-trip con DEK esplicita
SELECT pg_vault_tde_test_encrypt_decrypt_with_dek(
    'hello world'::bytea,
    decode('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF', 'hex')  -- fake DEK
);

-- Expected: true (round-trip success)
```

Implementare funzione SQL-callable per test:
```c
PG_FUNCTION_INFO_V1(pg_vault_tde_test_encrypt_decrypt_with_dek);
Datum
pg_vault_tde_test_encrypt_decrypt_with_dek(PG_FUNCTION_ARGS)
{
    /* ... usa tde_gcm_encrypt_with_dek + tde_gcm_decrypt_with_dek ... */
}
```

### Test 2: Backup Header Init

```sql
-- Test 2: Header init restituisce DEK diversa dalla shmem DEK
SELECT pg_vault_tde_test_backup_header_init();

-- Expected output:
-- backup_dek != shmem_dek: true
-- wrapped_dek_len == 512: true
```

### Test 3: Full Backup Round-Trip (TAP Test)

**File**: `tap/t/03_backup_encrypt.pl` (NUOVO)

```perl
# Test completo:
# 1. Init header → ottieni backup_dek
# 2. Encrypt 3 blocchi con backup_dek
# 3. Unwrap DEK dal header
# 4. Decrypt 3 blocchi con unwrapped DEK
# 5. Verifica plaintext == original

my $header = $node->safe_psql('postgres', 
    "SELECT pg_vault_tde_test_backup_init_and_encrypt()");

ok($header->{wrapped_dek_len} == 512, "wrapped DEK length correct");
ok($header->{decrypted_matches}, "Full backup round-trip success");
```

### Test 4: Regression Negativa (Wrong DEK Detection)

```sql
-- Test 4: Decrypt con DEK sbagliata deve fallire con GCM error
SELECT pg_vault_tde_test_decrypt_with_wrong_dek();

-- Expected: ERROR: GCM authentication failed
```

---

## 📊 Definition of Done

### @SecurityKMS (Crypto Module)
- [ ] `tde_gcm_encrypt_with_dek()` implementato con v2 wire format
- [ ] `tde_gcm_decrypt_with_dek()` implementato con GCM tag verification
- [ ] Unit test round-trip passa (Test 1)
- [ ] Zero compiler warnings con `-Wall -Wextra`
- [ ] `OPENSSL_cleanse` su tutti i path (success + error)
- [ ] @DocWriter ha rivisto i commenti

### @Architect (Backup Module)
- [ ] `tde_backup_header_init()` corretto:
  - [ ] `const` rimosso dai buffer
  - [ ] `PG_TRY/PG_CATCH` avvolge generate + wrap + random
  - [ ] Restituisce `backup_dek_out` al caller
- [ ] `tde_backup_encrypt_block()` usa `tde_gcm_encrypt_with_dek()`
- [ ] Header file aggiornato con nuove signature
- [ ] Test 2 passa (backup_dek != shmem_dek)

### @QA (Regression Tests)
- [ ] `sql/regression_test_backup.sql` creato con 4 test
- [ ] Expected output in `expected/regression_test_backup.out`
- [ ] `make ci-regress` passa con nuovi test
- [ ] Test 4 verifica che wrong DEK → GCM error

### @IntegrationTest (TAP Tests)
- [ ] `tap/t/03_backup_encrypt.pl` implementato
- [ ] Mock Vault provider per test wrap/unwrap
- [ ] Full round-trip test passa (Test 3)
- [ ] `make ci-tap` passa

### @DevOps (CI/CD)
- [ ] CI pipeline esegue nuovi test backup
- [ ] Zero regression sui test esistenti
- [ ] Performance: encrypt_with_dek overhead < 5% vs encrypt (benchmark con `bench_tde.sh`)

### @DocWriter (Documentation)
- [ ] `doc/pg_vault_tde.md` § Backup aggiornato con nuovo flusso
- [ ] Ogni funzione ha comment block "WHY, not WHAT"
- [ ] README.md § Backup Usage aggiornato
- [ ] Questo file (`backup_dek_fix_plan.md`) archiviato in `doc/archive/` quando completato

---

## 🚨 Rollback Plan

Se dopo il merge emergono problemi critici:

1. **Revert commit immediato**: l'API crypto esistente (`tde_gcm_encrypt`) è invariata, quindi TAM/IAM continuano a funzionare
2. **Disable backup feature**: Aggiungere GUC `pg_vault_tde.enable_backup = off` (default `off` fino a stabilizzazione)
3. **Hot-patch**: Se un backup è stato generato con il codice buggy, NON è recuperabile — richiedere re-dump

---

## 🔗 Cross-References

| File Modified | Module | Agent Owner |
|--------------|--------|-------------|
| `src/crypto/pg_vault_tde_crypto.c` | Crypto | @SecurityKMS |
| `src/crypto/pg_vault_tde_crypto.h` | Crypto API | @SecurityKMS |
| `src/backup/pg_vault_tde_backup.c` | Backup | @Architect |
| `src/backup/pg_vault_tde_backup.h` | Backup API | @Architect |
| `sql/regression_test_backup.sql` | Tests | @QA |
| `tap/t/03_backup_encrypt.pl` | TAP | @IntegrationTest |

---

## 📅 Timeline

| Fase | Durata Stimata | Dipendenze |
|------|----------------|------------|
| Fase 1 (Crypto API) | 2 giorni | Nessuna |
| Fase 2 (Backup Fix) | 1 giorno | Fase 1 |
| Fase 3 (Caller Update) | DEFERRED | pg_dump_tde tool (v1.7 milestone) |
| Testing (Unit + TAP) | 2 giorni | Fase 1 + 2 |
| Code Review + Doc | 1 giorno | Fase 1 + 2 + Testing |
| **TOTALE** | **6 giorni** | — |

---

## ✅ Sign-off

Questo piano sarà considerato APPROVATO quando:
- [ ] @Coordinator ha rivisto e approved
- [ ] @SecurityKMS ha confermato fattibilità crypto
- [ ] @Architect ha confermato fattibilità backup module
- [ ] @QA ha confermato testabilità

**Status**: 🟡 DRAFT — in attesa di approval

---

**END OF DOCUMENT**
