-- pg_vault_tde_init.sql
-- Test di base: caricamento estensione
CREATE EXTENSION pg_vault_tde;
-- Verifica che l'estensione sia caricata
SELECT extname FROM pg_extension WHERE extname = 'pg_vault_tde';
