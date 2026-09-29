void
done(char *passphrase, char *new_pass, char *path, unsigned char *dek)
{
    // ruleid: tde-cleanse-before-free
    pfree(passphrase);
    OPENSSL_cleanse(new_pass, strlen(new_pass));
    // ok: tde-cleanse-before-free
    pfree(new_pass);
    // ok: tde-cleanse-before-free
    pfree(path);
    // ruleid: tde-cleanse-before-free
    free(dek);
}
