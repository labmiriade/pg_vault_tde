int
verify(const unsigned char *hmac, const unsigned char *expected_mac, const char *name)
{
    // ruleid: tde-constant-time-compare
    if (memcmp(hmac, expected_mac, 32) != 0)
        return 0;
    // ruleid: tde-constant-time-compare
    if (memcmp(buf + off, tag, TDE_GCM_TAG_LEN) != 0)
        return 0;
    // ok: tde-constant-time-compare
    if (CRYPTO_memcmp(hmac, expected_mac, 32) != 0)
        return 0;
    // ok: tde-constant-time-compare
    if (strcmp(name, "local") == 0)
        return 1;
    return 1;
}
