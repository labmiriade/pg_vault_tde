void
fill(unsigned char *iv, int len)
{
    // ruleid: tde-strong-random
    RAND_bytes(iv, len);
    // ruleid: tde-strong-random
    RAND_priv_bytes(iv, len);
    // ruleid: tde-strong-random
    iv[0] = rand();
    // ok: tde-strong-random
    if (!pg_strong_random(iv, len))
        elog(ERROR, "RAND_bytes is not what failed");
}
