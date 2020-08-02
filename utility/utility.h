#ifndef UTILITY_H
#define UTILITY_H

void select_random_key(unsigned char *key, int b)
{
    int i;

    RAND_bytes(key, b);
    for (i = 0; i < b - 1; i++)
    {
        printf("%02X:", key[i]);
    }
    printf("%02X:\n", key[i]);
}

void select_random_iv(unsigned char *iv, int b)
{
    RAND_pseudo_bytes(iv, b);
}

#endif