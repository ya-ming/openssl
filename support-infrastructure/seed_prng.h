#ifndef SEED_PRNG_H
#define SEED_PRNG_H
#include <openssl/rand.h>

int seed_prng(int bytes)
{
  if (!RAND_load_file("/dev/urandom", bytes))
    return 0;
  return 1;
}

#endif