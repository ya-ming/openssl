#include <openssl/rand.h>
#include <memory.h>

#ifndef DEVRANDOM_EGD
#define DEVRANDOM_EGD "/var/run/egd-pool", "/dev/egd-pool", "/etc/egd-pool", "/etc/entropy"
#endif
int seed_prng(int bytes)
{
  int i;
  char *names[] = {DEVRANDOM_EGD, NULL};
  for (i = 0; names[i]; i++)
    // can't compile because no configured
    if (RAND_egd(names[i]) != -1) /* RAND_egd_bytes(names[i],255) */
      return 1;
  return 0;
}