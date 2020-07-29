#include <openssl/rand.h>
#include <stdio.h>

int seed_prng(int bytes)
{
  if (!RAND_load_file("/dev/urandom", bytes))
    return 0;
  return 1;
}

int main()
{
  /* Read 1024 bytes from /dev/random and seed the PRNG with it */
  // /dev/random is very slow, use /dev/urandom instead
  RAND_load_file("/dev/urandom", 1024);

  /* Write a seed file */
  RAND_write_file("prngseed.dat");

  /* Read the seed file in its entirety and print the number of bytes obtained */
  int nb = RAND_load_file("prngseed.dat", -1);
  printf("Seeded the PRNG with %d byte(s) of data from prngseed.dat.\n", nb);
}