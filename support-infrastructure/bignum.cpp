#include <openssl/bn.h>
#include <string.h>
#include <stdio.h>

static void prime_status(int code, int arg, void *cb_arg)
{
  if (code == 0)
    printf("\n * Found potential prime #%d ...", (arg + 1));
  else if (code == 1 && arg && !(arg % 10))
    printf(".");
  else
    printf("\n Got one!\n");
}

BIGNUM *generate_prime(int bits, int safe)
{
  char *str;
  BIGNUM *prime;
  printf("Searching for a %sprime %d bits in size ...", (safe ? "safe " : ""),
         bits);
  prime = BN_generate_prime(NULL, bits, safe, NULL, NULL,
                            prime_status, NULL);
  if (!prime)
    return NULL;
  str = BN_bn2dec(prime);
  if (str)
  {
    printf("Found prime: %s\n", str);
    OPENSSL_free(str);
  }
  return prime;
}

int main()
{
  BIGNUM *bn1, *bn2, *bn3;

  bn1 = BN_new();

  unsigned char num[] = "1234567890123456789012345678901234567890";
  bn2 = BN_bin2bn(num, strlen((const char *)num), NULL);

  printf("%s\n", BN_bn2hex(bn2));
  printf("%s\n", BN_bn2dec(bn2));

  unsigned char num3[] = "1";
  bn3 = BN_bin2bn(num3, strlen((const char *)num3), NULL);
  printf("%s\n", BN_bn2dec(bn3));
  BN_add(bn3, bn2, bn3);
  printf("%s\n", BN_bn2dec(bn3));

  BIGNUM *p = generate_prime(128, 1);
  printf("%s\n", BN_bn2dec(p));

  BN_free(bn1);
  BN_free(bn2);
  BN_free(bn3);
  BN_free(p);
}