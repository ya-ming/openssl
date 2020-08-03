#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <openssl/provider.h>

int do_crypt(char *outfile)
{
    OSSL_PROVIDER *legacy;
    OSSL_PROVIDER *deflt;

    /* Load Multiple providers into the default (NULL) library context */
    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (legacy == NULL)
    {
        printf("Failed to load Legacy provider\n");
        exit(EXIT_FAILURE);
    }
    deflt = OSSL_PROVIDER_load(NULL, "default");
    if (deflt == NULL)
    {
        printf("Failed to load Default provider\n");
        OSSL_PROVIDER_unload(legacy);
        exit(EXIT_FAILURE);
    }
    unsigned char outbuf[1024];
    int outlen, tmplen;
    /*
      * Bogus key and IV: we'd normally set these from
      * another source.
      */
    unsigned char key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    unsigned char iv[] = {1, 2, 3, 4, 5, 6, 7, 8};
    char intext[] = "Some Crypto Text";
    EVP_CIPHER_CTX *ctx;
    FILE *out;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_bf_ofb(), NULL, key, iv);

    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, (const unsigned char *)intext, strlen(intext)))
    {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    /*
      * Buffer passed to EVP_EncryptFinal() must be after data just
      * encrypted to avoid overwriting it.
      */
    if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen))
    {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    /*
      * Need binary mode for fopen because encrypted data is
      * binary data. Also cannot use strlen() on it because
      * it won't be NUL terminated and may contain embedded
      * NULs.
      */
    out = fopen(outfile, "wb");
    if (out == NULL)
    {
        /* Error */
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);
    fclose(out);

    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    return 1;
}

int main()
{
    do_crypt("encrypted.dat");
}