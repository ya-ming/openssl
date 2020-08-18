#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <gtest/gtest.h>

class KeyDerivationTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    KeyDerivationTest()
    {
        // You can do set-up work for each test here.
    }

    ~KeyDerivationTest() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override
    {
        // Code here will be called immediately after the constructor (right
        // before each test).
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).
    }

    // Class members declared here can be used by all tests in the test suite
    // for SymmetricCipher.
};

TEST_F(KeyDerivationTest, HKDF)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char derived[32];
    OSSL_PARAM params[5], *p = params;

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
        printf("EVP_KDF_fetch");
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);    /* The kctx keeps a reference so this is safe */
    if (kctx == NULL) {
        printf("EVP_KDF_CTX_new");
    }

    /* Build up the parameters for the derivation */
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "sha256", (size_t)7);
    *p++ = OSSL_PARAM_construct_octet_string("salt", (void *)"salt", (size_t)4);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void *)"secret", (size_t)6);
    *p++ = OSSL_PARAM_construct_octet_string("info", (void *)"label", (size_t)5);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        printf("EVP_KDF_CTX_set_params");
    }

    /* Do the derivation */
    if (EVP_KDF_derive(kctx, derived, sizeof(derived)) <= 0) {
        printf("EVP_KDF_derive");
    }

    /* Use the 32 bytes as a Key and IV */
    const unsigned char *key = derived+0;
    const unsigned char  *iv = derived+16;
  
    printf("Key: ");
    for (size_t i=0; i<16; ++i)
        printf("%02x ", key[i]);
    printf("\n");

    printf("IV:  ");
    for (size_t i=0; i<16; ++i)
        printf("%02x ", iv[i]);
    printf("\n");

    EVP_KDF_CTX_free(kctx);
}