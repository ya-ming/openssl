#include <string.h>
#include <string>
#include <iostream>

#include <openssl/evp.h>

#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>


class KeyAndParameterGenerationTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    KeyAndParameterGenerationTest()
    {
        // You can do set-up work for each test here.
    }

    ~KeyAndParameterGenerationTest() override
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

/*
 * Parameter generation is supported for the following EVP_PKEY types only:
 * EVP_PKEY_EC (for ECDSA and ECDH keys)
 * EVP_PKEY_DSA
 * EVP_PKEY_DH
 */

void generateParam(EVP_PKEY_CTX *&pctx, int type, EVP_PKEY *&params)
{
    /* Create the context for generating the parameters */
    if (!(pctx = EVP_PKEY_CTX_new_id(type, NULL)))
    {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }
    if (!EVP_PKEY_paramgen_init(pctx))
    {
        throw std::runtime_error("EVP_PKEY_paramgen_init failed");
    }

    /* Set the paramgen parameters according to the type */
    switch (type)
    {
    case EVP_PKEY_EC:
        /* Use the NID_X9_62_prime256v1 named curve - defined in obj_mac.h */
        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))
        {
            throw std::runtime_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
        }
        break;

    case EVP_PKEY_DSA:
        /* Set a bit length of 2048 */
        if (!EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, 2048))
        {
            throw std::runtime_error("EVP_PKEY_CTX_set_dsa_paramgen_bits failed");
        }
        break;

    case EVP_PKEY_DH:
        /* Set a prime length of 2048 */
        if (!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048))
        {
            throw std::runtime_error("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed");
        }
    }

    /* Generate parameters */
    if (!EVP_PKEY_paramgen(pctx, &params))
    {
        throw std::runtime_error("EVP_PKEY_paramgen failed");
    }
}

void generateKey(EVP_PKEY_CTX *&kctx, int type, EVP_PKEY *&params, EVP_PKEY *&key)
{
    if (params != NULL)
    {
        if (!(kctx = EVP_PKEY_CTX_new(params, NULL)))
        {
            throw std::runtime_error("EVP_PKEY_CTX_new failed");
        }
    }
    else
    {
        /* Create context for the key generation */
        if (!(kctx = EVP_PKEY_CTX_new_id(type, NULL)))
        {
            throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
        }
    }

    if (!EVP_PKEY_keygen_init(kctx))
    {
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }

    /* RSA keys set the key length during key generation rather than parameter generation! */
    if (type == EVP_PKEY_RSA)
    {
        if (!EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048))
        {
            throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        }
    }

    /* Generate the key */
    if (!EVP_PKEY_keygen(kctx, &key))
    {
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
}

void generateCMACKey(EVP_PKEY_CTX *&kctx, int type, const char *k, EVP_PKEY *&key)
{
    if (!(kctx = EVP_PKEY_CTX_new_id(type, NULL)))
    {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }

    if (!EVP_PKEY_keygen_init(kctx))
    {
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }

    /* Set the cipher to be used for the CMAC */
    if (EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN,
        EVP_PKEY_CTRL_CIPHER,
        0, (void *)EVP_aes_256_ecb()) <= 0)
        if (!EVP_PKEY_keygen_init(kctx))
        {
            throw std::runtime_error("EVP_PKEY_CTX_ctrl cipher failed");
        }

    /* Set the key data to be used for the CMAC */
    if (EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN,
        EVP_PKEY_CTRL_SET_MAC_KEY,
        /*key length*/32, (void *)k) <= 0)
    {
        throw std::runtime_error("EVP_PKEY_CTX_ctrl key failed");
    }

    /* Generate the key */
    if (!EVP_PKEY_keygen(kctx, &key))
    {
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
}

int hmac_it(const unsigned char *msg, size_t mlen, unsigned char **val, size_t *vlen, EVP_PKEY *pkey)
{
    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    size_t req = 0;
    int rc;

    if (!msg || !mlen || !val || !pkey)
        return 0;

    *val = NULL;
    *vlen = 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1) {
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
        goto err;
    }

    *val = (unsigned char *)OPENSSL_malloc(req);
    if (*val == NULL) {
        printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    *vlen = req;
    rc = EVP_DigestSignFinal(ctx, *val, vlen);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
        goto err;
    }

    result = 1;


    err:
    EVP_MD_CTX_free(ctx);
    if (!result) {
        OPENSSL_free(*val);
        *val = NULL;
    }
    return result;
}

TEST_F(KeyAndParameterGenerationTest, GenerateECKey)
{
    auto type = EVP_PKEY_EC;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    generateParam(pctx, type, params);

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;
    generateKey(kctx, type, params, key);

    // cleanup everything but the final key
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);

    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(key);
    BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(bio, ec);
    BIO_flush(bio);

    EC_KEY_free(ec);
    EVP_PKEY_free(key);
}

TEST_F(KeyAndParameterGenerationTest, GenerateDSAKey)
{
    auto type = EVP_PKEY_DSA;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    generateParam(pctx, type, params);

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;
    generateKey(kctx, type, params, key);

    // cleanup everything but the final key
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);

    DSA* dsa = EVP_PKEY_get1_DSA(key);
    BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_DSAPrivateKey(bio, dsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_DSA_PUBKEY(bio, dsa);
    BIO_flush(bio);

    DSA_free(dsa);
    EVP_PKEY_free(key);
}

TEST_F(KeyAndParameterGenerationTest, GenerateDHparams)
{
    auto type = EVP_PKEY_DH;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    generateParam(pctx, type, params);

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *dhParam = NULL;
    generateKey(kctx, type, params, dhParam);

    // cleanup everything but the final dhParam
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);

    DH* dh = EVP_PKEY_get1_DH(dhParam);
    BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_DHparams(bio, dh);
    BIO_flush(bio);

    DH_free(dh);
    EVP_PKEY_free(dhParam);
}

TEST_F(KeyAndParameterGenerationTest, GenerateCMAC)
{
    auto type = EVP_PKEY_CMAC;

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;

    // 32 bytes
    const char *k = "01234567890123456789012345678901";

    generateCMACKey(kctx, type, k, key);

    // cleanup everything but the final key
    EVP_PKEY_CTX_free(kctx);

    unsigned char *msg = (unsigned char *)"message to be cmac hashed";
    unsigned char *cmac;
    size_t cmac_len;

    hmac_it((const unsigned char *)msg, strlen((const char *)msg), &cmac, &cmac_len, key);

    printf("CMAC is:\n");
    BIO_dump_fp(stdout, (const char *)cmac, cmac_len);

    EVP_PKEY_free(key);
    if (cmac)
        OPENSSL_free(cmac);
}

TEST_F(KeyAndParameterGenerationTest, GenerateHMAC)
{
    auto key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, (const unsigned char*)"password", strlen("password"));

    unsigned char *msg = (unsigned char *)"message to be hmac hashed";
    unsigned char *hmac;
    size_t hmac_len;

    hmac_it((const unsigned char *)msg, strlen((const char *)msg), &hmac, &hmac_len, key);

    printf("HMAC is:\n");
    BIO_dump_fp(stdout, (const char *)hmac, hmac_len);

    EVP_PKEY_free(key);
    if (hmac)
        OPENSSL_free(hmac);
}
