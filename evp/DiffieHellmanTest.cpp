#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <gtest/gtest.h>

class DiffieHellmanTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    DiffieHellmanTest()
    {
        // You can do set-up work for each test here.
    }

    ~DiffieHellmanTest() override
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

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void DiffieHellmanGenerateKeys(DH *&privkey)
{
    int codes;

    /* Generate the parameters to be used */
    if (NULL == (privkey = DH_new()))
        handleErrors();
    if (1 != DH_generate_parameters_ex(privkey, 2048, DH_GENERATOR_2, NULL))
        handleErrors();

    if (1 != DH_check(privkey, &codes))
        handleErrors();
    if (codes != 0)
    {
        /* Problems have been found with the generated parameters */
        /* Handle these here - we'll just abort for this example */
        printf("DH_check failed\n");
        abort();
    }

    /* Generate the public and private key pair */
    if (1 != DH_generate_key(privkey))
        handleErrors();
}

void DiffieHellmanGenerateCommonSecret(DH *privkey, const BIGNUM *pubkey, unsigned char *&secret, int &secret_size)
{
    /* Compute the shared secret */
    if (NULL == (secret = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privkey)))))
        handleErrors();

    if (0 > (secret_size = DH_compute_key(secret, pubkey, privkey)))
        handleErrors();
}
/*
TEST_F(DiffieHellmanTest, DH_lowlevel)
{
    unsigned char *secret1, *secret2;
    int secret_size1, secret_size2;

    DH *dh1 = NULL;
    DH *dh2 = NULL;

    DiffieHellmanGenerateKeys(dh1);

    if (NULL == (dh2 = DH_new()))
        handleErrors();
    
    // Prime and Generator need to be passed to the peer
    BIGNUM *p = BN_dup(DH_get0_p(dh1));
    BIGNUM *g = BN_dup(DH_get0_g(dh1));

    // Set param for dh2
    DH_set0_pqg(dh2, p, NULL, g) ;
    // Generate key for dh2
    if (1 != DH_generate_key(dh2))
        handleErrors();

    // Exchange the public key with each peer.
    BIGNUM *bignum_pubkey1 = NULL;
    BIGNUM *bignum_pubkey2 = NULL;

    DH_get0_key(dh1, (const BIGNUM **)&bignum_pubkey1, NULL);
    DH_get0_key(dh2, (const BIGNUM **)&bignum_pubkey2, NULL);

    // Send the public key to the peer.
    // How this occurs will be specific to your situation (see main text below)
    DiffieHellmanGenerateCommonSecret(dh1, (const BIGNUM *)bignum_pubkey2, secret1, secret_size1);
    DiffieHellmanGenerateCommonSecret(dh2, (const BIGNUM *)bignum_pubkey1, secret2, secret_size2);

    // Do something with the shared secret
    // Note secret_size may be less than DH_size(privkey)
    printf("The shared secret1 is:\n");
    BIO_dump_fp(stdout, secret1, secret_size1);
    printf("The shared secret2 is:\n");
    BIO_dump_fp(stdout, secret2, secret_size2);

    EXPECT_EQ(secret_size1, secret_size2);
    EXPECT_TRUE(strncmp((const char *)secret1, (const char *)secret2, secret_size1) == 0);

    // Clean up
    OPENSSL_free(secret1);
    DH_free(dh1);

    OPENSSL_free(secret2);
    DH_free(dh2);
}*/

TEST_F(DiffieHellmanTest, DH_evp)
{
    EVP_PKEY *param_common;

    EVP_PKEY_CTX *kctx1 = NULL, *kctx2 = NULL;

    EVP_PKEY *dhkey1 = NULL, *dhkey2 = NULL;

    unsigned char *secret1, *secret2;
    size_t secret_size1, secret_size2;

    /* Use built-in parameters */
    if (NULL == (param_common = EVP_PKEY_new()))
        handleErrors();
    if (1 != EVP_PKEY_set1_DH(param_common, DH_get_2048_256()))
        handleErrors();

    /* Create context for the key generation */
    if (!(kctx1 = EVP_PKEY_CTX_new(param_common, NULL)))
        handleErrors();
    if (!(kctx2 = EVP_PKEY_CTX_new(param_common, NULL)))
        handleErrors();

    /* Generate a new key */
    if (1 != EVP_PKEY_keygen_init(kctx1))
        handleErrors();
    if (1 != EVP_PKEY_keygen(kctx1, &dhkey1))
        handleErrors();

    if (1 != EVP_PKEY_keygen_init(kctx2))
        handleErrors();
    if (1 != EVP_PKEY_keygen(kctx2, &dhkey2))
        handleErrors();

    // Exchange public key

    BIO* bio1 = BIO_new(BIO_s_mem());
    if (1 != PEM_write_bio_PUBKEY(bio1, dhkey1))
        handleErrors();

    EVP_PKEY *dh1pubkey = NULL;
    PEM_read_bio_PUBKEY(bio1, &dh1pubkey, NULL, NULL);

    BIO* bio2 = BIO_new(BIO_s_mem());
    if (1 != PEM_write_bio_PUBKEY(bio2, dhkey2))
        handleErrors();

    EVP_PKEY *dh2pubkey = NULL;
    PEM_read_bio_PUBKEY(bio2, &dh2pubkey, NULL, NULL);

    // Generate secrets

    EVP_PKEY_CTX *ctx1, *ctx2;

    ///////////////////// generate secret 1 ///////////////////////////////////

    ctx1 = EVP_PKEY_CTX_new(dhkey1, NULL);
    if (!ctx1)
        handleErrors();
    if (EVP_PKEY_derive_init(ctx1) <= 0)
        handleErrors();
    if (EVP_PKEY_derive_set_peer(ctx1, dh2pubkey) <= 0)
        handleErrors();

    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx1, NULL, &secret_size1) <= 0)
        handleErrors();

    secret1 = (unsigned char *)OPENSSL_malloc(secret_size1);
    if (!secret1)
        /* malloc failure */ handleErrors();

    if (EVP_PKEY_derive(ctx1, secret1, &secret_size1) <= 0)
        handleErrors();

    ///////////////////// generate secret 2 ///////////////////////////////////

    ctx2 = EVP_PKEY_CTX_new(dhkey2, NULL);
    if (!ctx2)
        handleErrors();
    if (EVP_PKEY_derive_init(ctx2) <= 0)
        handleErrors();
    if (EVP_PKEY_derive_set_peer(ctx2, dh1pubkey) <= 0)
        handleErrors();

    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx2, NULL, &secret_size2) <= 0)
        handleErrors();

    secret2 = (unsigned char *)OPENSSL_malloc(secret_size2);
    if (!secret2)
        /* malloc failure */ handleErrors();

    if (EVP_PKEY_derive(ctx2, secret2, &secret_size2) <= 0)
        handleErrors();

    // Compare the secrets

    printf("The shared secret1 is:\n");
    BIO_dump_fp(stdout, secret1, secret_size1);
    printf("The shared secret2 is:\n");
    BIO_dump_fp(stdout, secret2, secret_size2);

    EXPECT_EQ(secret_size1, secret_size2);
    EXPECT_TRUE(strncmp((const char *)secret1, (const char *)secret2, secret_size1) == 0);

    // Clean up

    EVP_PKEY_free(param_common);
    EVP_PKEY_CTX_free(kctx1);
    EVP_PKEY_CTX_free(kctx2);
    EVP_PKEY_CTX_free(ctx1);
    EVP_PKEY_CTX_free(ctx2);
    BIO_free(bio1);
    BIO_free(bio2);
    EVP_PKEY_free(dhkey1);
    EVP_PKEY_free(dhkey2);
    EVP_PKEY_free(dh1pubkey);
    EVP_PKEY_free(dh2pubkey);
    OPENSSL_free(secret1);
    OPENSSL_free(secret2);
}