#include "AsymmetricEnvelope.h"
#include <string.h>
#include <string>
#include <iostream>

#include <openssl/pem.h>

using namespace my;

// The fixture for testing class AsymmetricEnvelope.
class AsymmetricEnvelopeTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    AsymmetricEnvelopeTest()
    {
        // You can do set-up work for each test here.
    }

    ~AsymmetricEnvelopeTest() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override
    {
        // Code here will be called immediately after the constructor (right
        // before each test).
        cipher = new my::AsymmetricEnvelope();
        cipher->load_providers();
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).
        delete cipher;
    }

    // Class members declared here can be used by all tests in the test suite
    // for AsymmetricEnvelope.
    my::AsymmetricEnvelope *cipher = NULL;
};

TEST_F(AsymmetricEnvelopeTest, aes_256_cbc)
{
    /*
     * Generate public-private key pairs
     *   openssl genrsa -out keypair-1.pem 2048
     *   openssl rsa -in keypair-1.pem -pubout -out publickey-1.crt
     * 
     *   openssl genrsa -out keypair-2.pem 2048
     *   openssl rsa -in keypair-2.pem -pubout -out publickey-2.crt
     * 
     *   openssl genrsa -out keypair-3.pem 4096
     *   openssl rsa -in keypair-3.pem -pubout -out publickey-3.crt
     */

    /*
     * Prepare the input
     *   plaintext: text to be encrypted
     *   iv[16]: buffer to store the iv genreated by 'envelope_seal()'
     *   EVP_PKEY *privateKeys[]: arrary of private keys
     *   EVP_PKEY *publicKeys[]: array of public keys
     *   unsigned char *entrypedKeys[]: array of buffers where the public key encrypted secret key will be written
     *   int encryptedKeyLen[]: array of actual size of each secret key
     */
    
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    unsigned char iv[16];
    unsigned char ciphertext[128];

    static const int NUM_OF_KEYS = 3;
    EVP_PKEY *privateKeys[NUM_OF_KEYS];
    EVP_PKEY *publicKeys[NUM_OF_KEYS];
    unsigned char *entrypedKeys[NUM_OF_KEYS] ={ 0 };

    for (int i = 0; i < NUM_OF_KEYS; i++)
    {
        char filePath[100];
        EVP_PKEY *privateKey = NULL;
        EVP_PKEY *publicKey = NULL;

        FILE *f;

        sprintf(filePath, "/home/osboxes/cpp/openssl/evp/keys/keypair-%d.pem", i + 1);
        f = fopen(filePath, "rb");
        PEM_read_PrivateKey(
            f,     /* use the FILE* that was opened */
            &privateKey, /* pointer to EVP_PKEY structure */
            NULL,  /* password callback - can be NULL */
            NULL   /* parameter passed to callback or password if callback is NULL */
        );
        fclose(f);

        privateKeys[i] = privateKey;

        sprintf(filePath, "/home/osboxes/cpp/openssl/evp/keys/publickey-%d.crt", i + 1);
        f = fopen(filePath, "rb");
        PEM_read_PUBKEY(
            f,     /* use the FILE* that was opened */
            &publicKey, /* pointer to EVP_PKEY structure */
            NULL,  /* password callback - can be NULL */
            NULL   /* parameter passed to callback or password if callback is NULL */
        );
        fclose(f);

        publicKeys[i] = publicKey;

        int encryptedKeySize = EVP_PKEY_size(publicKeys[i]);
        entrypedKeys[i] = new unsigned char[encryptedKeySize];
        memset(entrypedKeys[i], 0, encryptedKeySize);
    }

    int encryptedKeyLen[NUM_OF_KEYS] = {0};

    int ciphertext_len = 0;
    ciphertext_len = cipher->envelope_seal(publicKeys, NUM_OF_KEYS,
        plaintext, strlen((const char*)plaintext), (unsigned char **)&entrypedKeys[0], encryptedKeyLen, iv, ciphertext);

    printf("Iv is:\n");
    BIO_dump_fp(stdout, (const char *)iv, 16);

    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    for (int i = 0; i < NUM_OF_KEYS; i++)
    {
        printf("\nKeypair - %d\n", i + 1);
        printf("entrypedKey len is %d:\n", encryptedKeyLen[i]);
        printf("entrypedKey is:\n");
        BIO_dump_fp(stdout, (const char *)entrypedKeys[i], encryptedKeyLen[i]);

        unsigned char decryptedtext[128] = {0};
        int decryptedtext_len = 0;

        decryptedtext_len =  cipher->envelope_open(privateKeys[i], ciphertext, ciphertext_len, (unsigned char *)entrypedKeys[i], encryptedKeyLen[i], iv, decryptedtext);
        decryptedtext[decryptedtext_len] = '\0';

        EXPECT_EQ(strlen((const char*)plaintext), decryptedtext_len);
        EXPECT_TRUE(!strcmp((const char *)plaintext, (const char *)decryptedtext));
    }

    for (int i = 0; i < NUM_OF_KEYS; i++)
    {
        EVP_PKEY_free(privateKeys[i]);
        EVP_PKEY_free(publicKeys[i]);
        delete []entrypedKeys[i];
    }
}