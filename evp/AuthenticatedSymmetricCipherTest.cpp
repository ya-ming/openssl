#include "AuthenticatedSymmetricCipher.h"
#include <string.h>
#include <string>
#include <iostream>

using namespace my;

// The fixture for testing class AuthenticatedSymmetricCipher.
class AuthenticatedSymmetricCipherTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    AuthenticatedSymmetricCipherTest()
    {
        // You can do set-up work for each test here.
    }

    ~AuthenticatedSymmetricCipherTest() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override
    {
        // Code here will be called immediately after the constructor (right
        // before each test).
        cipher = new my::AuthenticatedSymmetricCipher();
        cipher->load_providers();
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).
        delete cipher;
    }

    // void test_cipher(const EVP_CIPHER *cipher)
    // {
    //     secure_string ptext = "123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()_+{}|:\"<>?-=[];',./";
    //     secure_string ctext, rtext;

    //     std::cout << "Testing cipher: " << EVP_CIPHER_name(cipher) << std::endl;

    //     const unsigned int BLOCK_SIZE = EVP_CIPHER_block_size(cipher);
    //     const unsigned int KEY_SIZE = EVP_CIPHER_block_size(cipher);

    //     byte key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_BLOCK_LENGTH];
    //     gen_params(key, KEY_SIZE, iv, BLOCK_SIZE);

    //     cipher->encrypt(cipher, key, iv, BLOCK_SIZE, ptext, ctext);
    //     cipher->decrypt(cipher, key, iv, BLOCK_SIZE, ctext, rtext);

    //     OPENSSL_cleanse(key, KEY_SIZE);
    //     OPENSSL_cleanse(iv, BLOCK_SIZE);

    //     std::cout << "   ptest    :'" << ptext << "'" << std::endl;
    //     std::cout << "   ctest len: " << ctext.length() << " bytes" << std::endl;
    //     std::cout << "   rtest    :'" << ptext << "'" << std::endl;

    //     EXPECT_EQ(ptext, rtext);
    // }

    // Class members declared here can be used by all tests in the test suite
    // for AuthenticatedSymmetricCipher.
    my::AuthenticatedSymmetricCipher *cipher = NULL;
};

TEST_F(AuthenticatedSymmetricCipherTest, block_ciphers)
{
    // test_cipher(EVP_aes_128_cbc());
    // test_cipher(EVP_aes_256_cbc());
}

TEST_F(AuthenticatedSymmetricCipherTest, aes_256_gcm)
{
    // plaintext, ciphertext, recovered text
    // secure_string ptext = "123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()_+{}|:\"<>?-=[];',./";
    // secure_string ctext, rtext;

    // const unsigned int KEY_SIZE = 32;
    // const unsigned int IV_LENTGH = 12;
    // const unsigned int BLOCK_SIZE = 16;

    // byte key[KEY_SIZE], iv[IV_LENTGH];
    // gen_params(key, KEY_SIZE, iv, IV_LENTGH);

    // cipher->encrypt(EVP_aes_256_cbc(), key, iv, BLOCK_SIZE, ptext, ctext);
    // cipher->decrypt(EVP_aes_256_cbc(), key, iv, BLOCK_SIZE, ctext, rtext);

    // OPENSSL_cleanse(key, KEY_SIZE);
    // OPENSSL_cleanse(iv, BLOCK_SIZE);

    // EXPECT_EQ(ptext, rtext);

    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    size_t iv_len = 16;

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /* Additional data */
    unsigned char *additional =
        (unsigned char *)"The five boxing wizards jump quickly.";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    /* Buffer for the tag */
    unsigned char tag[16];

    int decryptedtext_len, ciphertext_len;

    const EVP_CIPHER *evp_cipher = EVP_aes_256_gcm();

    /* Encrypt the plaintext */
    ciphertext_len = cipher->encrypt(evp_cipher, my::GCM_MODE, plaintext, strlen((char *)plaintext),
        additional, strlen((char *)additional),
        key,
        iv, iv_len,
        ciphertext, tag);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    printf("Tag is:\n");
    BIO_dump_fp(stdout, (const char *)tag, 16);

    /* Decrypt the ciphertext */
    decryptedtext_len = cipher->decrypt(evp_cipher, my::GCM_MODE, ciphertext, ciphertext_len,
        additional, strlen((char *)additional),
        tag,
        key, iv, iv_len,
        decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    }
    else {
        printf("Decryption failed\n");
    }

    EXPECT_TRUE(!strcmp((const char *)plaintext, (const char *)decryptedtext));

    tag[sizeof(tag)-1]+=0xAA;
    printf("\nModified tag is:\n");
    BIO_dump_fp(stdout, (const char *)tag, 16);


    /* Decrypt the ciphertext with modified tag */
    // if tag doesn't match, the ciphertext will be decrpted but the length returned will be -1
    decryptedtext_len = cipher->decrypt(evp_cipher, my::GCM_MODE, ciphertext, ciphertext_len,
        additional, strlen((char *)additional),
        tag,
        key, iv, iv_len,
        decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    }
    else {
        printf("Decryption failed\n");
    }

    EXPECT_TRUE(!strcmp((const char *)plaintext, (const char *)decryptedtext));
}

TEST_F(AuthenticatedSymmetricCipherTest, aes_256_ccm)
{
    // plaintext, ciphertext, recovered text
    // secure_string ptext = "123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()_+{}|:\"<>?-=[];',./";
    // secure_string ctext, rtext;

    // const unsigned int KEY_SIZE = 32;
    // const unsigned int BLOCK_SIZE = 16;

    // byte key[KEY_SIZE], iv[BLOCK_SIZE];
    // gen_params(key, KEY_SIZE, iv, BLOCK_SIZE);

    // cipher->encrypt(EVP_aes_256_cbc(), key, iv, BLOCK_SIZE, ptext, ctext);
    // cipher->decrypt(EVP_aes_256_cbc(), key, iv, BLOCK_SIZE, ctext, rtext);

    // OPENSSL_cleanse(key, KEY_SIZE);
    // OPENSSL_cleanse(iv, BLOCK_SIZE);

    // EXPECT_EQ(ptext, rtext);

    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    size_t iv_len = 12;

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /* Additional data */
    unsigned char *additional =
        (unsigned char *)"The five boxing wizards jump quickly.";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    /* Buffer for the tag */
    unsigned char tag[14];

    int decryptedtext_len, ciphertext_len;

    const EVP_CIPHER *evp_cipher = EVP_aes_256_ccm();

    /* Encrypt the plaintext */
    ciphertext_len = cipher->encrypt(evp_cipher, my::CCM_MODE, plaintext, strlen((char *)plaintext),
        additional, strlen((char *)additional),
        key,
        iv, iv_len,
        ciphertext, tag);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    printf("Tag is:\n");
    BIO_dump_fp(stdout, (const char *)tag, 14);

    /* Decrypt the ciphertext */
    decryptedtext_len = cipher->decrypt(evp_cipher, my::CCM_MODE, ciphertext, ciphertext_len,
        additional, strlen((char *)additional),
        tag,
        key, iv, iv_len,
        decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    }
    else {
        printf("Decryption failed\n");
    }

    EXPECT_TRUE(!strcmp((const char *)plaintext, (const char *)decryptedtext));

    tag[sizeof(tag)-1]+=0xAA;
    printf("\nModified tag is:\n");
    BIO_dump_fp(stdout, (const char *)tag, 14);


    /* Decrypt the ciphertext with modified tag */
    decryptedtext_len = cipher->decrypt(evp_cipher, my::CCM_MODE, ciphertext, ciphertext_len,
        additional, strlen((char *)additional),
        tag,
        key, iv, iv_len,
        decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    }
    else {
        printf("Decryption failed\n");
    }

    EXPECT_FALSE(!strcmp((const char *)plaintext, (const char *)decryptedtext));
}