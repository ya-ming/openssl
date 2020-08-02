#include "symmetric-cryptography.h"
#include <string.h>
#include <string>

// The fixture for testing class SymmetricCryptography.
class SymmetricCryptographyTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    SymmetricCryptographyTest()
    {
        // You can do set-up work for each test here.
    }

    ~SymmetricCryptographyTest() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override
    {
        // Code here will be called immediately after the constructor (right
        // before each test).
        sc = new my::SymmetricCryptography();
        sc->load_providers();
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).
        delete sc;
    }

    void test_cipher(const EVP_CIPHER *cipher)
    {
        printf("\ncipher name: %s\n", EVP_CIPHER_name(cipher));
        sc->setup_for_encryption(cipher);

        unsigned char *encryptedStr;
        unsigned char *decryptedStr;
        std::string str("123456789abcdefghijklmnopqrstuvwxyz");
        int encryptedStrLen = 0;

        encryptedStr = sc->encrypt((unsigned char *)str.c_str(), str.length(), &encryptedStrLen);
        printf("str '%s' encrypted, length of cipher text is %d bytes\n", str.c_str(), encryptedStrLen);

        sc->setup_for_decryption(cipher, sc->key_, sc->iv_);

        decryptedStr = sc->decrypt(encryptedStr, encryptedStrLen);

        EXPECT_EQ(str, std::string((const char*)decryptedStr));

        free(encryptedStr);
        free(decryptedStr);
    }

    // Class members declared here can be used by all tests in the test suite
    // for SymmetricCryptography.
    my::SymmetricCryptography *sc = NULL;
};

void printCipherInfo(const EVP_CIPHER* cipher)
{
    printf("\ncipher name: %s\n", EVP_CIPHER_name(cipher));
    printf("block size: %d\n", EVP_CIPHER_block_size(cipher));
    printf("key_ length: %d\n", EVP_CIPHER_key_length(cipher));
    printf("iv_ length: %d\n", EVP_CIPHER_iv_length(cipher));
    printf("\n");
}

TEST(CipherTest, cipher)
{
    printCipherInfo(EVP_bf_cbc());
    printCipherInfo(EVP_idea_cbc());
    printCipherInfo(EVP_aes_128_cbc());
    printCipherInfo(EVP_aes_256_cbc());
    printCipherInfo(EVP_des_ede3_cbc());
}

TEST_F(SymmetricCryptographyTest, block_ciphers)
{
    test_cipher(EVP_bf_cbc());
    test_cipher(EVP_aes_128_cbc());
    test_cipher(EVP_aes_256_cbc());
    test_cipher(EVP_des_ede3_cbc());
}

TEST_F(SymmetricCryptographyTest, idea_cbc)
{
    sc->setup_for_encryption(EVP_idea_cbc());

    unsigned char *encryptedStr;
    unsigned char *decryptedStr;
    std::string str("123456789abcdefghijklmnopqrstuvwxyz.");
    int encryptedStrLen = 0;

    encryptedStr = sc->encrypt((unsigned char *)str.c_str(), str.length(), &encryptedStrLen);
    printf("str '%s' encrypted, length of cipher text is %d bytes\n", str.c_str(), encryptedStrLen);

    sc->setup_for_decryption(EVP_idea_cbc(), sc->key_, sc->iv_);

    decryptedStr = sc->decrypt(encryptedStr, encryptedStrLen);

    EXPECT_EQ(str, std::string((const char*)decryptedStr));

    free(encryptedStr);
    free(decryptedStr);
}

TEST_F(SymmetricCryptographyTest, aes_256_cbc)
{
    sc->setup_for_encryption_ex(EVP_aes_256_cbc());

    unsigned char plaintext[] = "123456789abcdefghijklmnopqrstuvwxyz.";

    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    ciphertext_len = sc->encrypt(plaintext, strlen((char *)plaintext), sc->key_, sc->iv_, ciphertext);
    printf("plaintext '%s' encrypted, length of ciphertext is %d bytes\n", plaintext, ciphertext_len);

    sc->setup_for_decryption_ex(EVP_aes_256_cbc(), sc->key_, sc->iv_);

    decryptedtext_len = sc->decrypt(ciphertext, ciphertext_len, sc->key_, sc->iv_, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    EXPECT_TRUE(strncmp((const char *)plaintext, (const char *)decryptedtext, decryptedtext_len) == 0);
}