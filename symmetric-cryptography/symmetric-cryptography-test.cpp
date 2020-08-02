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

    // Class members declared here can be used by all tests in the test suite
    // for SymmetricCryptography.
    my::SymmetricCryptography *sc = NULL;
};

TEST_F(SymmetricCryptographyTest, bf_cbc)
{
    sc->setup_for_encryption(EVP_bf_cbc());

    unsigned char *encryptedStr;
    unsigned char *decryptedStr;
    std::string str("123456789abcdefgh");
    int encryptedStrLen = 0;

    encryptedStr = sc->encrypt((unsigned char *)str.c_str(), str.length(), &encryptedStrLen);
    printf("str '%s' encrypted, length of cipher text is %d bytes\n", str.c_str(), encryptedStrLen);

    sc->setup_for_decryption(EVP_bf_cbc(), sc->key, sc->iv);

    decryptedStr = sc->decrypt(encryptedStr, encryptedStrLen);

    EXPECT_EQ(str, std::string((const char*)decryptedStr));

    free(encryptedStr);
    free(decryptedStr);
}