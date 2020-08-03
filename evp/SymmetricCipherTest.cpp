#include "SymmetricCipher.h"
#include <string.h>
#include <string>
#include <iostream>

using namespace my;

// The fixture for testing class SymmetricCipher.
class SymmetricCipherTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    SymmetricCipherTest()
    {
        // You can do set-up work for each test here.
    }

    ~SymmetricCipherTest() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override
    {
        // Code here will be called immediately after the constructor (right
        // before each test).
        sc = new my::SymmetricCipher();
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
        secure_string ptext = "123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()_+{}|:\"<>?-=[];',./";
        secure_string ctext, rtext;

        std::cout << "Testing cipher: " << EVP_CIPHER_name(cipher) << std::endl;

        const unsigned int BLOCK_SIZE = EVP_CIPHER_block_size(cipher);
        const unsigned int KEY_SIZE = EVP_CIPHER_block_size(cipher);

        byte key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_BLOCK_LENGTH];
        gen_params(key, KEY_SIZE, iv, BLOCK_SIZE);
    
        sc->encrypt(cipher, key, iv, BLOCK_SIZE, ptext, ctext);
        sc->decrypt(cipher, key, iv, BLOCK_SIZE, ctext, rtext);
        
        OPENSSL_cleanse(key, KEY_SIZE);
        OPENSSL_cleanse(iv, BLOCK_SIZE);

        std::cout << "   ptest    :'" << ptext << "'" << std::endl;
        std::cout << "   ctest len: " << ctext.length() << " bytes" << std::endl;
        std::cout << "   rtest    :'" << ptext << "'" << std::endl;

        EXPECT_EQ(ptext, rtext);
    }

    // Class members declared here can be used by all tests in the test suite
    // for SymmetricCipher.
    my::SymmetricCipher *sc = NULL;
};

TEST_F(SymmetricCipherTest, block_ciphers)
{
    test_cipher(EVP_bf_cbc());
    test_cipher(EVP_aes_128_cbc());
    test_cipher(EVP_aes_256_cbc());
    test_cipher(EVP_des_ede3_cbc());
}

TEST_F(SymmetricCipherTest, aes_256_cbc)
{
    // plaintext, ciphertext, recovered text
    secure_string ptext = "123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()_+{}|:\"<>?-=[];',./";
    secure_string ctext, rtext;

    const unsigned int KEY_SIZE = 32;
    const unsigned int BLOCK_SIZE = 16;

    byte key[KEY_SIZE], iv[BLOCK_SIZE];
    gen_params(key, KEY_SIZE, iv, BLOCK_SIZE);
  
    sc->encrypt(EVP_aes_256_cbc(), key, iv, BLOCK_SIZE, ptext, ctext);
    sc->decrypt(EVP_aes_256_cbc(), key, iv, BLOCK_SIZE, ctext, rtext);
    
    OPENSSL_cleanse(key, KEY_SIZE);
    OPENSSL_cleanse(iv, BLOCK_SIZE);

    EXPECT_EQ(ptext, rtext);
}