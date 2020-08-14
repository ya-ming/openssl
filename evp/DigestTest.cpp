#include <openssl/evp.h>
#include <openssl/err.h>

#include <gtest/gtest.h>

#include "../utility/utility.h"

class DigestTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    DigestTest()
    {
        // You can do set-up work for each test here.
    }

    ~DigestTest() override
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

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);
}

TEST_F(DigestTest, sha256)
{
    const unsigned char *message = (unsigned char *)"message to create digest";
    size_t message_len = strlen((const char *)message);

    unsigned char *digest = NULL;
    unsigned int digest_len = 0;
    
    digest_message(message, message_len, &digest, &digest_len);

    printf("Digest is:\n");
    BIO_dump_fp(stdout, (const char *)digest, digest_len);

    OPENSSL_free(digest);
}