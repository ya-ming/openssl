#ifndef SYMMETRIC_CRYPTOGRAPHY_H
#define SYMMETRIC_CRYPTOGRAPHY_H

#include <memory>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include "../support-infrastructure/seed_prng.h"
#include "../utility/utility.h"

namespace my
{

    template <class T>
    struct DeleterOf;
    template <>
    struct DeleterOf<EVP_CIPHER_CTX>
    {
        void operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
    };

    template <>
    struct DeleterOf<OSSL_PROVIDER>
    {
        void operator()(OSSL_PROVIDER *p) const { OSSL_PROVIDER_unload(p); }
    };

    template <class MyType>
    using UniquePtr = std::unique_ptr<MyType, my::DeleterOf<MyType>>;

    class SymmetricCryptography
    {
        my::UniquePtr<EVP_CIPHER_CTX> ctx_;
        my::UniquePtr<OSSL_PROVIDER> legacyProvider_;
        my::UniquePtr<OSSL_PROVIDER> defaultProvider_;

    public:
        SymmetricCryptography(SymmetricCryptography &&) = delete;
        SymmetricCryptography &operator=(SymmetricCryptography &&) = delete;

        unsigned char key[EVP_MAX_BLOCK_LENGTH];
        unsigned char iv[EVP_MAX_IV_LENGTH];

        explicit SymmetricCryptography()
        {
        }

        int setup_for_encryption(const EVP_CIPHER *cipher)
        {
            ctx_.reset(EVP_CIPHER_CTX_new());

            if (!seed_prng(2048))
                return 0;

            select_random_key(key, EVP_MAX_KEY_LENGTH);
            select_random_iv(iv, EVP_MAX_IV_LENGTH);
            EVP_EncryptInit(ctx_.get(), cipher, key, iv);
            return 1;
        }

        int setup_for_encryption_ex(const EVP_CIPHER *cipher)
        {
            ctx_.reset(EVP_CIPHER_CTX_new());

            if (!seed_prng(2048))
                return 0;

            select_random_key(key, EVP_MAX_KEY_LENGTH);
            select_random_iv(iv, EVP_MAX_IV_LENGTH);
            EVP_EncryptInit_ex(ctx_.get(), cipher, NULL, key, iv);
            return 1;
        }

        void setup_for_decryption(const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv)
        {
            EVP_DecryptInit(ctx_.get(), cipher, key, iv);
        }

        void setup_for_decryption_ex(const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv)
        {
            EVP_DecryptInit_ex(ctx_.get(), cipher, NULL, key, iv);
        }

        void load_providers()
        {
            /* Load Multiple providers into the default (NULL) library context */
            legacyProvider_.reset(OSSL_PROVIDER_load(NULL, "legacy"));
            if (legacyProvider_.get() == NULL)
            {
                printf("Failed to load Legacy provider\n");
                exit(EXIT_FAILURE);
            }
            defaultProvider_.reset(OSSL_PROVIDER_load(NULL, "default"));
            if (defaultProvider_.get() == NULL)
            {
                printf("Failed to load Default provider\n");
                exit(EXIT_FAILURE);
            }
        }

        unsigned char *encrypt(unsigned char *data, int inl, int *rb)
        {
            EVP_CIPHER_CTX *ctx = ctx_.get();
            unsigned char *ret;
            int i, tmp, ol;
            ol = 0;
            ret = (unsigned char *)malloc(inl + EVP_CIPHER_CTX_block_size(ctx));
            for (i = 0; i < inl / 100; i++)
            {
                EVP_EncryptUpdate(ctx, &ret[ol], &tmp, &data[ol], 100);
                ol += tmp;
            }
            if (inl % 100)
            {
                EVP_EncryptUpdate(ctx, &ret[ol], &tmp, &data[ol], inl % 100);
                ol += tmp;
            }
            EVP_EncryptFinal(ctx, &ret[ol], &tmp);
            *rb = ol + tmp;
            return ret;
        }

        int incremental_encrypt(unsigned char *data, int inl)
        {
            EVP_CIPHER_CTX *ctx = ctx_.get();
            unsigned char *buf;
            int ol;
            int bl = EVP_CIPHER_CTX_block_size(ctx);
            /* Up to the block size - 1 chars can be buffered up. Add that to the length
             * of the input, and then we can easily determine the maximum number of
             * blocks output will take by integer divison with the block size.
             */
            buf = (unsigned char *)malloc((inl + bl - 1) / bl * bl);
            EVP_EncryptUpdate(ctx, buf, &ol, data, inl);
            if (ol)
                incremental_send(buf, ol);
            /* incremental_send must copy if it wants to store. */
            free(buf);
            return ol;
        }

        /* Also returns the number of bytes written. */
        int incremental_encrypt_finish()
        {
            EVP_CIPHER_CTX *ctx = ctx_.get();
            unsigned char *buf;
            int ol;
            buf = (unsigned char *)malloc(EVP_CIPHER_CTX_block_size(ctx));
            EVP_EncryptFinal(ctx, buf, &ol);
            if (ol)
                incremental_send(buf, ol);
            free(buf);
            return ol;
        }

        unsigned char *incremental_decrypt_finish()
        {
            EVP_CIPHER_CTX *ctx = ctx_.get();
            unsigned char *buf;
            int ol;
            buf = (unsigned char *)malloc(EVP_CIPHER_CTX_block_size(ctx));
            if (!EVP_DecryptFinal(ctx, buf, &ol))
            {
                printf("ERROR: Padding incorrect.\n");
                abort();
            }
            if (!ol)
            {
                free(buf);
                return NULL;
            }
            buf[ol] = 0;
            return buf;
        }

        unsigned char *decrypt_(unsigned char *ct, int inl)
        {
            EVP_CIPHER_CTX *ctx = ctx_.get();
            unsigned char *buf = (unsigned char *)malloc(inl + EVP_CIPHER_CTX_block_size(ctx) + 1);
            int ol;
            EVP_DecryptUpdate(ctx, buf, &ol, ct, inl);
            if (!ol)
            {
                free(buf);
                return NULL;
            }
            buf[ol] = 0;
            return buf;
        }

        unsigned char *decrypt(unsigned char *encryptedStr, int encryptedStrLen)
        {
            int i;
            std::string decryptedStr;
            unsigned char *ret = NULL;
            int block_size = EVP_CIPHER_CTX_block_size(ctx_.get());
            for (i = 0; i < encryptedStrLen; i += block_size)
            {
                unsigned char *tempStr = decrypt_(encryptedStr + i, block_size);
                if (tempStr != NULL)
                {
                    printf("Decrypted block: %s\n", tempStr);
                    decryptedStr += std::string((const char *)tempStr);
                    free(tempStr);
                }
                else
                {
                    printf("Decrypted block: %s\n", tempStr);
                }
            }
            unsigned char *tempStr = incremental_decrypt_finish();
            if (tempStr != NULL)
            {
                printf("Decrypted block: %s\n", tempStr);
                decryptedStr += std::string((const char *)tempStr);
                free(tempStr);
            }
            printf("Decrypted: %s\n", decryptedStr.c_str());
            ret = (unsigned char *)malloc(decryptedStr.length() + 1);
            strncpy((char *)ret, decryptedStr.c_str(), decryptedStr.length());
            ret[decryptedStr.length()] = '\0';
            return ret;
        }

        int counter_encrypt_or_decrypt(EVP_CIPHER_CTX *ctx, char *pt, char *ct, int len, unsigned char *counter)
        {
            int i, j, where = 0, num, bl = EVP_CIPHER_CTX_block_size(ctx);
            unsigned char encr_ctrs[len + bl]; /* Encrypted counters. */
            if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_ECB_MODE)
                return -1;
            /* <= is correct, so that we handle any possible non-aligned data. */
            for (i = 0; i <= len / bl; i++)
            {
                /* Encrypt the current counter. */
                EVP_EncryptUpdate(ctx, &encr_ctrs[where], &num, counter, bl);
                where += num;
                /* Increment the counter. Remember it's an array of single characters */
                for (j = 0; j < bl / sizeof(char); j++)
                {
                    if (++counter[j])
                        break;
                }
            }
            /* XOR the key stream with the first buffer, placing the results in the
             * second buffer.
             */
            for (i = 0; i < len; i++)
                ct[i] = pt[i] ^ encr_ctrs[i];
            return 1; /* Success. */
        }

        int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                    unsigned char *iv, unsigned char *ciphertext)
        {
            EVP_CIPHER_CTX *ctx = ctx_.get();

            int len;

            int ciphertext_len;

            /* Create and initialise the context */
            // if (!(ctx = EVP_CIPHER_CTX_new()))
            //     handleErrors();

            /*
             * Initialise the encryption operation. IMPORTANT - ensure you use a key
             * and IV size appropriate for your cipher
             * In this example we are using 256 bit AES (i.e. a 256 bit key). The
             * IV size for *most* modes is the same as the block size. For AES this
             * is 128 bits
             */
            // if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
            //     handleErrors();

            /*
             * Provide the message to be encrypted, and obtain the encrypted output.
             * EVP_EncryptUpdate can be called multiple times if necessary
             */
            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                handleErrors();
            ciphertext_len = len;

            /*
             * Finalise the encryption. Further ciphertext bytes may be written at
             * this stage.
             */
            if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
                handleErrors();
            ciphertext_len += len;

            /* Clean up */
            // EVP_CIPHER_CTX_free(ctx);

            return ciphertext_len;
        }

        int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                    unsigned char *iv, unsigned char *plaintext)
        {
            EVP_CIPHER_CTX *ctx = ctx_.get();

            int len;

            int plaintext_len;

            /* Create and initialise the context */
            // if (!(ctx = EVP_CIPHER_CTX_new()))
            //     handleErrors();

            /*
             * Initialise the decryption operation. IMPORTANT - ensure you use a key
             * and IV size appropriate for your cipher
             * In this example we are using 256 bit AES (i.e. a 256 bit key). The
             * IV size for *most* modes is the same as the block size. For AES this
             * is 128 bits
             */
            // if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
            //     handleErrors();

            /*
             * Provide the message to be decrypted, and obtain the plaintext output.
             * EVP_DecryptUpdate can be called multiple times if necessary.
             */
            if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
                handleErrors();
            plaintext_len = len;

            /*
             * Finalise the decryption. Further plaintext bytes may be written at
             * this stage.
             */
            if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
                handleErrors();
            plaintext_len += len;

            /* Clean up */
            // EVP_CIPHER_CTX_free(ctx);

            return plaintext_len;
        }

        void handleErrors(void)
        {
            ERR_print_errors_fp(stderr);
            abort();
        }

        void incremental_send(unsigned char *str, int)
        {
            printf("buf: %s\n", str);
        }
    };
} // namespace my

#endif