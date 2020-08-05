#ifndef AUTHENTICATED_SYMMETRIC_CIPHER_H
#define AUTHENTICATED_SYMMETRIC_CIPHER_H

#include "Cipher.h"

/*
 * Symmetric encryption with Associated-Data (AEAD).
 * The modes include EAX, CCM and GCM mode.
 *
 * Algorithm (currently only AES is supported)
 * Mode (currently only GCM and CCM are supported)
 */

namespace my
{
    class AuthenticatedSymmetricCipher : public Cipher
    {
    public:
        int encrypt(const EVP_CIPHER *cipher, int mode, unsigned char *plaintext, int plaintext_len,
            unsigned char *aad, int aad_len,
            unsigned char *key,
            unsigned char *iv, int iv_len,
            unsigned char *ciphertext,
            unsigned char *tag)
        {
            EVP_CIPHER_CTX *ctx;

            int len;

            int ciphertext_len;


            /* Create and initialise the context */
            if (!(ctx = EVP_CIPHER_CTX_new()))
                handleErrors();

            /* Initialise the encryption operation. */
            if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
                handleErrors();

            /*
             * Set IV length if default 12 bytes (96 bits) is not appropriate
             */
            if (mode == my::GCM_MODE)
            {
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
                    handleErrors();
            }

            if (mode == my::CCM_MODE)
            {
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL))
                    handleErrors();

                /* Set tag length */
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL))
                    handleErrors();
            }

            /* Initialise key and IV */
            if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
                handleErrors();

            if (mode == my::CCM_MODE)
            {
                /* Provide the total plaintext length */
                if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
                    handleErrors();
            }
            /*
             * Provide any AAD data. This can be called zero or more times as
             * required
             */
            if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
                handleErrors();

            /*
             * Provide the message to be encrypted, and obtain the encrypted output.
             * EVP_EncryptUpdate can be called multiple times if necessary (GCM).
             * EVP_EncryptUpdate can only be called once for this (CCM).
             */
            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                handleErrors();
            ciphertext_len = len;

            /*
             * Finalise the encryption. Normally ciphertext bytes may be written at
             * this stage, but this does not occur in GCM mode
             */
            if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
                handleErrors();
            ciphertext_len += len;

            if (mode == my::GCM_MODE)
            {
                /* Get the tag */
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
                    handleErrors();
            }
            else if (mode == my::CCM_MODE)
            {
                /* Get the tag */
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag))
                    handleErrors();
            }

            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);

            return ciphertext_len;
        }


        int decrypt(const EVP_CIPHER *cipher, int mode, unsigned char *ciphertext, int ciphertext_len,
            unsigned char *aad, int aad_len,
            unsigned char *tag,
            unsigned char *key,
            unsigned char *iv, int iv_len,
            unsigned char *plaintext)
        {
            EVP_CIPHER_CTX *ctx;
            int len;
            int plaintext_len;
            int ret;

            /* Create and initialise the context */
            if (!(ctx = EVP_CIPHER_CTX_new()))
                handleErrors();

            /* Initialise the decryption operation. */
            if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
                handleErrors();

            if (mode == my::GCM_MODE)
            {
                /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
                    handleErrors();
            }

            if (mode == my::CCM_MODE)
            {
                /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL))
                    handleErrors();
                /* Set tag length */
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, tag))
                    handleErrors();
            }

            /* Initialise key and IV */
            if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
                handleErrors();

            if (mode == my::CCM_MODE)
            {
                /* Provide the total ciphertext length */
                if(1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len))
                    handleErrors();
            }

            /*
             * Provide any AAD data. This can be called zero or more times as
             * required
             */
            if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
                handleErrors();
            /*
             * Provide the message to be decrypted, and obtain the plaintext output.
             * EVP_DecryptUpdate can be called multiple times if necessary
             * CCM mode verifies Tag here
             */
            ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
            printf("ret = %d, len = %d, ciphertext_len = %d\n", ret, len, ciphertext_len);
            plaintext_len = len;
            if (mode == my::GCM_MODE)
            {
                if (1 != ret)
                    handleErrors();
                /* Set expected tag value. Works in OpenSSL 1.0.1d and later
                 * GCM mode verifies Tag here
                 */
                if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
                    handleErrors();
                /*
                 * Finalise the decryption. A positive return value indicates success,
                 * anything else is a failure - the plaintext is not trustworthy.
                 */
                ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
                if (ret > 0)
                {
                    plaintext_len += len;
                }
            }

            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);
            if (ret > 0) {
                /* Success */
                return plaintext_len;
            }
            else {
                /* Verify failed */
                return -1;
            }
        }

    };
}
#endif