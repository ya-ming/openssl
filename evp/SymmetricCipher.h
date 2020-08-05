#ifndef SYMMETRIC_CIPHER_H
#define SYMMETRIC_CIPHER_H

#include "Cipher.h"

/*
 * Standard symmetric encryption modes like CBC, CFB and OFB modes.
 */

namespace my
{
    class SymmetricCipher : public Cipher
    {
    public:
        void encrypt(const EVP_CIPHER *cipher, const byte *key, const byte *iv, int blockSize, const secure_string &ptext, secure_string &ctext)
        {
            EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
            int rc = EVP_EncryptInit_ex(ctx.get(), cipher, NULL, key, iv);
            if (rc != 1)
                throw std::runtime_error("EVP_EncryptInit_ex failed");

            // Recovered text expands upto BLOCK_SIZE
            ctext.resize(ptext.size() + blockSize);
            int out_len1 = (int)ctext.size();

            rc = EVP_EncryptUpdate(ctx.get(), (byte *)&ctext[0], &out_len1, (const byte *)&ptext[0], (int)ptext.size());
            if (rc != 1)
                throw std::runtime_error("EVP_EncryptUpdate failed");

            int out_len2 = (int)ctext.size() - out_len1;
            rc = EVP_EncryptFinal_ex(ctx.get(), (byte *)&ctext[0] + out_len1, &out_len2);
            if (rc != 1)
                throw std::runtime_error("EVP_EncryptFinal_ex failed");

            // Set cipher text size now that we know it
            ctext.resize(out_len1 + out_len2);
        }

        void decrypt(const EVP_CIPHER *cipher, const byte *key, const byte *iv, int blockSize, const secure_string &ctext, secure_string &rtext)
        {
            EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
            int rc = EVP_DecryptInit_ex(ctx.get(), cipher, NULL, key, iv);
            if (rc != 1)
                throw std::runtime_error("EVP_DecryptInit_ex failed");

            // Recovered text contracts upto BLOCK_SIZE
            rtext.resize(ctext.size());
            int out_len1 = (int)rtext.size();

            rc = EVP_DecryptUpdate(ctx.get(), (byte *)&rtext[0], &out_len1, (const byte *)&ctext[0], (int)ctext.size());
            if (rc != 1)
                throw std::runtime_error("EVP_DecryptUpdate failed");

            int out_len2 = (int)rtext.size() - out_len1;
            rc = EVP_DecryptFinal_ex(ctx.get(), (byte *)&rtext[0] + out_len1, &out_len2);
            if (rc != 1)
                throw std::runtime_error("EVP_DecryptFinal_ex failed");

            // Set recovered text size now that we know it
            rtext.resize(out_len1 + out_len2);
        }
    };

} // namespace my

#endif