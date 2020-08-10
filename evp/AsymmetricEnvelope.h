#ifndef ASYMMETRIC_ENVELOPE_H
#define ASYMMETRIC_ENVELOPE_H

#include "Cipher.h"

/*
 * Encryption and decryption with asymmetric keys is computationally expensive.
 * Typically then messages are not encrypted directly with such keys but are instead encrypted using a symmetric "session" key.
 * This key is itself then encrypted using the public key.
 * In OpenSSL this combination is referred to as an envelope.
 * It is also possible to encrypt the session key with multiple public keys.
 * This way the message can be sent to a number of different recipients (one for each public key used).
 * The session key is the same for each recipient.
 */

namespace my
{
    class AsymmetricEnvelope : public Cipher
    {
    public:
        int envelope_seal(EVP_PKEY **pub_key, int npubk, unsigned char *plaintext, int plaintext_len,
            unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
            unsigned char *ciphertext)
        {
            EVP_CIPHER_CTX *ctx;
            int ciphertext_len;
            int len;

            /* Create and initialise the context */
            if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

            /* Initialise the envelope seal operation. This operation generates
             * a key for the provided cipher, and then encrypts that key a number
             * of times (one for each public key provided in the pub_key array). In
             * this example the array size is just one. This operation also
             * generates an IV and places it in iv. */
            if (npubk != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
                encrypted_key_len, iv, pub_key, npubk))
                handleErrors();

            /* Provide the message to be encrypted, and obtain the encrypted output.
             * EVP_SealUpdate can be called multiple times if necessary
             */
            if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                handleErrors();
            ciphertext_len = len;

            /* Finalise the encryption. Further ciphertext bytes may be written at
             * this stage.
             */
            if (1 != EVP_SealFinal(ctx, ciphertext + len, &len)) handleErrors();
            ciphertext_len += len;

            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);

            return ciphertext_len;
        }

        int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
            unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
            unsigned char *plaintext)
        {
            EVP_CIPHER_CTX *ctx;
            int len;
            int plaintext_len;

            /* Create and initialise the context */
            if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

            /* Initialise the decryption operation. The asymmetric private key is
             * provided and priv_key, whilst the encrypted session key is held in
             * encrypted_key */
            if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
                encrypted_key_len, iv, priv_key))
                handleErrors();

            /* Provide the message to be decrypted, and obtain the plaintext output.
             * EVP_OpenUpdate can be called multiple times if necessary
             */
            if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
                handleErrors();
            plaintext_len = len;

            /* Finalise the decryption. Further plaintext bytes may be written at
             * this stage.
             */
            if (1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
            plaintext_len += len;

            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);

            return plaintext_len;
        }
    };

} // namespace my

#endif