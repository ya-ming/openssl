#ifndef CIPHER_H
#define CIPHER_H

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

    typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;
    using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

    class Cipher
    {
    protected:
        my::UniquePtr<EVP_CIPHER_CTX> ctx_;
        my::UniquePtr<OSSL_PROVIDER> legacyProvider_;
        my::UniquePtr<OSSL_PROVIDER> defaultProvider_;

    public:
        Cipher(Cipher &&) = delete;
        Cipher &operator=(Cipher &&) = delete;

        unsigned char key_[EVP_MAX_KEY_LENGTH];
        unsigned char iv_[EVP_MAX_IV_LENGTH];

        explicit Cipher()
        {
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
    };
} // namespace my
#endif