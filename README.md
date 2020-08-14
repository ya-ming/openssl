# OpenSSL

## OpenSSL client and server from scratch

Based on the posts at [OpenSSL client and server from scratch](https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/) to implement http/https server and client.

Added support of:

* Client certificate verification.
* CRL verification.

* http_https
  * http server and client
  * https server and client
    * `./https-server.out ca`
    * `./https-client.out localhost 8080 ca client`
    * `./https-client.out localhost 8080 ca client2`
  * client certificate verification
    * load and verify certificate revokation list
      * X509_load_crl_file
      * X509_STORE_set_flags
    * if certificate has been revoked, end the connection

## Examples of using openssl

[OpenSSL wiki](https://wiki.openssl.org/index.php/Main_Page)

* EVP
  * SymmetricCipher
    * EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free()
    * EVP_EncryptInit_ex(), EVP_DecryptInit_ex()
    * EVP_EncryptUpdate(), EVP_DecryptUpdate()
    * EVP_EncryptFinal_ex(), EVP_DecryptFinal_ex()
  * AuthenticatedSymmetricCipher
    * EVP_CIPHER_CTX_ctrl()
      * EVP_CTRL_'Algorithm'_SET/GET_'Param'
  * AsymmetricEnvelope
    * EVP_SealInit(), EVP_SealUpdate(), EVP_SealFinal()
    * EVP_OpenInit(), EVP_OpenUpdate(), EVP_OpenFinal()
  * Key and Parameter Generation
    * EVP_PKEY_EC (for ECDSA and ECDH keys), EVP_PKEY_DSA, EVP_PKEY_DH
    * Parameter
      * EVP_PKEY_CTX_new_id(), EVP_PKEY_paramgen_init()
      * EVP_PKEY_CTX_set_ec_paramgen_curve_nid(), EVP_PKEY_CTX_set_dsa_paramgen_bits(), EVP_PKEY_CTX_set_dh_paramgen_prime_len()
      * EVP_PKEY_paramgen()
    * Key
      * EVP_PKEY_CTX_new(), EVP_PKEY_CTX_new_id(), EVP_PKEY_keygen_init(), EVP_PKEY_CTX_set_rsa_keygen_bits(), EVP_PKEY_keygen()
    * HMAC and CMAC
      * EVP_PKEY_CTX_ctrl()
      * EVP_MD_CTX_new(), EVP_DigestSignInit(), EVP_DigestSignUpdate(), EVP_DigestSignFinal(), EVP_MD_CTX_free()
      * EVP_PKEY_new_mac_key()
  * Diffie Hellman
    * Low-level
      * DH_new(), DH_generate_parameters_ex(), DH_check(), DH_generate_key(), DH_compute_key()
    * evp
      * EVP_PKEY_derive_init(), EVP_PKEY_derive_set_peer(), EVP_PKEY_derive(), EVP_PKEY_derive()
  * Digest
    * EVP_DigestInit_ex(), EVP_DigestUpdate(), EVP_DigestFinal_ex()
  * ~~SymmetricCryptography~~
* Base64
* ...
