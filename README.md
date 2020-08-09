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

* Block Cipher
  * SymmetricCipher
    * EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free()
    * EVP_EncryptInit_ex(), EVP_DecryptInit_ex()
    * EVP_EncryptUpdate(), EVP_DecryptUpdate()
    * EVP_EncryptFinal_ex(), EVP_DecryptFinal_ex()
  * AuthenticatedSymmetricCipher
    * EVP_CIPHER_CTX_ctrl()
      * EVP_CTRL_'Algorithm'_SET/GET_'Param'
  * ~~SymmetricCryptography~~
* Base64
* ...
