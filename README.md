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
  * ~~SymmetricCryptography~~
* Base64
* ...
