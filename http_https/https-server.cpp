#include "my.h"

#include <openssl/x509_vfy.h>

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
  char buf[256];
  X509 *err_cert;
  int err, depth;
  SSL *ssl;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);

  char data[256];
  X509_NAME_oneline(X509_get_issuer_name(err_cert), data, 256);
  printf("verify_callback issuer = %s\n", data);
  X509_NAME_oneline(X509_get_subject_name(err_cert), data, 256);
  printf("verify_callback subject = %s\n", data);

  // ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  if (err != X509_V_OK)
  {
    if (err != X509_V_ERR_UNABLE_TO_GET_CRL)
    {
      const char *message = X509_verify_cert_error_string(err);
      printf("Certificate verification error: %s (%d)\n", message, err);
      return 0;
    }
    else
    {
      printf("X509_V_ERR_UNABLE_TO_GET_CRL\n");
    }
  }
  else
  {
    printf("Certificate verified\n");
  }

  return 1;
}

int main(int argc, char **argv)
{
  // setting up SSL/TLS
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
  SSL_load_error_strings();
  auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
  auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION);
#endif

  char *server_cert_path = "server-cert.pem";
  char *key_path = "server-key.pem";
  char *client_cert_path = "client-cert.pem";
  if (argc > 1)
  {
    if (strncmp("ca", argv[1], 2) == 0)
    {
      // the certificates in the chain are listed in ca-chain.cert, and loaded via SSL_CTX_use_certificate_file
      server_cert_path = "/home/osboxes/cpp/ca/root/ca/intermediate/certs/ca-chain.cert.pem";
      key_path = "/home/osboxes/cpp/ca/root/ca/intermediate/private/localhost.key.pem";
      client_cert_path = "/home/osboxes/cpp/ca/root/ca/intermediate/certs/client-all.cert.pem";
    }
  }

  if (SSL_CTX_use_certificate_file(ctx.get(), server_cert_path, SSL_FILETYPE_PEM) <= 0)
  {
    my::print_errors_and_exit("Error loading server certificate");
  }
  if (SSL_CTX_use_PrivateKey_file(ctx.get(), key_path, SSL_FILETYPE_PEM) <= 0)
  {
    my::print_errors_and_exit("Error loading server private key");
  }

  /* verify private key */
  if (!SSL_CTX_check_private_key(ctx.get()))
  {
    printf("Private key does not match the public certificate\n");
    abort();
  }

  // load a certificate file
  // if (SSL_CTX_load_verify_locations(ctx.get(), client_cert_path, nullptr) != 1)
  // {
  //   my::print_errors_and_exit("Error setting up trust store");
  // }

  // load CA from folder
  // using `c_reash .` at the folder which stores CA files to generate subject name hash soft links
  // if (SSL_CTX_load_verify_locations(ctx.get(), nullptr, "/home/osboxes/cpp/ca/root/ca/intermediate/certs/all/") != 1)
  // {
  //   my::print_errors_and_exit("Error setting up trust store");
  // }

  int ret = 0;
  X509_STORE *store = SSL_CTX_get_cert_store(ctx.get());
  X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
  // same result as 'SSL_CTX_load_verify_locations'
  ret = X509_LOOKUP_add_dir(lookup, "/home/osboxes/cpp/ca/root/ca/intermediate/certs/all/", X509_FILETYPE_PEM);
  printf("X509_LOOKUP_add_dir ret = %d\n", ret);

  // load crl file
  ret = X509_load_crl_file(lookup, "/home/osboxes/cpp/ca/root/ca/intermediate/crl/intermediate.crl.pem", X509_FILETYPE_PEM);
  printf("X509_load_crl_file ret = %d\n", ret);

  // same crl will be ignored
  ret = X509_load_cert_crl_file(lookup, "/home/osboxes/cpp/ca/root/ca/intermediate/crl/intermediate.crl.pem", X509_FILETYPE_PEM);
  printf("X509_load_cert_crl_file ret = %d\n", ret);

  // X509_V_FLAG_CRL_CHECK enables CRL checking for the certificate chain leaf certificate. An error occurs if a suitable CRL cannot be found.
  // X509_V_FLAG_CRL_CHECK_ALL enables CRL checking for the entire certificate chain. If check all, intermediate and root certificate not
  //    on the CRL will result in verification error - 'X509_V_ERR_UNABLE_TO_GET_CRL'
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK /* | X509_V_FLAG_CRL_CHECK_ALL*/);

  // Ask for client certificate
  // verify_callback will be used as preverify
  // formal verify need to be called after SSL_accept()
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
  // SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  // end of setting up
  // accept_bio represents a factory
  auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("8080"));

  // blocks until a client tries to connect to the server
  // it produces a new socket BIO to represent that connection
  // bind
  if (BIO_do_accept(accept_bio.get()) <= 0)
  {
    my::print_errors_and_exit("Error in BIO_do_accept");
  }

  static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
    close(fd);
  };

  signal(SIGINT, [](int) { shutdown_the_socket(); });

  while (auto bio = my::accept_new_tcp_connection(accept_bio.get()))
  {
    // 0 means server
    bio = std::move(bio) | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0));

    // verify the client certificate
    SSL *ssl = my::get_ssl(bio.get());
    SSL_accept(ssl);
    my::verify_the_certificate(ssl, "localhost");

    try
    {
      std::string request = my::receive_http_message(bio.get());
      printf("Got request:\n");
      printf("%s\n", request.c_str());
      my::send_http_response(bio.get(), "okay cool\n");
    }
    catch (const std::exception &ex)
    {
      printf("Worker exited with exception:\n%s\n", ex.what());
    }
  }

  printf("\nClean exit!\n");
}