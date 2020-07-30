#include "my.h"

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
  printf(" issuer = %s\n", data);
  X509_NAME_oneline(X509_get_subject_name(err_cert), data, 256);
  printf(" subject = %s\n", data);

  // ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

  return 1;
}

int main()
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

  if (SSL_CTX_use_certificate_file(ctx.get(), "server-cert.pem", SSL_FILETYPE_PEM) <= 0)
  {
    my::print_errors_and_exit("Error loading server certificate");
  }

  if (SSL_CTX_use_PrivateKey_file(ctx.get(), "server-key.pem", SSL_FILETYPE_PEM) <= 0)
  {
    my::print_errors_and_exit("Error loading server private key");
  }

  if (SSL_CTX_load_verify_locations(ctx.get(), "client-cert.pem", nullptr) != 1)
  {
    my::print_errors_and_exit("Error setting up trust store");
  }

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