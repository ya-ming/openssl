#include "my.h"

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
#endif

  if (SSL_CTX_use_certificate_file(ctx.get(), "server-certificate.pem", SSL_FILETYPE_PEM) <= 0)
  {
    my::print_errors_and_exit("Error loading server certificate");
  }

  if (SSL_CTX_use_PrivateKey_file(ctx.get(), "server-private-key.pem", SSL_FILETYPE_PEM) <= 0)
  {
    my::print_errors_and_exit("Error loading server private key");
  }
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
    // 0 means sever
    bio = std::move(bio) | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0));

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