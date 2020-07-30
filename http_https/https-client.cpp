#include "my.h"

int main(int argc, char *argv[])
{
  char *hostname = "duckduckgo.com";
  char *port = "443";
  if (argc > 2)
  {
    hostname = argv[1];
    port = argv[2];
  }

  char *server_cert_path = "server-cert.pem";
  char *key_path = "client-key.pem";
  char *client_cert_path = "client-cert.pem";
  if (argc > 3)
  {
    if (strncmp("ca", argv[3], 2) == 0)
    {
      server_cert_path = "../../ca/root/ca/intermediate/certs/ca-chain.cert.pem";
      key_path = "../../ca/root/ca/intermediate/private/client.key.pem";
      client_cert_path = "../../ca/root/ca/intermediate/certs/ca-chain-client.cert.pem";
    }
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
  SSL_load_error_strings();
#endif

// Setting up SSL/TLS
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
  auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif

  if (strcmp(hostname, "localhost") != 0)
  {
    if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1)
    {
      my::print_errors_and_exit("Error setting up trust store");
    }
  }
  else
  {
    if (SSL_CTX_load_verify_locations(ctx.get(), server_cert_path, nullptr) != 1)
    {
      my::print_errors_and_exit("Error setting up trust store");
    }

    if (SSL_CTX_use_certificate_file(ctx.get(), client_cert_path, SSL_FILETYPE_PEM) <= 0)
    {
      my::print_errors_and_exit("Error loading client certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx.get(), key_path, SSL_FILETYPE_PEM) <= 0)
    {
      my::print_errors_and_exit("Error loading server private key");
    }
  }
  // Endof setting up

  std::string hostString;
  hostString.append(hostname);
  hostString.append(":");
  hostString.append(port);

  auto bio = my::UniquePtr<BIO>(BIO_new_connect(hostString.c_str()));
  if (bio == nullptr)
  {
    my::print_errors_and_exit("Error in BIO_new_connect");
  }
  if (BIO_do_connect(bio.get()) <= 0)
  {
    my::print_errors_and_exit("Error in BIO_do_connect");
  }

  auto ssl_bio = std::move(bio) | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1));
  SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), hostname);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  SSL_set1_host(my::get_ssl(ssl_bio.get()), hostname);
#endif
  if (BIO_do_handshake(ssl_bio.get()) <= 0)
  {
    my::print_errors_and_exit("Error in BIO_do_handshake");
  }
  my::verify_the_certificate(my::get_ssl(ssl_bio.get()), hostname);
  my::send_http_request(ssl_bio.get(), "GET / HTTP/1.1", "duckduckgo.com");
  std::string response = my::receive_http_message(ssl_bio.get());
  printf("%s", response.c_str());
}
