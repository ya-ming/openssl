#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

using namespace std;

namespace my
{
  template <class T>
  struct DeleterOf;
  // template <>
  // struct DeleterOf<SSL_CTX>
  // {
  //   void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
  // };
  // template <>
  // struct DeleterOf<SSL>
  // {
  //   void operator()(SSL *p) const { SSL_free(p); }
  // };
  template <>
  struct DeleterOf<BIO>
  {
    void operator()(BIO *p) const { BIO_free_all(p); }
  };
  template <>
  struct DeleterOf<BIO_METHOD>
  {
    void operator()(BIO_METHOD *p) const { BIO_meth_free(p); }
  };
  template <>
  struct DeleterOf<SSL_CTX>
  {
    void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
  };

  template <class OpenSSLType>
  using UniquePtr = std::unique_ptr<OpenSSLType, my::DeleterOf<OpenSSLType>>;

  my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper)
  {
    BIO_push(upper.get(), lower.release());
    return upper;
  }

  class StringBIO
  {
    std::string str_;
    my::UniquePtr<BIO_METHOD> methods_;
    my::UniquePtr<BIO> bio_;

  public:
    StringBIO(StringBIO &&) = delete;
    StringBIO &operator=(StringBIO &&) = delete;

    explicit StringBIO()
    {
      methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
      if (methods_ == nullptr)
      {
        throw std::runtime_error("StringBIO: error in BIO_meth_new");
      }

      BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
        std::string *str = reinterpret_cast<std::string *>(BIO_get_data(bio));
        str->append(data, len);
        return len;
      });
      bio_.reset(BIO_new(methods_.get()));
      if (bio_ == nullptr)
      {
        throw std::runtime_error("StringBIO: error in BIO_new");
      }
      BIO_set_data(bio_.get(), &str_);
      BIO_set_init(bio_.get(), 1);
    }

    BIO *bio() { return bio_.get(); }
    std::string str() && { return std::move(str_); }
  };

  [[noreturn]] void print_errors_and_exit(const char *message)
  {
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  [[noreturn]] void print_errors_and_throw(const char *message)
  {
    my::StringBIO bio;
    ERR_print_errors(bio.bio());
    throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
  }

  std::string receive_some_data(BIO *bio)
  {
    char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0)
    {
      my::print_errors_and_throw("error in BIO_read");
    }
    else if (len > 0)
    {
      return std::string(buffer, len);
    }
    else if (BIO_should_retry(bio))
    {
      return receive_some_data(bio);
    }
    else
    {
      my::print_errors_and_throw("empty BIO_read");
    }
  }

  std::vector<std::string> split_headers(const std::string &text)
  {
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n"))
    {
      lines.push_back(std::string(start, end));
      start = end + 2;
    }
    return lines;
  }

  std::string receive_http_message(BIO *bio)
  {
    std::string headers = my::receive_some_data(bio);
    char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr)
    {
      headers += my::receive_some_data(bio);
      end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }

    std::string body = std::string(end_of_headers + 4, &headers[headers.size()]);
    headers.resize(end_of_headers + 2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string &line : my::split_headers(headers))
    {
      if (const char *colon = strchr(line.c_str(), ':'))
      {
        auto header_name = std::string(&line[0], colon);
        if (header_name == "Content-Length")
        {
          content_length = std::stoul(colon + 1);
        }
      }
    }

    while (body.size() < content_length)
    {
      body += my::receive_some_data(bio);
    }

    return headers + "\r\n" + body;
  }

  void send_http_request(BIO *bio, const std::string &line, const std::string &host)
  {
    std::string request = line + "\r\n";
    request += "Host: " + host + "\r\n";
    request += "\r\n";

    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
  }

  SSL *get_ssl(BIO *bio)
  {
    SSL *ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr)
    {
      my::print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
  }

  void verify_the_certificate(SSL *ssl, const std::string &expected_hostname)
  {
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK)
    {
      const char *message = X509_verify_cert_error_string(err);
      fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
      exit(1);
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr)
    {
      fprintf(stderr, "No certificate was presented by the server\n");
      exit(1);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1)
    {
      fprintf(stderr, "Certificate verification error: X509_check_host\n");
      exit(1);
    }
#else
    // X509_check_host is called automatically during verification,
    // because we set it up in main()
    (void)expected_hostname;
#endif
  }

} // namespace my

int main(int argc, char* argv[])
{
  char *hostname = "duckduckgo.com";
  char *port = "443";
  if (argc > 2)
  {
    hostname = argv[1];
    port = argv[2];
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
  if (SSL_CTX_load_verify_locations(ctx.get(), "server-certificate.pem", nullptr) != 1)
  {
    my::print_errors_and_exit("Error setting up trust store");
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
