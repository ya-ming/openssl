#include "my.h"

int main()
{
  // auto bio = my::UniquePtr<BIO>(BIO_new_connect("duckduckgo.com:80"));
  auto bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:8080"));
  if (bio == nullptr)
  {
    my::print_errors_and_exit("Error in BIO_new_connect");
  }
  if (BIO_do_connect(bio.get()) <= 0)
  {
    my::print_errors_and_exit("Error in BIO_do_connect");
  }

  my::send_http_request(bio.get(), "GET / HTTP/1.1", "duckduckgo.com");
  std::string response = my::receive_http_message(bio.get());
  printf("%s", response.c_str());
}