#include "my.h"

int main()
{
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