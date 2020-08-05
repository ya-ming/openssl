#include "gtest/gtest.h"

#include "../evp/obselete/SymmetricCryptographyTest.cpp"
#include "../evp/SymmetricCipherTest.cpp"
#include "../evp/AuthenticatedSymmetricCipherTest.cpp"

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
