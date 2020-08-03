#include "gtest/gtest.h"

#include "../evp/SymmetricCryptographyTest.cpp"
#include "../evp/SymmetricCipherTest.cpp"

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
