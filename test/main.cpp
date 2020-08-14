#include "gtest/gtest.h"

#include "../evp/obselete/SymmetricCryptographyTest.cpp"
#include "../evp/SymmetricCipherTest.cpp"
#include "../evp/AuthenticatedSymmetricCipherTest.cpp"
#include "../evp/AsymmetricEnvelopeTest.cpp"
#include "../evp/KeyAndParameterGenerationTest.cpp"
#include "../evp/DiffieHellmanTest.cpp"
#include "../evp/DigestTest.cpp"

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
