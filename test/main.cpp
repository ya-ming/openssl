#include "gtest/gtest.h"

#include "../symmetric-cryptography/symmetric-cryptography-test.cpp"

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}