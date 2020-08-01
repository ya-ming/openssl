// The fixture for testing class Foo.
class SymmetricCryptographyTest : public ::testing::Test
{
protected:
  // You can remove any or all of the following functions if their bodies would
  // be empty.

  SymmetricCryptographyTest()
  {
    // You can do set-up work for each test here.
  }

  ~SymmetricCryptographyTest() override
  {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  void SetUp() override
  {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  void TearDown() override
  {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

  // Class members declared here can be used by all tests in the test suite
  // for SymmetricCryptography.
};

// Tests factorial of 0.
TEST(SymmetricCryptographyTest, HandlesZeroInput)
{
  EXPECT_EQ(1, 1);
}