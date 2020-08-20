#include <gtest/gtest.h>
#include <string>

#define CODE_A 0x18
#define CODE_B 0x13
#define CODE_C 0xE
#define CODE_D 0x12
#define CODE_E 0x10
#define CODE_F 0x16
#define CODE_G 0xB
#define CODE_H 0x5
#define CODE_I 0xC
#define CODE_J 0x1A
#define CODE_K 0x1E
#define CODE_L 0x9
#define CODE_M 0x7
#define CODE_N 0x6
#define CODE_O 0x3
#define CODE_P 0xD
#define CODE_Q 0x1D
#define CODE_R 0xA
#define CODE_S 0x14
#define CODE_T 0x1
#define CODE_U 0x1C
#define CODE_V 0xF
#define CODE_W 0x19
#define CODE_X 0x17
#define CODE_Y 0x15
#define CODE_Z 0x11
#define CODE_3 0x2
#define CODE_4 0x8
#define CODE_8 0x1F
#define CODE_9 0x4
#define CODE_ADD 0x1B
#define CODE_DIV 0

class SimplifiedLorenzCipherMachineTest : public ::testing::Test
{
protected:
    // You can remove any or all of the following functions if their bodies would
    // be empty.

    SimplifiedLorenzCipherMachineTest()
    {
        // You can do set-up work for each test here.
        code_to_string[0x18] = 'A';
        code_to_string[0x13] = 'B';
        code_to_string[0xE] = 'C';
        code_to_string[0x12] = 'D';
        code_to_string[0x10] = 'E';
        code_to_string[0x16] = 'F';
        code_to_string[0xB] = 'G';
        code_to_string[0x5] = 'H';
        code_to_string[0xC] = 'I';
        code_to_string[0x1A] = 'J';
        code_to_string[0x1E] = 'K';
        code_to_string[0x9] = 'L';
        code_to_string[0x7] = 'M';
        code_to_string[0x6] = 'N';
        code_to_string[0x3] = 'O';
        code_to_string[0xD] = 'P';
        code_to_string[0x1D] = 'Q';
        code_to_string[0xA] = 'R';
        code_to_string[0x14] = 'S';
        code_to_string[0x1] = 'T';
        code_to_string[0x1C] = 'U';
        code_to_string[0xF] = 'V';
        code_to_string[0x19] = 'W';
        code_to_string[0x17] = 'X';
        code_to_string[0x15] = 'Y';
        code_to_string[0x11] = 'Z';
        code_to_string[0x2] = '3';
        code_to_string[0x8] = '4';
        code_to_string[0x1F] = '8';
        code_to_string[0x4] = '9';
        code_to_string[0x1B] = '+';
        code_to_string[0] = '/';
    }

    ~SimplifiedLorenzCipherMachineTest() override
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
    // for SymmetricCipher.
    char code_to_string[100];
};

int encipher(int input, int key)
{
    int output = 0;
    output = input ^ key;

    return output;
}

#define K_SIZE 14
#define S_SZIE 4
const int wheel_k[] = {CODE_A, CODE_B, CODE_C, CODE_D, CODE_E, CODE_F, CODE_G, CODE_H, CODE_I, CODE_J, CODE_K, CODE_L, CODE_M, CODE_N};
const int wheel_s[] = {CODE_A, CODE_A, CODE_B, CODE_B};

void encipher(int *input, int size, int *output, int k, int s)
{
    k = k % 14;
    s = s % 4;

    for (int i = 0; i < size; i++)
    {
        output[i] = encipher(input[i], wheel_k[k]);
        output[i] = encipher(output[i], wheel_s[s]);

        k++;
        s++;
        if (k == K_SIZE)
            k = 0;
        if (s == S_SZIE)
            s = 0;
    }
}

TEST_F(SimplifiedLorenzCipherMachineTest, oneChar)
{
    EXPECT_EQ(CODE_L, encipher(CODE_J, CODE_B));
}

TEST_F(SimplifiedLorenzCipherMachineTest, help_abcd)
{
    EXPECT_EQ(CODE_Q, encipher(CODE_H, CODE_A));
    EXPECT_EQ(CODE_O, encipher(CODE_E, CODE_B));
    EXPECT_EQ(CODE_M, encipher(CODE_L, CODE_C));
    EXPECT_EQ(CODE_8, encipher(CODE_P, CODE_D));
}

TEST_F(SimplifiedLorenzCipherMachineTest, qom8_abcd)
{
    EXPECT_EQ(CODE_H, encipher(CODE_Q, CODE_A));
    EXPECT_EQ(CODE_E, encipher(CODE_O, CODE_B));
    EXPECT_EQ(CODE_L, encipher(CODE_M, CODE_C));
    EXPECT_EQ(CODE_P, encipher(CODE_8, CODE_D));
}

TEST_F(SimplifiedLorenzCipherMachineTest, THE_0_3)
{
    int input[3] = {CODE_T, CODE_H, CODE_E};
    int output[3] = {0};

    encipher(input, 3, output, 0, 3);

    EXPECT_EQ(output[0], CODE_R);
    EXPECT_EQ(output[1], CODE_C);
    EXPECT_EQ(output[2], CODE_N);
}

TEST_F(SimplifiedLorenzCipherMachineTest, RCN_0_3)
{
    int input[3] = {CODE_R, CODE_C, CODE_N};
    int output[3] = {0};

    encipher(input, 3, output, 0, 3);

    EXPECT_EQ(output[0], CODE_T);
    EXPECT_EQ(output[1], CODE_H);
    EXPECT_EQ(output[2], CODE_E);
}

TEST_F(SimplifiedLorenzCipherMachineTest, SECRET9MESSAGE_4_1)
{
    int input[14] = {CODE_S, CODE_E, CODE_C, CODE_R, CODE_E, CODE_T, CODE_9, CODE_M, CODE_E, CODE_S, CODE_S, CODE_A, CODE_G, CODE_E};
    int output[14] = {0};

    encipher(input, 14, output, 4, 1);

    EXPECT_EQ(output[0], CODE_U);
    EXPECT_EQ(output[1], CODE_Y);
    EXPECT_EQ(output[2], CODE_F);
    EXPECT_EQ(output[3], CODE_X);
    EXPECT_EQ(output[4], CODE_9);
    EXPECT_EQ(output[5], CODE_4);
    EXPECT_EQ(output[6], CODE_L);
    EXPECT_EQ(output[7], CODE_F);
    EXPECT_EQ(output[8], CODE_V);
    EXPECT_EQ(output[9], CODE_T);
    EXPECT_EQ(output[10], CODE_8);
    EXPECT_EQ(output[11], CODE_B);
    EXPECT_EQ(output[12], CODE_Q);
    EXPECT_EQ(output[13], CODE_Z);
}

TEST_F(SimplifiedLorenzCipherMachineTest, UYFX94LFVT8BQZ_4_1)
{
    int input[14] = {CODE_U, CODE_Y, CODE_F, CODE_X, CODE_9, CODE_4, CODE_L, CODE_F, CODE_V, CODE_T, CODE_8, CODE_B, CODE_Q, CODE_Z};
    int output[14] = {0};

    encipher(input, 14, output, 4, 1);

    EXPECT_EQ(output[0], CODE_S);
    EXPECT_EQ(output[1], CODE_E);
    EXPECT_EQ(output[2], CODE_C);
    EXPECT_EQ(output[3], CODE_R);
    EXPECT_EQ(output[4], CODE_E);
    EXPECT_EQ(output[5], CODE_T);
    EXPECT_EQ(output[6], CODE_9);
    EXPECT_EQ(output[7], CODE_M);
    EXPECT_EQ(output[8], CODE_E);
    EXPECT_EQ(output[9], CODE_S);
    EXPECT_EQ(output[10], CODE_S);
    EXPECT_EQ(output[11], CODE_A);
    EXPECT_EQ(output[12], CODE_G);
    EXPECT_EQ(output[13], CODE_E);
}

int arrayOfDeltaK[14][53] = {0};
int arrayOfDeltaP[54] = {0};
int arrayofK[54] = {0};
int arrayOfS[54] = {0};

void generateArrayOfDeltaP(int *p)
{
    for (int i = 0; i < 54 - 1; i++)
    {
        arrayOfDeltaP[i] = p[i] ^ p[i+1];
    }
}

void generateArrayOfDeltaK()
{
    for (int l = 0; l < 14; l++)
    {
        for (int i = 0, j = l; i < 54 - 1; i++, j++)
        {
            int j_plus_1 = j + 1;
            if (j == 13)
                j_plus_1 = 0;
            arrayOfDeltaK[l][i] = wheel_k[j] ^ wheel_k[j_plus_1];
            if (j == 14 - 1)
            {
                j = -1;
            }
        }
    }
}

void generateArrayOfK(int k)
{
    for (int i = 0; i < 54; i++)
    {
        arrayofK[i] = wheel_k[k];
        k++;
        if (k == 14)
            k = 0;
    }
}

void generateArrayOfS(int s)
{
    for (int i = 0; i < 54; i++)
    {
        arrayOfS[i] = wheel_s[s];
        s++;
        if (s == 4)
            s = 0;
    }
}

TEST_F(SimplifiedLorenzCipherMachineTest, BreakingThisCipher)
{

    // 99HERE99IS99A99TEST99MESSAGE99FOR99YOU99TO99TRY99OUT99
    int input[54] = {
        CODE_9, CODE_9, CODE_H, CODE_E, CODE_R, CODE_E,
        CODE_9, CODE_9, CODE_I, CODE_S, CODE_9, CODE_9,
        CODE_A, CODE_9, CODE_9, CODE_T, CODE_E, CODE_S,
        CODE_T, CODE_9, CODE_9, CODE_M, CODE_E, CODE_S,
        CODE_S, CODE_A, CODE_G, CODE_E, CODE_9, CODE_9,
        CODE_F, CODE_O, CODE_R, CODE_9, CODE_9, CODE_Y,
        CODE_O, CODE_U, CODE_9, CODE_9, CODE_T, CODE_O,
        CODE_9, CODE_9, CODE_T, CODE_R, CODE_Y, CODE_9,
        CODE_9, CODE_O, CODE_U, CODE_T, CODE_9, CODE_9};
    int output[54] = {0};

    encipher(input, 54, output, 6, 2);

    generateArrayOfDeltaP(input);
    printf("  Delta P: ");
    for (int i = 0; i < 53; i++)
    {
        printf("%c", code_to_string[arrayOfDeltaP[i]]);
    }
    printf("\n");

    int dZ[54] = {0};
    int dZ_xor_dK[14][54] = {0};
    int Z_xor_K7_xor_S[4][54] = {0};

    for (int i = 0, j = 0; i < 54 - 1; i++, j++)
    {
        dZ[i] = output[i] ^ output[i + 1];
    }

    generateArrayOfDeltaK();

    printf("Encoded Z: ");
    for (int i = 0; i < 54; i++)
    {
        printf("%c", code_to_string[output[i]]);
    }
    printf("\n");

    printf("  Delta Z: ");
    for (int i = 0; i < 53; i++)
    {
        printf("%c", code_to_string[dZ[i]]);
    }
    printf("\n");

    for (int l = 0; l < 14; l++)
    {
        printf(" Delta K%d: ", l + 1);
        for (int i = 0; i < 53; i++)
        {
            printf("%c", code_to_string[arrayOfDeltaK[l][i]]);
        }
        printf("\n");

        for (int i = 0; i < 53; i++)
        {
            dZ_xor_dK[l][i] = dZ[i] ^ arrayOfDeltaK[l][i];
        }

        int count_of_0 = 0;
        printf("   dZ ^dK: ");
        for (int i = 0; i < 53; i++)
        {
            if (dZ_xor_dK[l][i] == 0)
            {
                count_of_0++;
            }
            printf("%c", code_to_string[dZ_xor_dK[l][i]]);
        }
        printf(" Number of '/' = %d\n", count_of_0);
    }

    printf("\n");
    generateArrayOfK(6);
    for (int l = 0; l < 4; l++)
    {
        generateArrayOfS(l);
        printf("       S%d: ", l + 1);
        for (int i = 0; i < 54; i++)
        {
            printf("%c", code_to_string[arrayOfS[i]]);
        }
        printf("\n");

        for (int i = 0; i < 54; i++)
        {
            Z_xor_K7_xor_S[l][i] = output[i] ^ arrayofK[i] ^ arrayOfS[i];
        }

        printf("Decrypted m%d: ", l + 1);
        for (int i = 0; i < 54; i++)
        {
            printf("%c", code_to_string[Z_xor_K7_xor_S[l][i]]);
        }
        printf("\n");
    }
}