#include <libcryptosec/ByteArray.h>

#include <osstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe ByteArray.
 */
class ByteArrayTest : public ::testing::Test {

protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    static std::string stringASCII;
    static std::string stringHex;
    static const char compChar;
    static const unsigned char *uchr;
    static unsigned int size;

};

/*
 * Initialization of variables used in the tests
 */
std::string ByteArrayTest::stringASCII = "I found it! Silksong release date is [redacted]";
std::string ByteArrayTest::stringHex = "4920666F756E64206974212053696C6B736F6E672072656C656173652064617465206973205B72656461637465645D";
const char ByteArrayTest::compChar = '!';
const unsigned char chr[] = "I found it! Silksong release date is [redacted]";
const unsigned char* ByteArrayTest::uchr = chr;
unsigned int ByteArrayTest::size = 47;


/**
 * @brief Tests ByteArray functionalities from a string constructor
 */
TEST_F(ByteArrayTest, FromString) {
    ByteArray ba(ByteArrayTest::stringASCII);
    ByteArray baCopy = ba;
    std::istringstream *iss = ba.toStream();

    std::string issValue = iss->str();
    char at = ba.at(10);

    ASSERT_EQ(at, ByteArrayTest::compChar);
    ASSERT_EQ(ba.toString(), ByteArrayTest::stringASCII);
    ASSERT_EQ(ba.toHex(), ByteArrayTest::stringHex);
    ASSERT_EQ(ba.size(), ByteArrayTest::size);

    ASSERT_EQ(baCopy, ba);
    ASSERT_EQ(issValue, ByteArrayTest::stringASCII);
    ASSERT_EQ(ba[10], ByteArrayTest::compChar);

    ASSERT_TRUE(ba == baCopy);
    ASSERT_FALSE(ba != baCopy);
}

/**
 * @brief Tests ByteArray functionalities from an unsigned char constructor
 */
TEST_F(ByteArrayTest, FromUnsignedChar) {
    ByteArray ba(ByteArrayTest::uchr, ByteArrayTest::size);
    ByteArray baCopy = ba;
    std::istringstream *iss = ba.toStream();

    std::string issValue = iss->str();
    char at = ba.at(10);

    ASSERT_EQ(at, ByteArrayTest::compChar);
    ASSERT_EQ(ba.toHex(), ByteArrayTest::stringHex);
    ASSERT_EQ(ba.size(), ByteArrayTest::size);

    ASSERT_EQ(baCopy, ba);
    ASSERT_EQ(issValue, ByteArrayTest::stringASCII);
    ASSERT_EQ(ba[10], ByteArrayTest::compChar);

    ASSERT_TRUE(ba == baCopy);
    ASSERT_FALSE(ba != baCopy);
}

/**
 * @brief Tests ByteArray functionalities from an ostringstream constructor
 */
TEST_F(ByteArrayTest, FromOStringStream) {
    std::ostringstream oss;
    oss.str(ByteArrayTest::stringASCII);

    ByteArray ba(&oss);
    ByteArray baCopy = ba;
    std::istringstream *iss = ba.toStream();

    std::string issValue = iss->str();
    char at = ba.at(10);

    ASSERT_EQ(at, ByteArrayTest::compChar);
    ASSERT_EQ(ba.toHex(), ByteArrayTest::stringHex);
    ASSERT_EQ(ba.size(), ByteArrayTest::size);

    ASSERT_EQ(baCopy, ba);
    ASSERT_EQ(issValue, ByteArrayTest::stringASCII);
    ASSERT_EQ(ba[10], ByteArrayTest::compChar);

    ASSERT_TRUE(ba == baCopy);
    ASSERT_FALSE(ba != baCopy);
}