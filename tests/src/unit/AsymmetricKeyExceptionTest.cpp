#include "libcryptosec/exception/AsymmetricCipherException.h"
#include "libcryptosec/exception/AsymmetricKeyException.h"
#include <libcryptosec/exception/LibCryptoSecException.h>
#include <sstream>
#include <gtest/gtest.h>

class AsymmetricKeyExceptionTest : public ::testing::Test {
  public:
  std::string getMessage() {
    std::string message { AsymmetricKeyException("valores").getMessage() };
    return message;
  }

  std::string toString() {
    std::string toString { AsymmetricKeyException("valores").toString()};
    return toString;
  }

  std::string throwUnknown() {
    auto unknown { AsymmetricKeyException(AsymmetricKeyException::UNKNOWN, "here")};
    return unknown.getMessage();
  }

  std::string throwSetNoValue() {
    auto value { AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE, "here") };
    return value.getMessage();
  }

  std::string throwInvalidType() {
    auto invalid_type { AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "here") };
    return invalid_type.getMessage();
  }

  std::string throwInternalError() {
    auto internal { AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "here") };
    return internal.getMessage();
  }

  std::string throwUnavailableError() {
    auto unavailable_key { AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "here") };
    return unavailable_key.getMessage();
  }

  std::string throwInvalidAsymmetricKey() {
    auto invalid_asymmetric { AsymmetricKeyException(AsymmetricKeyException::INVALID_ASYMMETRIC_KEY, "here") };
    return invalid_asymmetric.getMessage();
  }

  protected:
  static std::string where;
};

std::string AsymmetricKeyExceptionTest::where {"here"};

TEST_F(AsymmetricKeyExceptionTest, ToString) {
  auto result = toString();
  ASSERT_EQ(result, "AsymmetricKeyException. Called by: valores.");
}

TEST_F(AsymmetricKeyExceptionTest, ThrowUnknown) {
  auto result = throwUnknown();
  ASSERT_EQ(result, "Unknown error. Details: .");
}

TEST_F(AsymmetricKeyExceptionTest, ThrowNoValue) {
  auto result = throwSetNoValue();
  ASSERT_EQ(result, "Set no value. Details: .");
}

TEST_F(AsymmetricKeyExceptionTest, ThrowInvalid) {
  auto result = throwInvalidType();
  ASSERT_EQ(result, "Invalid asymmetric key type. Details: .");
}

TEST_F(AsymmetricKeyExceptionTest, ThrowInternal) {
  auto result = throwInternalError();
  ASSERT_EQ(result, "Internal error. Details: .");
}

TEST_F(AsymmetricKeyExceptionTest, ThrowUnavailable) {
  auto result = throwUnavailableError();
  ASSERT_EQ(result, "Asymmetric key not available. Details: .");
}

TEST_F(AsymmetricKeyExceptionTest, ThrowInvalidAsymmetric) {
  auto result = throwInvalidAsymmetricKey();
  ASSERT_EQ(result, "Invalid asymmetric key. Details: .");
}
