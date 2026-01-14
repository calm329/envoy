#include "source/extensions/filters/http/mcp_router/session_codec.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace McpRouter {
namespace {

using ::testing::Pair;
using ::testing::UnorderedElementsAre;

TEST(SessionCodecTest, EncodeDecode) {
  EXPECT_EQ("aGVsbG8=", SessionCodec::encode("hello"));
  EXPECT_EQ("hello", SessionCodec::decode("aGVsbG8="));
  EXPECT_EQ("", SessionCodec::decode(SessionCodec::encode("")));
}

TEST(SessionCodecTest, BuildCompositeSessionId) {
  const std::string id = SessionCodec::buildCompositeSessionId(
      "route1", "user1", {{"backend1", "s1"}, {"backend2", "s2"}});

  EXPECT_THAT(id, testing::StartsWith("route1@" + SessionCodec::encode("user1") + "@"));
  EXPECT_THAT(id, testing::HasSubstr("backend1:" + SessionCodec::encode("s1")));
  EXPECT_THAT(id, testing::HasSubstr("backend2:" + SessionCodec::encode("s2")));
}

TEST(SessionCodecTest, ParseCompositeSessionId) {
  std::string composite = absl::StrCat("route1@", SessionCodec::encode("user1"),
                                       "@backend1:", SessionCodec::encode("s1"),
                                       ",backend2:", SessionCodec::encode("s2"));

  auto result = SessionCodec::parseCompositeSessionId(composite);

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result->route, "route1");
  EXPECT_EQ(result->subject, "user1");
  EXPECT_THAT(result->backend_sessions,
              UnorderedElementsAre(Pair("backend1", "s1"), Pair("backend2", "s2")));
}

// Test that subjects containing splitter are correctly handled.
TEST(SessionCodecTest, SubjectWithAtSymbol) {
  const std::string subject_with_at = "user@example.com";
  const std::string id = SessionCodec::buildCompositeSessionId("my_route", subject_with_at,
                                                               {{"backend1", "session1"}});

  auto result = SessionCodec::parseCompositeSessionId(id);

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result->route, "my_route");
  EXPECT_EQ(result->subject, subject_with_at);
  EXPECT_THAT(result->backend_sessions, UnorderedElementsAre(Pair("backend1", "session1")));
}

TEST(SessionCodecTest, ParseInvalidCustomFormat) {
  const std::vector<std::string> invalid_inputs = {
      "invalid",
      "no_backends@user",
      "route@user@",         // Empty backends
      "route@user@backend",  // Missing colon
      "route@user@:session", // Empty backend name
  };

  for (const auto& input : invalid_inputs) {
    EXPECT_FALSE(SessionCodec::parseCompositeSessionId(input).ok()) << "Input: " << input;
  }
}

// Encryption tests.
class SessionCodecEncryptionTest : public ::testing::Test {
protected:
  // Valid 32-byte (256-bit) AES key.
  const std::string valid_key_ = "01234567890123456789012345678901";
  // Invalid key (wrong size).
  const std::string invalid_key_ = "tooshort";
};

TEST_F(SessionCodecEncryptionTest, EncryptDecryptRoundTrip) {
  const std::string plaintext = "hello world session data";

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  // Encrypted data should be different from plaintext.
  EXPECT_NE(encrypted, plaintext);

  // Decrypt should recover the original plaintext.
  auto result = SessionCodec::decodeAndDecrypt(encrypted, valid_key_);
  ASSERT_TRUE(result.ok()) << result.status().message();
  EXPECT_EQ(*result, plaintext);
}

TEST_F(SessionCodecEncryptionTest, EncryptDecryptEmptyString) {
  const std::string plaintext;

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  auto result = SessionCodec::decodeAndDecrypt(encrypted, valid_key_);
  ASSERT_TRUE(result.ok()) << result.status().message();
  EXPECT_EQ(*result, plaintext);
}

TEST_F(SessionCodecEncryptionTest, EncryptDecryptLargeData) {
  // Create a large string.
  std::string plaintext(10000, 'x');

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  auto result = SessionCodec::decodeAndDecrypt(encrypted, valid_key_);
  ASSERT_TRUE(result.ok()) << result.status().message();
  EXPECT_EQ(*result, plaintext);
}

TEST_F(SessionCodecEncryptionTest, EncryptDecryptBinaryData) {
  // Binary data with null bytes and special characters.
  std::string plaintext;
  plaintext.push_back('\0');
  plaintext.push_back('\x01');
  plaintext.push_back('\xff');
  plaintext.append("mixed content");
  plaintext.push_back('\0');

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  auto result = SessionCodec::decodeAndDecrypt(encrypted, valid_key_);
  ASSERT_TRUE(result.ok()) << result.status().message();
  EXPECT_EQ(*result, plaintext);
}

TEST_F(SessionCodecEncryptionTest, EncryptWithInvalidKeyReturnsEmpty) {
  const std::string plaintext = "test data";

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, invalid_key_);
  EXPECT_TRUE(encrypted.empty());
}

TEST_F(SessionCodecEncryptionTest, DecryptWithInvalidKeyReturnsError) {
  const std::string plaintext = "test data";

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  auto result = SessionCodec::decodeAndDecrypt(encrypted, invalid_key_);
  EXPECT_FALSE(result.ok());
}

TEST_F(SessionCodecEncryptionTest, DecryptWithWrongKeyFails) {
  const std::string plaintext = "test data";
  const std::string other_key = "98765432109876543210987654321098";

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  auto result = SessionCodec::decodeAndDecrypt(encrypted, other_key);
  EXPECT_FALSE(result.ok());
  EXPECT_TRUE(absl::IsInvalidArgument(result.status()));
}

TEST_F(SessionCodecEncryptionTest, DecryptTamperedDataFails) {
  const std::string plaintext = "test data";

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  // Tamper with the encrypted data by modifying a character.
  std::string tampered = encrypted;
  if (!tampered.empty()) {
    tampered[tampered.size() / 2] ^= 0x01;
  }

  auto result = SessionCodec::decodeAndDecrypt(tampered, valid_key_);
  EXPECT_FALSE(result.ok());
}

TEST_F(SessionCodecEncryptionTest, DecryptTruncatedDataFails) {
  const std::string plaintext = "test data";

  std::string encrypted = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  // Truncate the encrypted data.
  std::string truncated = encrypted.substr(0, encrypted.size() / 2);

  auto result = SessionCodec::decodeAndDecrypt(truncated, valid_key_);
  EXPECT_FALSE(result.ok());
}

TEST_F(SessionCodecEncryptionTest, DecryptInvalidBase64Fails) {
  auto result = SessionCodec::decodeAndDecrypt("!!!invalid-base64!!!", valid_key_);
  EXPECT_FALSE(result.ok());
}

TEST_F(SessionCodecEncryptionTest, DifferentEncryptionsProduceDifferentCiphertexts) {
  const std::string plaintext = "same plaintext";

  std::string encrypted1 = SessionCodec::encryptAndEncode(plaintext, valid_key_);
  std::string encrypted2 = SessionCodec::encryptAndEncode(plaintext, valid_key_);

  ASSERT_FALSE(encrypted1.empty());
  ASSERT_FALSE(encrypted2.empty());

  // Each encryption should produce different ciphertext due to random IV.
  EXPECT_NE(encrypted1, encrypted2);

  // Both should decrypt to the same plaintext.
  auto result1 = SessionCodec::decodeAndDecrypt(encrypted1, valid_key_);
  auto result2 = SessionCodec::decodeAndDecrypt(encrypted2, valid_key_);

  ASSERT_TRUE(result1.ok());
  ASSERT_TRUE(result2.ok());
  EXPECT_EQ(*result1, plaintext);
  EXPECT_EQ(*result2, plaintext);
}

// End-to-end test: build composite session ID, encrypt, decrypt, and parse.
TEST_F(SessionCodecEncryptionTest, EncryptedCompositeSessionIdRoundTrip) {
  const std::string route = "my_route";
  const std::string subject = "user@example.com";
  const absl::flat_hash_map<std::string, std::string> backend_sessions = {
      {"backend1", "session_id_1"},
      {"backend2", "session_id_2"},
  };

  // Build composite session ID.
  std::string composite = SessionCodec::buildCompositeSessionId(route, subject, backend_sessions);
  ASSERT_FALSE(composite.empty());

  // Encrypt the composite session ID.
  std::string encrypted = SessionCodec::encryptAndEncode(composite, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  // The encrypted version should be opaque (not contain plaintext route/subject).
  EXPECT_EQ(encrypted.find(route), std::string::npos);
  EXPECT_EQ(encrypted.find(subject), std::string::npos);

  // Decrypt the session ID.
  auto decrypt_result = SessionCodec::decodeAndDecrypt(encrypted, valid_key_);
  ASSERT_TRUE(decrypt_result.ok()) << decrypt_result.status().message();

  // Parse the decrypted composite session ID.
  auto parse_result = SessionCodec::parseCompositeSessionId(*decrypt_result);
  ASSERT_TRUE(parse_result.ok()) << parse_result.status().message();

  // Verify all fields are recovered correctly.
  EXPECT_EQ(parse_result->route, route);
  EXPECT_EQ(parse_result->subject, subject);
  EXPECT_THAT(parse_result->backend_sessions,
              UnorderedElementsAre(Pair("backend1", "session_id_1"),
                                   Pair("backend2", "session_id_2")));
}

// Test that tampering with encrypted composite session ID is detected.
TEST_F(SessionCodecEncryptionTest, TamperedEncryptedCompositeSessionIdRejected) {
  const std::string composite =
      SessionCodec::buildCompositeSessionId("route", "user", {{"backend", "session"}});

  std::string encrypted = SessionCodec::encryptAndEncode(composite, valid_key_);
  ASSERT_FALSE(encrypted.empty());

  // Tamper with the middle of the encrypted data.
  std::string tampered = encrypted;
  tampered[tampered.size() / 2] ^= 0xFF;

  // Decryption should fail due to authentication tag mismatch.
  auto result = SessionCodec::decodeAndDecrypt(tampered, valid_key_);
  EXPECT_FALSE(result.ok());
  EXPECT_TRUE(absl::IsInvalidArgument(result.status()));
}

} // namespace
} // namespace McpRouter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
