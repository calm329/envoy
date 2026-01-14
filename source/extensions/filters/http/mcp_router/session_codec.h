#pragma once

#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace McpRouter {

// AES-256-GCM encryption constants.
constexpr size_t kAesKeySize = 32;  // 256 bits for AES-256
constexpr size_t kAesGcmIvSize = 12;  // 96 bits recommended for GCM
constexpr size_t kAesGcmTagSize = 16; // 128 bits authentication tag

/**
 * Codec for encoding and decoding composite MCP session IDs.
 * Combines route, subject, and per-backend session IDs into a single encoded string.
 *
 * When an encryption key is provided, session IDs are encrypted using AES-256-GCM
 * authenticated encryption to prevent tampering and information disclosure.
 */
class SessionCodec {
public:
  /**
   * Base64 encode data (no encryption).
   */
  static std::string encode(const std::string& data);

  /**
   * Base64 decode data (no decryption).
   */
  static std::string decode(const std::string& encoded);

  /**
   * Encrypt data using AES-256-GCM and Base64 encode the result.
   * @param data the plaintext data to encrypt.
   * @param key the 32-byte AES-256 encryption key.
   * @return Base64-encoded ciphertext with IV and authentication tag, or empty string on error.
   */
  static std::string encryptAndEncode(absl::string_view data, absl::string_view key);

  /**
   * Base64 decode and decrypt data using AES-256-GCM.
   * @param encoded the Base64-encoded ciphertext.
   * @param key the 32-byte AES-256 encryption key.
   * @return decrypted plaintext, or error status if decryption/authentication fails.
   */
  static absl::StatusOr<std::string> decodeAndDecrypt(absl::string_view encoded,
                                                       absl::string_view key);

  // Format: {route}@{base64(subject)}@{backend1}:{base64(sid1)},{backend2}:{base64(sid2)}
  static std::string
  buildCompositeSessionId(const std::string& route, const std::string& subject,
                          const absl::flat_hash_map<std::string, std::string>& backend_sessions);

  struct ParsedSession {
    std::string route;
    std::string subject;
    absl::flat_hash_map<std::string, std::string> backend_sessions;
  };
  static absl::StatusOr<ParsedSession> parseCompositeSessionId(const std::string& composite);
};

} // namespace McpRouter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
