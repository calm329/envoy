#include "source/extensions/filters/http/mcp_router/session_codec.h"

#include "source/common/common/base64.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace McpRouter {

std::string SessionCodec::encode(const std::string& data) {
  return Base64::encode(data.data(), data.size());
}

std::string SessionCodec::decode(const std::string& encoded) { return Base64::decode(encoded); }

std::string SessionCodec::encryptAndEncode(absl::string_view data, absl::string_view key) {
  // Validate key size.
  if (key.size() != kAesKeySize) {
    return "";
  }

  // Generate random IV.
  std::vector<uint8_t> iv(kAesGcmIvSize);
  if (RAND_bytes(iv.data(), kAesGcmIvSize) != 1) {
    return "";
  }

  // Create cipher context.
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return "";
  }

  // Initialize encryption with AES-256-GCM.
  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                         reinterpret_cast<const uint8_t*>(key.data()), iv.data()) != 1) {
    return "";
  }

  // Encrypt the data.
  std::vector<uint8_t> ciphertext(data.size() + EVP_MAX_BLOCK_LENGTH);
  int len = 0;
  if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                        reinterpret_cast<const uint8_t*>(data.data()), data.size()) != 1) {
    return "";
  }
  int ciphertext_len = len;

  // Finalize encryption.
  if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
    return "";
  }
  ciphertext_len += len;
  ciphertext.resize(ciphertext_len);

  // Get the authentication tag.
  std::vector<uint8_t> tag(kAesGcmTagSize);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kAesGcmTagSize, tag.data()) != 1) {
    return "";
  }

  // Combine IV + ciphertext + tag and Base64 encode.
  std::string combined;
  combined.reserve(kAesGcmIvSize + ciphertext_len + kAesGcmTagSize);
  combined.append(reinterpret_cast<const char*>(iv.data()), kAesGcmIvSize);
  combined.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
  combined.append(reinterpret_cast<const char*>(tag.data()), kAesGcmTagSize);

  return Base64::encode(combined.data(), combined.size());
}

absl::StatusOr<std::string> SessionCodec::decodeAndDecrypt(absl::string_view encoded,
                                                            absl::string_view key) {
  // Validate key size.
  if (key.size() != kAesKeySize) {
    return absl::InvalidArgumentError("Invalid encryption key size");
  }

  // Base64 decode.
  std::string combined = Base64::decode(std::string(encoded));

  // Minimum size: IV + tag (no ciphertext means empty plaintext).
  if (combined.size() < kAesGcmIvSize + kAesGcmTagSize) {
    return absl::InvalidArgumentError("Invalid encrypted data: too short");
  }

  // Extract IV, ciphertext, and tag.
  const uint8_t* iv = reinterpret_cast<const uint8_t*>(combined.data());
  const size_t ciphertext_len = combined.size() - kAesGcmIvSize - kAesGcmTagSize;
  const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(combined.data() + kAesGcmIvSize);
  const uint8_t* tag =
      reinterpret_cast<const uint8_t*>(combined.data() + kAesGcmIvSize + ciphertext_len);

  // Create cipher context.
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return absl::InternalError("Failed to create cipher context");
  }

  // Initialize decryption with AES-256-GCM.
  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                         reinterpret_cast<const uint8_t*>(key.data()), iv) != 1) {
    return absl::InternalError("Failed to initialize decryption");
  }

  // Decrypt the data.
  std::vector<uint8_t> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
  int len = 0;
  if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
    return absl::InternalError("Decryption failed");
  }
  int plaintext_len = len;

  // Set the authentication tag for verification.
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kAesGcmTagSize,
                          const_cast<uint8_t*>(tag)) != 1) {
    return absl::InternalError("Failed to set authentication tag");
  }

  // Finalize decryption and verify tag.
  if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
    return absl::InvalidArgumentError("Authentication failed: session ID may have been tampered");
  }
  plaintext_len += len;

  return std::string(reinterpret_cast<const char*>(plaintext.data()), plaintext_len);
}

std::string SessionCodec::buildCompositeSessionId(
    const std::string& route, const std::string& subject,
    const absl::flat_hash_map<std::string, std::string>& backend_sessions) {
  std::vector<std::string> backend_parts;
  backend_parts.reserve(backend_sessions.size());

  for (const auto& [backend, session] : backend_sessions) {
    std::string encoded = Base64::encode(session.data(), session.size());
    backend_parts.push_back(absl::StrCat(backend, ":", encoded));
  }

  std::string encoded_subject = Base64::encode(subject.data(), subject.size());
  return absl::StrCat(route, "@", encoded_subject, "@", absl::StrJoin(backend_parts, ","));
}

absl::StatusOr<SessionCodec::ParsedSession>
SessionCodec::parseCompositeSessionId(const std::string& composite) {
  std::vector<std::string> parts = absl::StrSplit(composite, '@');
  if (parts.size() != 3) {
    return absl::InvalidArgumentError("Invalid session format");
  }

  ParsedSession result;
  result.route = parts[0];
  result.subject = Base64::decode(parts[1]);

  if (parts[2].empty()) {
    return absl::InvalidArgumentError("Empty backend sessions");
  }

  std::vector<std::string> backend_parts = absl::StrSplit(parts[2], ',');
  for (const auto& bp : backend_parts) {
    size_t colon = bp.find(':');
    if (colon == std::string::npos || colon == 0) {
      return absl::InvalidArgumentError("Invalid backend session format");
    }
    std::string backend = bp.substr(0, colon);
    std::string encoded_session = bp.substr(colon + 1);
    result.backend_sessions[backend] = Base64::decode(encoded_session);
  }

  return result;
}

} // namespace McpRouter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
