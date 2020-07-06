#include "common.h"

namespace mls {

bytes
to_bytes(const std::string& ascii)
{
  return bytes(ascii.begin(), ascii.end());
}

std::string
to_hex(const bytes& data)
{
  std::stringstream hex(std::ios_base::out);
  hex.flags(std::ios::hex);
  for (const auto& byte : data) {
    hex << std::setw(2) << std::setfill('0') << int(byte);
  }
  return hex.str();
}

bytes
from_hex(const std::string& hex)
{
  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  int len = hex.length() / 2;
  bytes out(len);
  for (int i = 0; i < len; i += 1) {
    std::string byte = hex.substr(2 * i, 2);
    out[i] = strtol(byte.c_str(), nullptr, 16);
  }

  return out;
}

bytes&
operator+=(bytes& lhs, const bytes& rhs)
{
  // Not sure what the default argument is here
  // NOLINTNEXTLINE(fuchsia-default-arguments)
  lhs.insert(lhs.end(), rhs.begin(), rhs.end());
  return lhs;
}

bytes
operator+(const bytes& lhs, const bytes& rhs)
{
  bytes out = lhs;
  out += rhs;
  return out;
}

bytes
operator^(const bytes& lhs, const bytes& rhs)
{
  if (lhs.size() != rhs.size()) {
    throw InvalidParameterError("XOR with unequal size");
  }

  bytes out(lhs.size());
  for (size_t i = 0; i < lhs.size(); ++i) {
    out[i] = lhs[i] ^ rhs[i];
  }
  return out;
}

std::ostream&
operator<<(std::ostream& out, const bytes& data)
{
  // Adjust this threshold to make output more compact
  size_t threshold = 0xffff;
  if (data.size() < threshold) {
    return out << to_hex(data);
  }

  bytes abbrev(data.begin(), data.begin() + threshold);
  return out << to_hex(abbrev) << "...";
}

const std::array<CipherSuite, 6> all_supported_suites = {
  CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
  CipherSuite::P256_AES128GCM_SHA256_P256,
  CipherSuite::X25519_CHACHA20POLY1305_SHA256_Ed25519,
  CipherSuite::X448_AES256GCM_SHA512_Ed448,
  CipherSuite::P521_AES256GCM_SHA512_P521,
  CipherSuite::X448_CHACHA20POLY1305_SHA512_Ed448,
};

SignatureScheme
suite_signature_scheme(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::X25519_AES128GCM_SHA256_Ed25519:
    case CipherSuite::X25519_CHACHA20POLY1305_SHA256_Ed25519:
      return SignatureScheme::Ed25519;

    case CipherSuite::P256_AES128GCM_SHA256_P256:
      return SignatureScheme::P256_SHA256;

    case CipherSuite::X448_AES256GCM_SHA512_Ed448:
    case CipherSuite::X448_CHACHA20POLY1305_SHA512_Ed448:
      return SignatureScheme::Ed448;

    case CipherSuite::P521_AES256GCM_SHA512_P521:
      return SignatureScheme::P521_SHA512;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

size_t
suite_nonce_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::X25519_AES128GCM_SHA256_Ed25519:
    case CipherSuite::X25519_CHACHA20POLY1305_SHA256_Ed25519:
    case CipherSuite::P256_AES128GCM_SHA256_P256:
    case CipherSuite::X448_AES256GCM_SHA512_Ed448:
    case CipherSuite::X448_CHACHA20POLY1305_SHA512_Ed448:
    case CipherSuite::P521_AES256GCM_SHA512_P521:
      return 12;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

size_t
suite_key_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::X25519_AES128GCM_SHA256_Ed25519:
    case CipherSuite::P256_AES128GCM_SHA256_P256:
      return 16;

    case CipherSuite::X448_AES256GCM_SHA512_Ed448:
    case CipherSuite::P521_AES256GCM_SHA512_P521:
    case CipherSuite::X25519_CHACHA20POLY1305_SHA256_Ed25519:
    case CipherSuite::X448_CHACHA20POLY1305_SHA512_Ed448:
      return 32;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

} // namespace mls
