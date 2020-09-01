#include "mls/common.h"

namespace mls {

uint64_t
seconds_since_epoch()
{
  // TODO(RLB) This should use std::chrono, but that seems not to be available
  // on some platforms.
  return std::time(nullptr);
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

template<CipherSuite CS>
extern const CipherDetails cipher_details;

template<>
const CipherDetails
  cipher_details<CipherSuite::X25519_AES128GCM_SHA256_Ed25519>{
    32,
    16,
    12,
    SignatureScheme::Ed25519,
  };

template<>
const CipherDetails cipher_details<CipherSuite::P256_AES128GCM_SHA256_P256>{
  32,
  16,
  12,
  SignatureScheme::P256_SHA256,
};

template<>
const CipherDetails
  cipher_details<CipherSuite::X25519_CHACHA20POLY1305_SHA256_Ed25519>{
    32,
    32,
    12,
    SignatureScheme::Ed25519,
  };

template<>
const CipherDetails cipher_details<CipherSuite::X448_AES256GCM_SHA512_Ed448>{
  64,
  32,
  12,
  SignatureScheme::Ed448,
};

template<>
const CipherDetails cipher_details<CipherSuite::P521_AES256GCM_SHA512_P521>{
  64,
  32,
  12,
  SignatureScheme::P521_SHA512,
};

template<>
const CipherDetails
  cipher_details<CipherSuite::X448_CHACHA20POLY1305_SHA512_Ed448>{
    64,
    32,
    12,
    SignatureScheme::Ed448,
  };

const CipherDetails&
CipherDetails::get(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::X25519_AES128GCM_SHA256_Ed25519:
      return cipher_details<CipherSuite::X25519_AES128GCM_SHA256_Ed25519>;

    case CipherSuite::P256_AES128GCM_SHA256_P256:
      return cipher_details<CipherSuite::P256_AES128GCM_SHA256_P256>;

    case CipherSuite::X25519_CHACHA20POLY1305_SHA256_Ed25519:
      return cipher_details<
        CipherSuite::X25519_CHACHA20POLY1305_SHA256_Ed25519>;

    case CipherSuite::X448_AES256GCM_SHA512_Ed448:
      return cipher_details<CipherSuite::X448_AES256GCM_SHA512_Ed448>;

    case CipherSuite::P521_AES256GCM_SHA512_P521:
      return cipher_details<CipherSuite::P521_AES256GCM_SHA512_P521>;

    case CipherSuite::X448_CHACHA20POLY1305_SHA512_Ed448:
      return cipher_details<CipherSuite::X448_CHACHA20POLY1305_SHA512_Ed448>;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

} // namespace mls
