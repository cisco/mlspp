#include "mls/common.h"

namespace mls {

uint64_t
seconds_since_epoch()
{
  // TODO(RLB) This should use std::chrono, but that seems not to be available
  // on some platforms.
  return std::time(nullptr);
}

///
/// CipherSuites and details
///

using hpke::AEAD;
using hpke::Digest;
using hpke::HPKE;
using hpke::KDF;
using hpke::KEM;
using hpke::Signature;

struct CipherAlgorithms
{
  KEM::ID kem_id;
  KDF::ID kdf_id;
  AEAD::ID aead_id;
  Digest::ID digest_id;
  Signature::ID sig_id;
  SignatureScheme scheme;
};

template<CipherSuite::ID CS>
extern const CipherAlgorithms cipher_algs;

template<>
const CipherAlgorithms
  cipher_algs<CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519>{
    KEM::ID::DHKEM_X25519_SHA256, KDF::ID::HKDF_SHA256,   AEAD::ID::AES_128_GCM,
    Digest::ID::SHA256,           Signature::ID::Ed25519, SignatureScheme::Ed25519,
  };

template<>
const CipherAlgorithms cipher_algs<CipherSuite::ID::P256_AES128GCM_SHA256_P256>{
  KEM::ID::DHKEM_P256_SHA256, KDF::ID::HKDF_SHA256,       AEAD::ID::AES_128_GCM,
  Digest::ID::SHA256,         Signature::ID::P256_SHA256, SignatureScheme::P256_SHA256,
};

template<>
const CipherAlgorithms
  cipher_algs<CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519>{
    KEM::ID::DHKEM_X25519_SHA256, KDF::ID::HKDF_SHA256,
    AEAD::ID::CHACHA20_POLY1305,  Digest::ID::SHA256,
    Signature::ID::Ed25519, SignatureScheme::Ed25519,
  };

template<>
const CipherAlgorithms
  cipher_algs<CipherSuite::ID::X448_AES256GCM_SHA512_Ed448>{
    KEM::ID::DHKEM_X448_SHA512, KDF::ID::HKDF_SHA512, AEAD::ID::AES_256_GCM,
    Digest::ID::SHA512,         Signature::ID::Ed448, SignatureScheme::Ed448,
  };

template<>
const CipherAlgorithms cipher_algs<CipherSuite::ID::P521_AES256GCM_SHA512_P521>{
  KEM::ID::DHKEM_P521_SHA512, KDF::ID::HKDF_SHA512,       AEAD::ID::AES_256_GCM,
  Digest::ID::SHA512,         Signature::ID::P521_SHA512, SignatureScheme::P521_SHA512,
};

template<>
const CipherAlgorithms
  cipher_algs<CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448>{
    KEM::ID::DHKEM_X448_SHA512,  KDF::ID::HKDF_SHA512,
    AEAD::ID::CHACHA20_POLY1305, Digest::ID::SHA512,
    Signature::ID::Ed448,  SignatureScheme::Ed448,
  };

static const CipherAlgorithms&
algs_for_suite(CipherSuite::ID id)
{
  switch (id) {
    case CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519:
      return cipher_algs<CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519>;

    case CipherSuite::ID::P256_AES128GCM_SHA256_P256:
      return cipher_algs<CipherSuite::ID::P256_AES128GCM_SHA256_P256>;

    case CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519:
      return cipher_algs<
        CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519>;

    case CipherSuite::ID::X448_AES256GCM_SHA512_Ed448:
      return cipher_algs<CipherSuite::ID::X448_AES256GCM_SHA512_Ed448>;

    case CipherSuite::ID::P521_AES256GCM_SHA512_P521:
      return cipher_algs<CipherSuite::ID::P521_AES256GCM_SHA512_P521>;

    case CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448:
      return cipher_algs<CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448>;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

static std::unique_ptr<HPKE>
hpke_for_suite(CipherSuite::ID id)
{
  const auto& algs = algs_for_suite(id);
  return std::make_unique<HPKE>(algs.kem_id, algs.kdf_id, algs.aead_id);
}

static std::unique_ptr<Digest>
digest_for_suite(CipherSuite::ID id)
{
  return Digest::create(algs_for_suite(id).digest_id);
}

static std::unique_ptr<Signature>
sig_for_suite(CipherSuite::ID id)
{
  return Signature::create(algs_for_suite(id).sig_id);
}

SignatureScheme
scheme_for_suite(CipherSuite::ID id)
{
  return algs_for_suite(id).scheme;
}

CipherSuite::CipherSuite()
  : id(CipherSuite::ID::unknown)
{}

CipherSuite::CipherSuite(ID id_in)
  : id(id_in)
{
  reset(id);
}

CipherSuite::CipherSuite(const CipherSuite& other)
  : id(other.id)
{
  reset(id);
}

CipherSuite::CipherSuite(CipherSuite&& other)
  : id(other.id)
  , hpke(std::move(other.hpke))
  , digest(std::move(other.digest))
  , sig(std::move(other.sig))
{}

CipherSuite&
CipherSuite::operator=(const CipherSuite& other)
{
  if (this != &other) {
    reset(other.id);
  }
  return *this;
}

struct HKDFLabel
{
  uint16_t length;
  bytes label;
  bytes context;

  TLS_SERIALIZABLE(length, label, context)
  TLS_TRAITS(tls::pass, tls::vector<1>, tls::vector<4>)
};

bytes
CipherSuite::expand_with_label(const bytes& secret,
                               const std::string& label,
                               const bytes& context,
                               size_t length) const
{
  auto mls_label = to_bytes(std::string("mls10 ") + label);
  auto length16 = static_cast<uint16_t>(length);
  auto label_bytes = tls::marshal(HKDFLabel{ length16, mls_label, context });
  return hpke->kdf->expand(secret, label_bytes, length);
}

void
CipherSuite::reset(ID id_in)
{
  if (id_in == ID::unknown) {
    return;
  }

  id = id_in;
  hpke = hpke_for_suite(id);
  digest = digest_for_suite(id);
  sig = sig_for_suite(id);
}

tls::istream&
operator>>(tls::istream& str, CipherSuite& suite)
{
  CipherSuite::ID id;
  str >> id;
  suite = CipherSuite(id);
  return str;
}

tls::ostream&
operator<<(tls::ostream& str, const CipherSuite& suite)
{
  return str << suite.id;
}

bool
operator==(const CipherSuite& lhs, const CipherSuite& rhs)
{
  return lhs.id == rhs.id;
}

bool
operator!=(const CipherSuite& lhs, const CipherSuite& rhs)
{
  return lhs.id != rhs.id;
}

const std::array<CipherSuite::ID, 6> all_supported_suites = {
  CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519,
  CipherSuite::ID::P256_AES128GCM_SHA256_P256,
  CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519,
  CipherSuite::ID::X448_AES256GCM_SHA512_Ed448,
  CipherSuite::ID::P521_AES256GCM_SHA512_P521,
  CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448,
};

} // namespace mls
