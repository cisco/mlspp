#include "common.h"
#include <stdexcept>

const Signature&
select_signature(Signature::ID id)
{
  switch (id) {
    case Signature::ID::P256_SHA256:
      return Signature::get<Signature::ID::P256_SHA256>();

    case Signature::ID::P384_SHA384:
      return Signature::get<Signature::ID::P384_SHA384>();

    case Signature::ID::P521_SHA512:
      return Signature::get<Signature::ID::P521_SHA512>();

    case Signature::ID::Ed25519:
      return Signature::get<Signature::ID::Ed25519>();

    case Signature::ID::Ed448:
      return Signature::get<Signature::ID::Ed448>();

    default:
      throw std::runtime_error("Unknown algorithm");
  }
}

const KEM&
select_kem(KEM::ID id)
{
  switch (id) {
    case KEM::ID::DHKEM_P256_SHA256:
      return KEM::get<KEM::ID::DHKEM_P256_SHA256>();

    case KEM::ID::DHKEM_P384_SHA384:
      return KEM::get<KEM::ID::DHKEM_P384_SHA384>();

    case KEM::ID::DHKEM_P521_SHA512:
      return KEM::get<KEM::ID::DHKEM_P521_SHA512>();

    case KEM::ID::DHKEM_X25519_SHA256:
      return KEM::get<KEM::ID::DHKEM_X25519_SHA256>();

    case KEM::ID::DHKEM_X448_SHA512:
      return KEM::get<KEM::ID::DHKEM_X448_SHA512>();

    default:
      throw std::runtime_error("Unknown algorithm");
  }
}

const KDF&
select_kdf(KDF::ID id)
{
  switch (id) {
    case KDF::ID::HKDF_SHA256:
      return KDF::get<KDF::ID::HKDF_SHA256>();

    case KDF::ID::HKDF_SHA384:
      return KDF::get<KDF::ID::HKDF_SHA384>();

    case KDF::ID::HKDF_SHA512:
      return KDF::get<KDF::ID::HKDF_SHA512>();

    default:
      throw std::runtime_error("Unknown algorithm");
  }
}

const AEAD&
select_aead(AEAD::ID id)
{
  switch (id) {
    case AEAD::ID::AES_128_GCM:
      return AEAD::get<AEAD::ID::AES_128_GCM>();

    case AEAD::ID::AES_256_GCM:
      return AEAD::get<AEAD::ID::AES_256_GCM>();

    case AEAD::ID::CHACHA20_POLY1305:
      return AEAD::get<AEAD::ID::CHACHA20_POLY1305>();

    default:
      throw std::runtime_error("Unknown algorithm");
  }
}
