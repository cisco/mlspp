#include <hpke/digest.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "openssl_common.h"

namespace hpke {

static const EVP_MD*
openssl_digest_type(Digest::ID digest)
{
  switch (digest) {
    case Digest::ID::SHA256:
      return EVP_sha256();

    case Digest::ID::SHA384:
      return EVP_sha384();

    case Digest::ID::SHA512:
      return EVP_sha512();

    default:
      throw std::runtime_error("Unsupported ciphersuite");
  }
}

template<>
const Digest&
Digest::get<Digest::ID::SHA256>()
{
  static const Digest instance(Digest::ID::SHA256);
  return instance;
}

template<>
const Digest&
Digest::get<Digest::ID::SHA384>()
{
  static const Digest instance(Digest::ID::SHA384);
  return instance;
}

template<>
const Digest&
Digest::get<Digest::ID::SHA512>()
{
  static const Digest instance(Digest::ID::SHA512);
  return instance;
}

Digest::Digest(Digest::ID id_in)
  : id(id_in)
  , hash_size(EVP_MD_size(openssl_digest_type(id_in)))
{}

bytes
Digest::hash(const bytes& data) const
{
  auto md = bytes(hash_size);
  unsigned int size = 0;
  const auto* type = openssl_digest_type(id);
  if (1 !=
      EVP_Digest(data.data(), data.size(), md.data(), &size, type, nullptr)) {
    throw openssl_error();
  }

  return md;
}

bytes
Digest::hmac(const bytes& key, const bytes& data) const
{
  auto md = bytes(hash_size);
  unsigned int size = 0;
  const auto* type = openssl_digest_type(id);
  if (nullptr == HMAC(type,
                      key.data(),
                      key.size(),
                      data.data(),
                      data.size(),
                      md.data(),
                      &size)) {
    throw openssl_error();
  }

  return md;
}

} // namespace hpke
