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
                      static_cast<int>(key.size()),
                      data.data(),
                      static_cast<int>(data.size()),
                      md.data(),
                      &size)) {
    throw openssl_error();
  }

  return md;
}

bytes
Digest::hmac_for_hkdf_extract(const bytes& key, const bytes& data) const
{
  const auto* type = openssl_digest_type(id);
  auto ctx = make_typed_unique(HMAC_CTX_new());

  // Some FIPS-enabled libraries are overly conservative in their interpretation
  // of NIST SP 800-131A, which requires HMAC keys to be at least 112 bits long.
  // That document does not impose that requirement on HKDF, so we disable FIPS
  // enforcement for purposes of HKDF.
  //
  // https://doi.org/10.6028/NIST.SP.800-131Ar2
  static const auto fips_min_hmac_key_len = 14;
  auto key_size = static_cast<int>(key.size());
  if (key_size < fips_min_hmac_key_len) {
    HMAC_CTX_set_flags(ctx.get(), EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
  }

  // Guard against sending nullptr to HMAC_Init_ex
  const auto* key_data = key.data();
  const auto non_null_zero_length_key = uint8_t(0);
  if (key_data == nullptr) {
    key_data = &non_null_zero_length_key;
  }

  if (1 != HMAC_Init_ex(ctx.get(), key_data, key_size, type, nullptr)) {
    throw openssl_error();
  }

  if (1 != HMAC_Update(ctx.get(), data.data(), data.size())) {
    throw openssl_error();
  }

  auto md = bytes(hash_size);
  unsigned int size = 0;
  if (1 != HMAC_Final(ctx.get(), md.data(), &size)) {
    throw openssl_error();
  }

  return md;
}

} // namespace hpke
