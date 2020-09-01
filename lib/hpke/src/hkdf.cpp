#include "hkdf.h"
#include "openssl_common.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>

namespace hpke {

HKDF::HKDF(HKDF::Digest digest_in)
  : digest(digest_in)
{}

std::unique_ptr<KDF>
HKDF::clone() const
{
  return std::make_unique<HKDF>(digest);
}

static const EVP_MD*
openssl_digest_type(HKDF::Digest digest)
{
  switch (digest) {
    case HKDF::Digest::sha256:
      return EVP_sha256();

    case HKDF::Digest::sha384:
      return EVP_sha384();

    case HKDF::Digest::sha512:
      return EVP_sha512();

    default:
      throw std::runtime_error("Unsupported ciphersuite");
  }
}

bytes
HKDF::hmac(const bytes& key, const bytes& data) const
{
  unsigned int size = 0;
  const auto* type = openssl_digest_type(digest);
  bytes md(EVP_MAX_MD_SIZE);
  if (nullptr == HMAC(type,
                      key.data(),
                      key.size(),
                      data.data(),
                      data.size(),
                      md.data(),
                      &size)) {
    throw openssl_error();
  }

  md.resize(size);
  return md;
}

bytes
HKDF::extract(const bytes& salt, const bytes& ikm) const
{
  return hmac(salt, ikm);
}

bytes
HKDF::expand(const bytes& prk, const bytes& info, size_t size) const
{
  auto okm = bytes{};
  auto i = uint8_t(0x00);
  auto Ti = bytes{};
  while (okm.size() < size) {
    i += 1;
    auto label = Ti;
    label.insert(label.end(), info.begin(), info.end());
    label.push_back(i);

    Ti = hmac(prk, label);
    okm.insert(okm.end(), Ti.begin(), Ti.end());
  }

  okm.resize(size);
  return okm;
}

size_t
HKDF::hash_size() const
{
  return EVP_MD_size(openssl_digest_type(digest));
}

} // namespace hpke
