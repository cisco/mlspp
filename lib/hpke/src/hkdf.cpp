#include "hkdf.h"
#include "openssl_common.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>

namespace hpke {

HKDF::HKDF(Digest::ID digest_id_in)
  : digest_id(digest_id_in)
  , digest(Digest::create(digest_id_in))
{}

std::unique_ptr<KDF>
HKDF::clone() const
{
  return std::make_unique<HKDF>(digest_id);
}

bytes
HKDF::extract(const bytes& salt, const bytes& ikm) const
{
  return digest->hmac(salt, ikm);
}

bytes
HKDF::expand(const bytes& prk, const bytes& info, size_t size) const
{
  auto okm = bytes{};
  auto i = uint8_t(0x00);
  auto Ti = bytes{};
  while (okm.size() < size) {
    i += 1;
    auto block = Ti + info + bytes{ i };

    Ti = digest->hmac(prk, block);
    okm += Ti;
  }

  okm.resize(size);
  return okm;
}

size_t
HKDF::hash_size() const
{
  return digest->hash_size();
}

} // namespace hpke
