#include "hkdf.h"
#include "openssl_common.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>

namespace hpke {

HKDF make_hkdf(const Digest& digest) {
  return HKDF(digest);
}

static const HKDF hkdf_sha256 = make_hkdf(Digest::get<Digest::ID::SHA256>());
static const HKDF hkdf_sha384 = make_hkdf(Digest::get<Digest::ID::SHA384>());
static const HKDF hkdf_sha512 = make_hkdf(Digest::get<Digest::ID::SHA512>());

template<>
const HKDF& HKDF::get<Digest::ID::SHA256>()
{
  return hkdf_sha256;
}

template<>
const HKDF& HKDF::get<Digest::ID::SHA384>()
{
  return hkdf_sha384;
}

template<>
const HKDF& HKDF::get<Digest::ID::SHA512>()
{
  return hkdf_sha512;
}

HKDF::HKDF(const Digest& digest_in)
  : digest(digest_in)
{}

bytes
HKDF::extract(const bytes& salt, const bytes& ikm) const
{
  return digest.hmac(salt, ikm);
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

    Ti = digest.hmac(prk, block);
    okm += Ti;
  }

  okm.resize(size);
  return okm;
}

size_t
HKDF::hash_size() const
{
  return digest.hash_size();
}

} // namespace hpke
