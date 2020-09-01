#pragma once

#include <hpke/hpke.h>

namespace hpke {

struct HKDF : public KDF
{
  enum struct Digest : uint8_t
  {
    sha256,
    sha384,
    sha512,
  };

  HKDF(Digest digest_in);

  std::unique_ptr<KDF> clone() const override;
  ~HKDF() override = default;

  bytes extract(const bytes& salt, const bytes& ikm) const override;
  bytes expand(const bytes& prk, const bytes& info, size_t size) const override;
  size_t hash_size() const override;

private:
  const Digest digest;

  bytes hmac(const bytes& key, const bytes& data) const;
};

} // namespace hpke
