#pragma once

#include <hpke/digest.h>
#include <hpke/hpke.h>

namespace hpke {

struct HKDF : public KDF
{
  HKDF(Digest::ID digest_id_in);

  std::unique_ptr<KDF> clone() const override;
  ~HKDF() override = default;

  bytes extract(const bytes& salt, const bytes& ikm) const override;
  bytes expand(const bytes& prk, const bytes& info, size_t size) const override;
  size_t hash_size() const override;

private:
  Digest::ID digest_id;
  std::unique_ptr<Digest> digest;

  bytes hmac(const bytes& key, const bytes& data) const;
};

} // namespace hpke
