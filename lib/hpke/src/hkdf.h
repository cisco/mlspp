#pragma once

#include <hpke/digest.h>
#include <hpke/hpke.h>

namespace hpke {

struct HKDF : public KDF
{
  template<Digest::ID digest_id>
  static const HKDF& get();

  ~HKDF() override = default;

  bytes extract(const bytes& salt, const bytes& ikm) const override;
  bytes expand(const bytes& prk, const bytes& info, size_t size) const override;
  size_t hash_size() const override;

private:
  const Digest& digest;

  explicit HKDF(const Digest& digest_in);
  friend HKDF make_hkdf(const Digest& digest);

  template<Digest::ID digest_id>
  static const HKDF instance;
};

} // namespace hpke
