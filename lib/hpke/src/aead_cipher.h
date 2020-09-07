#pragma once

#include <hpke/hpke.h>

namespace hpke {

struct AEADCipher : public AEAD
{
  template<AEAD::ID id>
  static const AEADCipher& get();

  ~AEADCipher() override = default;

  bytes seal(const bytes& key,
             const bytes& nonce,
             const bytes& aad,
             const bytes& pt) const override;
  std::optional<bytes> open(const bytes& key,
                            const bytes& nonce,
                            const bytes& aad,
                            const bytes& ct) const override;

  size_t key_size() const override;
  size_t nonce_size() const override;

private:
  const AEAD::ID cipher;
  const size_t nk;
  const size_t nn;
  const size_t tag_size;

  AEADCipher(AEAD::ID cipher_in);
  friend AEADCipher make_aead(AEAD::ID cipher_in);
};

} // namespace hpke
