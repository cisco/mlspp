#pragma once

#include <hpke/hpke.h>

namespace hpke {

struct AEADCipher : public AEAD
{
  AEADCipher(AEAD::ID cipher_in);
  std::unique_ptr<AEAD> clone() const override;
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
};

} // namespace hpke
