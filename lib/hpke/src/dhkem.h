#pragma once

#include <hpke/hpke.h>

#include "group.h"

namespace hpke {

struct DHKEM : public KEM
{
  struct PrivateKey : public KEM::PrivateKey
  {
    PrivateKey(Group::PrivateKey* group_priv_in);
    std::unique_ptr<KEM::PublicKey> public_key() const override;

    std::unique_ptr<Group::PrivateKey> group_priv;
  };

  DHKEM(KEM::ID kem_id_in, Group::ID group_id_in, KDF::ID kdf_id_in);
  std::unique_ptr<KEM> clone() const override;
  ~DHKEM() override = default;

  std::unique_ptr<KEM::PrivateKey> generate_key_pair() const override;
  std::unique_ptr<KEM::PrivateKey> derive_key_pair(
    const bytes& ikm) const override;

  bytes serialize(const KEM::PublicKey& pk) const override;
  std::unique_ptr<KEM::PublicKey> deserialize(const bytes& enc) const override;

  bytes serialize_private(const KEM::PrivateKey& sk) const override;
  std::unique_ptr<KEM::PrivateKey> deserialize_private(
    const bytes& skm) const override;

  std::pair<bytes, bytes> encap(const KEM::PublicKey& pk) const override;
  bytes decap(const bytes& enc, const KEM::PrivateKey& sk) const override;

  std::pair<bytes, bytes> auth_encap(const KEM::PublicKey& pkR,
                                     const KEM::PrivateKey& skS) const override;
  bytes auth_decap(const bytes& enc,
                   const KEM::PublicKey& pkS,
                   const KEM::PrivateKey& skR) const override;

  size_t secret_size() const override;
  size_t enc_size() const override;
  size_t pk_size() const override;
  size_t sk_size() const override;

private:
  KEM::ID kem_id;
  Group::ID group_id;
  KDF::ID kdf_id;
  std::unique_ptr<Group> group;
  std::unique_ptr<KDF> kdf;
  bytes suite_id;

  bytes extract_and_expand(const bytes& dh, const bytes& kem_context) const;
};

} // namespace hpke
