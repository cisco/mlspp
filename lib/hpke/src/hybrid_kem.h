#ifdef WITH_PQ
#pragma once

#include <hpke/hpke.h>
#include <namespace.h>

#include "group.h"
#include "mlkem.h"

#include <string>

namespace MLS_NAMESPACE::hpke {

struct HybridKEM : public KEM
{
  struct PublicKey : public KEM::PublicKey
  {
    PublicKey(KEM::PublicKey* mlkem_pub_in, Group::PublicKey* group_pub_in);

    std::unique_ptr<KEM::PublicKey> mlkem_pub;
    std::unique_ptr<Group::PublicKey> group_pub;
  };

  struct PrivateKey : public KEM::PrivateKey
  {
    PrivateKey(bytes seed_in,
               MLKEM::PrivateKey* mlkem_priv_in,
               Group::PrivateKey* group_priv_in);
    std::unique_ptr<KEM::PublicKey> public_key() const override;

    bytes seed;
    std::unique_ptr<MLKEM::PrivateKey> mlkem_priv;
    std::unique_ptr<Group::PrivateKey> group_priv;
  };

  template<KEM::ID>
  static const HybridKEM& get();

  ~HybridKEM() override = default;

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

private:
  const MLKEM& mlkem;
  const Group& group;
  bytes suite_id;

  static const auto seed_size = size_t(32);
  static const auto secret_size = size_t(32);
  static const auto sk_size = size_t(32);

  PrivateKey expand_seed(const bytes& seed) const;
  bytes c2pri_combiner(const bytes& ss_pq,
                       const bytes& ss_t,
                       const bytes& ct_t,
                       const bytes& ek_t,
                       const std::string& label) const;

  HybridKEM(KEM::ID kem_id_in, const MLKEM& mlkem_in, const Group& group_in);
  friend HybridKEM make_hybrid_kem(KEM::ID kem_id_in,
                                   const MLKEM& mlkem_in,
                                   const Group& group_in);
};

} // namespace MLS_NAMESPACE::hpke
#endif // def WITH_PQ
