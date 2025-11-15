#include "hybrid_kem.h"

#include "common.h"
#include <hpke/digest.h>
#include <hpke/random.h>
#include <namespace.h>

namespace MLS_NAMESPACE::hpke {

static std::tuple<bytes, bytes>
split(const bytes& data, size_t m, size_t n)
{
  if (data.size() != m + n) {
    throw std::runtime_error("Invalid split");
  }

  const auto cut = data.begin() + m;
  const auto first = bytes(std::vector<uint8_t>(data.begin(), cut));
  const auto last = bytes(std::vector<uint8_t>(cut, data.end()));
  return { first, last };
}

static const char*
get_label(KEM::ID kem_id)
{
  switch (kem_id) {
    case KEM::ID::MLKEM768_P256:
      return "MLKEM768-P256";
    case KEM::ID::MLKEM1024_P384:
      return "MLKEM1024-P384";
    case KEM::ID::MLKEM768_X25519:
      return "\\.//^\\";
    default:
      throw std::runtime_error("unreachable");
  }
}

HybridKEM::PublicKey::PublicKey(KEM::PublicKey* mlkem_pub_in,
                                Group::PublicKey* group_pub_in)
  : mlkem_pub(mlkem_pub_in)
  , group_pub(group_pub_in)
{
}

HybridKEM::PrivateKey::PrivateKey(bytes seed_in,
                                  MLKEM::PrivateKey* mlkem_priv_in,
                                  Group::PrivateKey* group_priv_in)
  : seed(seed_in)
  , mlkem_priv(mlkem_priv_in)
  , group_priv(group_priv_in)
{
}

std::unique_ptr<KEM::PublicKey>
HybridKEM::PrivateKey::public_key() const
{
  return std::make_unique<HybridKEM::PublicKey>(
    mlkem_priv->public_key().release(), group_priv->public_key().release());
}

HybridKEM
make_hybrid_kem(KEM::ID kem_id_in, const MLKEM& mlkem_in, const Group& group_in)
{
  return { kem_id_in, mlkem_in, group_in };
}

template<>
const HybridKEM&
HybridKEM::get<KEM::ID::MLKEM768_P256>()
{
  static const auto instance = make_hybrid_kem(KEM::ID::MLKEM768_P256,
                                               MLKEM::get<KEM::ID::MLKEM768>(),
                                               Group::get<Group::ID::P256>());
  return instance;
}

template<>
const HybridKEM&
HybridKEM::get<KEM::ID::MLKEM1024_P384>()
{
  static const auto instance = make_hybrid_kem(KEM::ID::MLKEM1024_P384,
                                               MLKEM::get<KEM::ID::MLKEM1024>(),
                                               Group::get<Group::ID::P384>());
  return instance;
}

template<>
const HybridKEM&
HybridKEM::get<KEM::ID::MLKEM768_X25519>()
{
  static const auto instance = make_hybrid_kem(KEM::ID::MLKEM768_X25519,
                                               MLKEM::get<KEM::ID::MLKEM768>(),
                                               Group::get<Group::ID::X25519>());
  return instance;
}

HybridKEM::HybridKEM(KEM::ID kem_id_in,
                     const MLKEM& mlkem_in,
                     const Group& group_in)
  : KEM(kem_id_in,
        HybridKEM::seed_size,
        HybridKEM::secret_size,
        mlkem_in.enc_size + group_in.pk_size,
        mlkem_in.pk_size + group_in.pk_size,
        HybridKEM::sk_size)
  , mlkem(mlkem_in)
  , group(group_in)
{
  static const auto label_kem = from_ascii("KEM");
  suite_id = label_kem + i2osp(uint16_t(kem_id_in), 2);
}

std::unique_ptr<KEM::PrivateKey>
HybridKEM::generate_key_pair() const
{
  const auto seed = random_bytes(sk_size);
  return std::make_unique<HybridKEM::PrivateKey>(expand_seed(seed));
}

std::unique_ptr<KEM::PrivateKey>
HybridKEM::derive_key_pair(const bytes& ikm) const
{
  const auto seed =
    SHAKE256::labeled_derive(id, ikm, "DeriveKeyPair", {}, HybridKEM::sk_size);
  return std::make_unique<HybridKEM::PrivateKey>(expand_seed(seed));
}

bytes
HybridKEM::serialize(const KEM::PublicKey& pk) const
{
  const auto& rpk = dynamic_cast<const HybridKEM::PublicKey&>(pk);

  const auto mpk = mlkem.serialize(*rpk.mlkem_pub);
  const auto gpk = group.serialize(*rpk.group_pub);

  return mpk + gpk;
}

std::unique_ptr<KEM::PublicKey>
HybridKEM::deserialize(const bytes& enc) const
{
  const auto [ek_pq, ek_t] = split(enc, mlkem.pk_size, group.pk_size);

  auto pk_pq = mlkem.deserialize(ek_pq);
  auto pk_t = group.deserialize(ek_t);

  return std::make_unique<HybridKEM::PublicKey>(pk_pq.release(),
                                                pk_t.release());
}

bytes
HybridKEM::serialize_private(const KEM::PrivateKey& sk) const
{
  const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
  return rsk.seed;
}

std::unique_ptr<KEM::PrivateKey>
HybridKEM::deserialize_private(const bytes& skm) const
{
  return std::make_unique<HybridKEM::PrivateKey>(expand_seed(skm));
}

std::pair<bytes, bytes>
HybridKEM::encap(const KEM::PublicKey& pkR) const
{
  const auto& rpkR = dynamic_cast<const PublicKey&>(pkR);

  const auto [ss_pq, ct_pq] = mlkem.encap(*rpkR.mlkem_pub);

  const auto skE = group.generate_key_pair();
  const auto pkE = skE->public_key();
  const auto ss_t = group.dh(*skE, *rpkR.group_pub);
  const auto ct_t = group.serialize(*pkE);
  const auto ek_t = group.serialize(*rpkR.group_pub);

  const auto ct_h = ct_pq + ct_t;
  const auto ss_h = c2pri_combiner(ss_pq, ss_t, ct_t, ek_t, get_label(id));
  return { ss_h, ct_h };
}

bytes
HybridKEM::decap(const bytes& enc, const KEM::PrivateKey& skR) const
{
  const auto& rskR = dynamic_cast<const PrivateKey&>(skR);
  const auto [ct_pq, ct_t] = split(enc, mlkem.enc_size, group.pk_size);

  const auto ss_pq = mlkem.decap(ct_pq, *rskR.mlkem_priv);

  const auto pkE = group.deserialize(ct_t);
  const auto ss_t = group.dh(*rskR.group_priv, *pkE);
  const auto ek_t = group.serialize(*rskR.group_priv->public_key());

  return c2pri_combiner(ss_pq, ss_t, ct_t, ek_t, get_label(id));
}

HybridKEM::PrivateKey
HybridKEM::expand_seed(const bytes& seed) const
{
  const auto seed_full =
    SHAKE256::derive(seed, mlkem.seed_size + group.seed_size);
  const auto [seed_pq, seed_t] =
    split(seed_full, mlkem.seed_size, group.seed_size);

  auto dk_pq_abstract = mlkem.deserialize_private(seed_pq);
  auto dk_pq = dynamic_cast<MLKEM::PrivateKey*>(dk_pq_abstract.release());

  auto dk_t = group.random_scalar(seed_t);

  return { seed, dk_pq, dk_t.release() };
}

bytes
HybridKEM::c2pri_combiner(const bytes& ss_pq,
                          const bytes& ss_t,
                          const bytes& ct_t,
                          const bytes& ek_t,
                          const char* label) const
{
  static const auto kdf = Digest::get<Digest::ID::SHA3_256>();
  const auto label_bytes = std::vector<uint8_t>(label, label + strlen(label));
  return kdf.hash(ss_pq + ss_t + ct_t + ek_t + label_bytes);
}

} // namespace MLS_NAMESPACE::hpke
