#include "dhkem.h"

#include "common.h"

namespace hpke {

///
/// DHKEM::PrivateKey
///
DHKEM::PrivateKey::PrivateKey(Group::PrivateKey* group_priv_in)
  : group_priv(group_priv_in)
{}

std::unique_ptr<KEM::PublicKey>
DHKEM::PrivateKey::public_key() const
{
  return group_priv->public_key();
}

///
/// DHKEM::PrivateKey
///

DHKEM::DHKEM(KEM::ID kem_id_in, Group::ID group_id_in, KDF::ID kdf_id_in)
  : kem_id(kem_id_in)
  , group_id(group_id_in)
  , kdf_id(kdf_id_in)
  , group(Group::create(group_id_in, kdf_id_in))
  , kdf(KDF::create(kdf_id_in))
{
  static const auto label_kem = to_bytes("KEM");
  suite_id = label_kem + i2osp(uint16_t(kem_id_in), 2);
  group->suite_id = suite_id;
}

std::unique_ptr<KEM>
DHKEM::clone() const
{
  return std::make_unique<DHKEM>(kem_id, group_id, kdf_id);
}

std::unique_ptr<KEM::PrivateKey>
DHKEM::generate_key_pair() const
{
  return std::make_unique<DHKEM::PrivateKey>(
    group->generate_key_pair().release());
}

std::unique_ptr<KEM::PrivateKey>
DHKEM::derive_key_pair(const bytes& ikm) const
{
  return std::make_unique<DHKEM::PrivateKey>(
    group->derive_key_pair(ikm).release());
}

bytes
DHKEM::serialize(const KEM::PublicKey& pk) const
{
  const auto& gpk = dynamic_cast<const Group::PublicKey&>(pk);
  return group->serialize(gpk);
}

std::unique_ptr<KEM::PublicKey>
DHKEM::deserialize(const bytes& enc) const
{
  return group->deserialize(enc);
}

bytes
DHKEM::serialize_private(const KEM::PrivateKey& sk) const
{
  const auto& gsk = dynamic_cast<const PrivateKey&>(sk);
  return group->serialize_private(*gsk.group_priv);
}

std::unique_ptr<KEM::PrivateKey>
DHKEM::deserialize_private(const bytes& skm) const
{
  return std::make_unique<PrivateKey>(
    group->deserialize_private(skm).release());
}

std::pair<bytes, bytes>
DHKEM::encap(const KEM::PublicKey& pkR) const
{
  const auto& gpkR = dynamic_cast<const Group::PublicKey&>(pkR);

  auto skE = group->generate_key_pair();
  auto pkE = skE->public_key();

  auto zz = group->dh(*skE, gpkR);
  auto enc = group->serialize(*pkE);

  auto pkRm = group->serialize(gpkR);
  auto kem_context = enc + pkRm;

  auto shared_secret = extract_and_expand(zz, kem_context);
  return std::make_pair(shared_secret, enc);
}

bytes
DHKEM::decap(const bytes& enc, const KEM::PrivateKey& skR) const
{
  const auto& gskR = dynamic_cast<const PrivateKey&>(skR);
  auto pkR = gskR.group_priv->public_key();
  auto pkE = group->deserialize(enc);
  auto zz = group->dh(*gskR.group_priv, *pkE);

  auto pkRm = group->serialize(*pkR);
  auto kem_context = enc + pkRm;
  return extract_and_expand(zz, kem_context);
}

std::pair<bytes, bytes>
DHKEM::auth_encap(const KEM::PublicKey& pkR, const KEM::PrivateKey& skS) const
{
  const auto& gpkR = dynamic_cast<const Group::PublicKey&>(pkR);
  const auto& gskS = dynamic_cast<const PrivateKey&>(skS);

  auto skE = group->generate_key_pair();
  auto pkE = skE->public_key();
  auto pkS = gskS.group_priv->public_key();

  auto zzER = group->dh(*skE, gpkR);
  auto zzSR = group->dh(*gskS.group_priv, gpkR);
  auto zz = zzER + zzSR;
  auto enc = group->serialize(*pkE);

  auto pkRm = group->serialize(gpkR);
  auto pkSm = group->serialize(*pkS);
  auto kem_context = enc + pkRm + pkSm;

  auto shared_secret = extract_and_expand(zz, kem_context);
  return std::make_pair(shared_secret, enc);
}

bytes
DHKEM::auth_decap(const bytes& enc,
                  const KEM::PublicKey& pkS,
                  const KEM::PrivateKey& skR) const
{
  const auto& gpkS = dynamic_cast<const Group::PublicKey&>(pkS);
  const auto& gskR = dynamic_cast<const PrivateKey&>(skR);

  auto pkE = group->deserialize(enc);
  auto pkR = gskR.group_priv->public_key();

  auto zzER = group->dh(*gskR.group_priv, *pkE);
  auto zzSR = group->dh(*gskR.group_priv, gpkS);
  auto zz = zzER + zzSR;

  auto pkRm = group->serialize(*pkR);
  auto pkSm = group->serialize(gpkS);
  auto kem_context = enc + pkRm + pkSm;

  return extract_and_expand(zz, kem_context);
}

size_t
DHKEM::secret_size() const
{
  return kdf->hash_size();
}

size_t
DHKEM::enc_size() const
{
  return group->pk_size();
}

size_t
DHKEM::pk_size() const
{
  return group->pk_size();
}

size_t
DHKEM::sk_size() const
{
  return group->sk_size();
}

bytes
DHKEM::extract_and_expand(const bytes& dh, const bytes& kem_context) const
{
  static const auto label_eae_prk = to_bytes("eae_prk");
  static const auto label_shared_secret = to_bytes("shared_secret");

  auto eae_prk = kdf->labeled_extract(suite_id, {}, label_eae_prk, dh);
  return kdf->labeled_expand(
    suite_id, eae_prk, label_shared_secret, kem_context, secret_size());
}

} // namespace hpke
