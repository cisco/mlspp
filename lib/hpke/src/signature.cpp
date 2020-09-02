#include "dhkem.h"

#include "common.h"
#include "group.h"

namespace hpke {

struct ConcreteSignature : public Signature
{
  struct PrivateKey : public Signature::PrivateKey
  {
    PrivateKey(Group::PrivateKey* group_priv_in)
      : group_priv(group_priv_in)
    {}

    std::unique_ptr<Signature::PublicKey> public_key() const override
    {
      return group_priv->public_key();
    }

    std::unique_ptr<Group::PrivateKey> group_priv;
  };

  ConcreteSignature(Group::ID group_id_in, KDF::ID kdf_id_in)
    : group_id(group_id_in)
    , kdf_id(kdf_id_in)
    , group(Group::create(group_id_in, kdf_id_in))
  {}

  std::unique_ptr<Signature> clone() const override
  {
    return std::make_unique<ConcreteSignature>(group_id, kdf_id);
  }

  std::unique_ptr<Signature::PrivateKey> generate_key_pair() const override
  {
    return std::make_unique<PrivateKey>(group->generate_key_pair().release());
  }

  std::unique_ptr<Signature::PrivateKey> derive_key_pair(
    const bytes& ikm) const override
  {
    return std::make_unique<PrivateKey>(group->derive_key_pair(ikm).release());
  }

  bytes serialize(const Signature::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const Group::PublicKey&>(pk);
    return group->serialize(rpk);
  }

  std::unique_ptr<Signature::PublicKey> deserialize(
    const bytes& enc) const override
  {
    return group->deserialize(enc);
  }

  bytes serialize_private(const Signature::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    return group->serialize_private(*rsk.group_priv);
  }

  std::unique_ptr<Signature::PrivateKey> deserialize_private(
    const bytes& skm) const override
  {
    return std::make_unique<PrivateKey>(
      group->deserialize_private(skm).release());
  }

  bytes sign(const bytes& data, const Signature::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    return group->sign(data, *rsk.group_priv);
  }

  bool verify(const bytes& data,
              const bytes& sig,
              const Signature::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const Group::PublicKey&>(pk);
    return group->verify(data, sig, rpk);
  }

private:
  Group::ID group_id;
  KDF::ID kdf_id;
  std::unique_ptr<Group> group;
};

std::unique_ptr<Signature>
Signature::create(ID id)
{
  switch (id) {
    case Signature::ID::P256_SHA256:
      return std::make_unique<ConcreteSignature>(Group::ID::P256,
                                                 KDF::ID::HKDF_SHA256);

    case Signature::ID::P384_SHA384:
      return std::make_unique<ConcreteSignature>(Group::ID::P384,
                                                 KDF::ID::HKDF_SHA384);

    case Signature::ID::P521_SHA512:
      return std::make_unique<ConcreteSignature>(Group::ID::P521,
                                                 KDF::ID::HKDF_SHA512);

    case Signature::ID::Ed25519:
      return std::make_unique<ConcreteSignature>(Group::ID::Ed25519,
                                                 KDF::ID::HKDF_SHA256);

    case Signature::ID::Ed448:
      return std::make_unique<ConcreteSignature>(Group::ID::Ed448,
                                                 KDF::ID::HKDF_SHA512);

    default:
      throw std::runtime_error("Unsupported algorithm");
  }
}

bytes
Signature::serialize_private(const PrivateKey& /* unused */) const
{
  throw std::runtime_error("Not implemented");
}

std::unique_ptr<Signature::PrivateKey>
Signature::deserialize_private(const bytes& /* unused */) const
{
  throw std::runtime_error("Not implemented");
}

} // namespace hpke
