#include "dhkem.h"

#include "common.h"
#include "group.h"

namespace hpke {

struct ConcreteSignature : public Signature
{
  struct PrivateKey : public Signature::PrivateKey
  {
    explicit PrivateKey(Group::PrivateKey* group_priv_in)
      : group_priv(group_priv_in)
    {}

    std::unique_ptr<Signature::PublicKey> public_key() const override
    {
      return group_priv->public_key();
    }

    std::unique_ptr<Group::PrivateKey> group_priv;
  };

  explicit ConcreteSignature(const Group& group_in)
    : group(group_in)
  {}

  std::unique_ptr<Signature::PrivateKey> generate_key_pair() const override
  {
    return std::make_unique<PrivateKey>(group.generate_key_pair().release());
  }

  std::unique_ptr<Signature::PrivateKey> derive_key_pair(
    const bytes& ikm) const override
  {
    return std::make_unique<PrivateKey>(
      group.derive_key_pair({}, ikm).release());
  }

  bytes serialize(const Signature::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const Group::PublicKey&>(pk);
    return group.serialize(rpk);
  }

  std::unique_ptr<Signature::PublicKey> deserialize(
    const bytes& enc) const override
  {
    return group.deserialize(enc);
  }

  bytes serialize_private(const Signature::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    return group.serialize_private(*rsk.group_priv);
  }

  std::unique_ptr<Signature::PrivateKey> deserialize_private(
    const bytes& skm) const override
  {
    return std::make_unique<PrivateKey>(
      group.deserialize_private(skm).release());
  }

  bytes sign(const bytes& data, const Signature::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    return group.sign(data, *rsk.group_priv);
  }

  bool verify(const bytes& data,
              const bytes& sig,
              const Signature::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const Group::PublicKey&>(pk);
    return group.verify(data, sig, rpk);
  }

  template<Signature::ID id>
  static const ConcreteSignature instance;

private:
  const Group& group;
};

template<>
const ConcreteSignature
  ConcreteSignature::instance<Signature::ID::P256_SHA256> =
    ConcreteSignature(Group::get<Group::ID::P256>());

template<>
const ConcreteSignature
  ConcreteSignature::instance<Signature::ID::P384_SHA384> =
    ConcreteSignature(Group::get<Group::ID::P384>());

template<>
const ConcreteSignature
  ConcreteSignature::instance<Signature::ID::P521_SHA512> =
    ConcreteSignature(Group::get<Group::ID::P521>());

template<>
const ConcreteSignature ConcreteSignature::instance<Signature::ID::Ed25519> =
  ConcreteSignature(Group::get<Group::ID::Ed25519>());

template<>
const ConcreteSignature ConcreteSignature::instance<Signature::ID::Ed448> =
  ConcreteSignature(Group::get<Group::ID::Ed448>());

template<>
const Signature&
Signature::get<Signature::ID::P256_SHA256>()
{
  return ConcreteSignature::instance<Signature::ID::P256_SHA256>;
}

template<>
const Signature&
Signature::get<Signature::ID::P384_SHA384>()
{
  return ConcreteSignature::instance<Signature::ID::P384_SHA384>;
}

template<>
const Signature&
Signature::get<Signature::ID::P521_SHA512>()
{
  return ConcreteSignature::instance<Signature::ID::P521_SHA512>;
}

template<>
const Signature&
Signature::get<Signature::ID::Ed25519>()
{
  return ConcreteSignature::instance<Signature::ID::Ed25519>;
}

template<>
const Signature&
Signature::get<Signature::ID::Ed448>()
{
  return ConcreteSignature::instance<Signature::ID::Ed448>;
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
