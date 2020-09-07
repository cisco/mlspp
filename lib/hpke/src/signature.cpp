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

  ConcreteSignature(Group::ID group_id_in)
    : group(Group::create(group_id_in))
  {}

  std::unique_ptr<Signature::PrivateKey> generate_key_pair() const override
  {
    return std::make_unique<PrivateKey>(group.generate_key_pair().release());
  }

  std::unique_ptr<Signature::PrivateKey> derive_key_pair(
    const bytes& ikm) const override
  {
    return std::make_unique<PrivateKey>(group.derive_key_pair({}, ikm).release());
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

private:
  const Group& group;
};

static const ConcreteSignature sig_p256(Group::ID::P256);
static const ConcreteSignature sig_p384(Group::ID::P384);
static const ConcreteSignature sig_p521(Group::ID::P521);
static const ConcreteSignature sig_ed25519(Group::ID::Ed25519);
static const ConcreteSignature sig_ed448(Group::ID::Ed448);

const Signature&
Signature::create(ID id)
{
  switch (id) {
    case Signature::ID::P256_SHA256: return sig_p256;

    case Signature::ID::P384_SHA384: return sig_p384;

    case Signature::ID::P521_SHA512: return sig_p521;

    case Signature::ID::Ed25519: return sig_ed25519;

    case Signature::ID::Ed448: return sig_ed448;

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
