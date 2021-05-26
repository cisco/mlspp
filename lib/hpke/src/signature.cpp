#include <hpke/digest.h>
#include <hpke/signature.h>

#include "dhkem.h"

#include "common.h"
#include "group.h"
#include "rsa.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace hpke {

struct GroupSignature : public Signature
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

  static Signature::ID group_to_sig(Group::ID group_id)
  {
    switch (group_id) {
      case Group::ID::P256:
        return Signature::ID::P256_SHA256;
      case Group::ID::P384:
        return Signature::ID::P384_SHA384;
      case Group::ID::P521:
        return Signature::ID::P521_SHA512;
      case Group::ID::Ed25519:
        return Signature::ID::Ed25519;
      case Group::ID::Ed448:
        return Signature::ID::Ed448;
      default:
        throw std::runtime_error("Unsupported group");
    }
  }

  explicit GroupSignature(const Group& group_in)
    : Signature(group_to_sig(group_in.id))
    , group(group_in)
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

private:
  const Group& group;
};

template<>
const Signature&
Signature::get<Signature::ID::P256_SHA256>()
{
  static const auto instance = GroupSignature(Group::get<Group::ID::P256>());
  return instance;
}

template<>
const Signature&
Signature::get<Signature::ID::P384_SHA384>()
{
  static const auto instance = GroupSignature(Group::get<Group::ID::P384>());
  return instance;
}

template<>
const Signature&
Signature::get<Signature::ID::P521_SHA512>()
{
  static const auto instance = GroupSignature(Group::get<Group::ID::P521>());
  return instance;
}

template<>
const Signature&
Signature::get<Signature::ID::Ed25519>()
{
  static const auto instance = GroupSignature(Group::get<Group::ID::Ed25519>());
  return instance;
}

template<>
const Signature&
Signature::get<Signature::ID::Ed448>()
{
  static const auto instance = GroupSignature(Group::get<Group::ID::Ed448>());
  return instance;
}

template<>
const Signature&
Signature::get<Signature::ID::RSA_SHA256>()
{
  static const auto instance = RSASignature(Digest::ID::SHA256);
  return instance;
}

template<>
const Signature&
Signature::get<Signature::ID::RSA_SHA384>()
{
  static const auto instance = RSASignature(Digest::ID::SHA384);
  return instance;
}

template<>
const Signature&
Signature::get<Signature::ID::RSA_SHA512>()
{
  static const auto instance = RSASignature(Digest::ID::SHA512);
  return instance;
}

Signature::Signature(Signature::ID id_in)
  : id(id_in)
{}

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

std::unique_ptr<Signature::PrivateKey>
Signature::generate_rsa(size_t bits)
{
  return RSASignature::generate_key_pair(bits);
}

} // namespace hpke
