#include <hpke/base64.h>
#include <hpke/digest.h>
#include <hpke/signature.h>
#include <namespace.h>
#include <string>

#include "dhkem.h"
#include "rsa.h"

#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using nlohmann::json;

namespace MLS_NAMESPACE::hpke {

struct GroupSignature : public Signature
{
  struct PrivateKey : public Signature::PrivateKey
  {
    explicit PrivateKey(Group::PrivateKey* group_priv_in)
      : group_priv(group_priv_in)
    {
    }

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
  {
  }

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

  std::unique_ptr<Signature::PrivateKey> import_jwk_private(
    const std::string& json_str) const override
  {
    const auto jwk_json = validate_jwk_json(json_str, true);

    const auto d = from_base64url(jwk_json.at("d"));
    auto gsk = group.deserialize_private(d);

    return std::make_unique<PrivateKey>(gsk.release());
  }

  std::unique_ptr<Signature::PublicKey> import_jwk(
    const std::string& json_str) const override
  {
    const auto jwk_json = validate_jwk_json(json_str, false);

    const auto x = from_base64url(jwk_json.at("x"));
    auto y = bytes{};
    if (jwk_json.contains("y")) {
      y = from_base64url(jwk_json.at("y"));
    }

    return group.public_key_from_coordinates(x, y);
  }

  std::string export_jwk(const Signature::PublicKey& pk) const override
  {
    const auto& gpk = dynamic_cast<const Group::PublicKey&>(pk);
    const auto jwk_json = export_jwk_json(gpk);
    return jwk_json.dump();
  }

  std::string export_jwk_private(const Signature::PrivateKey& sk) const override
  {
    const auto& gssk = dynamic_cast<const GroupSignature::PrivateKey&>(sk);
    const auto& gsk = gssk.group_priv;
    const auto gpk = gsk->public_key();

    auto jwk_json = export_jwk_json(*gpk);

    // encode the private key
    const auto enc = serialize_private(sk);
    jwk_json.emplace("d", to_base64url(enc));

    return jwk_json.dump();
  }

private:
  const Group& group;

  json validate_jwk_json(const std::string& json_str, bool private_key) const
  {
    json jwk_json = json::parse(json_str);

    if (jwk_json.empty() || !jwk_json.contains("kty") ||
        !jwk_json.contains("crv") || !jwk_json.contains("x") ||
        (private_key && !jwk_json.contains("d"))) {
      throw std::runtime_error("malformed JWK");
    }

    if (jwk_json.at("kty") != group.jwk_key_type) {
      throw std::runtime_error("invalid JWK key type");
    }

    if (jwk_json.at("crv") != group.jwk_curve_name) {
      throw std::runtime_error("invalid JWK curve");
    }

    return jwk_json;
  }

  json export_jwk_json(const Group::PublicKey& pk) const
  {
    const auto [x, y] = group.coordinates(pk);

    json jwk_json = json::object({
      { "crv", group.jwk_curve_name },
      { "kty", group.jwk_key_type },
    });

    if (group.jwk_key_type == "EC") {
      jwk_json.emplace("x", to_base64url(x));
      jwk_json.emplace("y", to_base64url(y));
    } else if (group.jwk_key_type == "OKP") {
      jwk_json.emplace("x", to_base64url(x));
    } else {
      throw std::runtime_error("unknown key type");
    }

    return jwk_json;
  }
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
{
}

std::unique_ptr<Signature::PrivateKey>
Signature::generate_rsa(size_t bits)
{
  return RSASignature::generate_key_pair(bits);
}

} // namespace MLS_NAMESPACE::hpke
