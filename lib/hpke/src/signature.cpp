#include <hpke/digest.h>
#include <hpke/signature.h>
#include <string>

#include "dhkem.h"

#include "common.h"
#include "group.h"
#include "rsa.h"
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace nlohmann;

namespace hpke {

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
    // TODO(ghewett): handle failed parse
    json jwk_json = json::parse(json_str);

    // TODO(ghewett): jwk_json should patch cipher suite

    // TODO(ghewett): handle the absense of 'd'
    bytes d = from_base64url(jwk_json["d"]);

    return std::make_unique<PrivateKey>(group.deserialize_private(d).release());
  }

  std::unique_ptr<Signature::PublicKey> import_jwk(
    const std::string& json_str) const override
  {
    bytes x = bytes({}, 0);
    bytes y = bytes({}, 0);
    json jwk_json = json::parse(json_str);

    if (jwk_json.empty() || !jwk_json.contains("kty") ||
        !jwk_json.contains("crv") || !jwk_json.contains("x")) {
      throw std::runtime_error("import_jwk: malformed json input");
    }

    if (jwk_json["kty"] != group.jwt_key_type) {
      throw std::runtime_error("import_jwk: group keytype does not match json");
    }

    if (jwk_json["crv"] != group.jwt_curve_name) {
      throw std::runtime_error("import_jwk: group curve does not match json");
    }
    x = from_base64url(jwk_json["x"]);

    if (jwk_json.contains("y")) {
      y = from_base64url(jwk_json["y"]);
    }
    return group.set_coordinates(x, y);
  }

  std::string export_jwk(const bytes& enc) const override
  {
    bytes x;
    bytes y;
    json json_jwk;
    json_jwk["crv"] = group.jwt_curve_name;
    json_jwk["kty"] = group.jwt_key_type;

    std::unique_ptr<hpke::Signature::PublicKey> pk = deserialize(enc);
    const auto& rpk =
      dynamic_cast<const hpke::Group::PublicKey&>(*(pk.release()));
    group.get_coordinates(rpk, x, y);

    if (!x.empty()) {
      json_jwk["x"] = to_base64url(x);
    }

    if (!y.empty()) {
      json_jwk["y"] = to_base64url(y);
    }
    return json_jwk.dump();
  }

  std::string export_jwk_private(const bytes& enc) const override
  {
    bytes x;
    bytes y;
    json json_jwk;
    json_jwk["crv"] = group.jwt_curve_name;
    json_jwk["kty"] = group.jwt_key_type;

    // encode the private key
    json_jwk["d"] = to_base64url(enc);

    const auto priv = group.deserialize_private(enc);
    const auto& rpk =
      dynamic_cast<const Group::PublicKey&>(*(priv->public_key().release()));
    group.get_coordinates(rpk, x, y);

    if (!x.empty()) {
      json_jwk["x"] = to_base64url(x);
    }

    if (!y.empty()) {
      json_jwk["y"] = to_base64url(y);
    }
    return json_jwk.dump();
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
{
}

bytes
Signature::serialize_private(const PrivateKey& /* unused */) const
{
  throw std::runtime_error("Not implemented");
}

std::unique_ptr<Signature::PublicKey>
Signature::import_jwk(const std::string& /* unused */) const
{
  throw std::runtime_error("Not implemented.");
}

std::unique_ptr<Signature::PrivateKey>
Signature::import_jwk_private(const std::string& /* unused */) const
{
  throw std::runtime_error("Not implemented.");
}

std::string
Signature::export_jwk(const bytes& /* unused */) const
{
  throw std::runtime_error("Not implemented.");
}

std::string
Signature::export_jwk_private(const bytes& /* unused */) const
{
  throw std::runtime_error("Not implemented.");
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
