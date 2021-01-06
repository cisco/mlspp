#include <hpke/digest.h>
#include <hpke/signature.h>

#include "dhkem.h"

#include "common.h"
#include "group.h"

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

// XXX(RLB): There is a lot of code in RSASignature that is duplicated in
// EVPGroup.  I have allowed this duplication rather than factoring it out
// because I would like to be able to cleanly remove RSA later.
struct RSASignature : public Signature
{
  struct PublicKey : public Signature::PublicKey
  {
    explicit PublicKey(EVP_PKEY* pkey_in)
      : pkey(pkey_in, typed_delete<EVP_PKEY>)
    {}

    ~PublicKey() override = default;

    typed_unique_ptr<EVP_PKEY> pkey;
  };

  struct PrivateKey : public Signature::PrivateKey
  {
    explicit PrivateKey(EVP_PKEY* pkey_in)
      : pkey(pkey_in, typed_delete<EVP_PKEY>)
    {}

    ~PrivateKey() override = default;

    std::unique_ptr<Signature::PublicKey> public_key() const override
    {
      if (1 != EVP_PKEY_up_ref(pkey.get())) {
        throw openssl_error();
      }
      return std::make_unique<PublicKey>(pkey.get());
    }

    typed_unique_ptr<EVP_PKEY> pkey;
  };

  explicit RSASignature(Digest::ID digest)
    : Signature(Signature::ID::RSA_SHA256)
    , md(digest_to_md(digest))
  {}

  std::unique_ptr<Signature::PrivateKey> generate_key_pair() const override
  {
    throw std::runtime_error("Not implemented");
  }

  std::unique_ptr<Signature::PrivateKey> derive_key_pair(
    const bytes& /*ikm*/) const override
  {
    throw std::runtime_error("Not implemented");
  }

  static std::unique_ptr<Signature::PrivateKey> generate_key_pair(size_t bits)
  {
    auto ctx = make_typed_unique(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (ctx == nullptr) {
      throw openssl_error();
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
      throw openssl_error();
    }

    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
      throw openssl_error();
    }

    auto* pkey = static_cast<EVP_PKEY*>(nullptr);
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
      throw openssl_error();
    }

    return std::make_unique<PrivateKey>(pkey);
  }

  // TODO(rlb): Implement derive() with sizes

  bytes serialize(const Signature::PublicKey& /*pk*/) const override
  {
    return {}; // TODO(rlb)
  }

  std::unique_ptr<Signature::PublicKey> deserialize(
    const bytes& /*enc*/) const override
  {
    return nullptr; // TODO(rlb)
  }

  bytes serialize_private(const Signature::PrivateKey& /*sk*/) const override
  {
    return {}; // TODO(rlb)
  }

  std::unique_ptr<Signature::PrivateKey> deserialize_private(
    const bytes& /*skm*/) const override
  {
    return nullptr; // TODO(rlb)
  }

  bytes sign(const bytes& data, const Signature::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);

    auto ctx = make_typed_unique(EVP_MD_CTX_create());
    if (ctx == nullptr) {
      throw openssl_error();
    }

    if (1 !=
        EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, rsk.pkey.get())) {
      throw openssl_error();
    }

    static const size_t max_sig_size = 256;
    auto siglen = max_sig_size;
    bytes sig(siglen);
    if (1 != EVP_DigestSign(
               ctx.get(), sig.data(), &siglen, data.data(), data.size())) {
      throw openssl_error();
    }

    sig.resize(siglen);
    return sig;
  }

  bool verify(const bytes& data,
              const bytes& sig,
              const Signature::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const PublicKey&>(pk);

    auto ctx = make_typed_unique(EVP_MD_CTX_create());
    if (ctx == nullptr) {
      throw openssl_error();
    }

    if (1 != EVP_DigestVerifyInit(
               ctx.get(), nullptr, md, nullptr, rpk.pkey.get())) {
      throw openssl_error();
    }

    auto rv = EVP_DigestVerify(
      ctx.get(), sig.data(), sig.size(), data.data(), data.size());

    return rv == 1;
  }

private:
  const EVP_MD* md;

  static const EVP_MD* digest_to_md(Digest::ID digest)
  {
    switch (digest) {
      case Digest::ID::SHA256:
        return EVP_sha256();
      case Digest::ID::SHA384:
        return EVP_sha384();
      case Digest::ID::SHA512:
        return EVP_sha512();
      default:
        throw std::runtime_error("Unsupported digest");
    }
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
