#include "group.h"

#include <hpke/random.h>

#include "common.h"
#include "openssl_common.h"

#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"

namespace hpke {

///
/// General implementation with OpenSSL EVP_PKEY
///

EVPGroup::EVPGroup(Group::ID group_id, const KDF& kdf)
  : Group(group_id, kdf)
{}

EVPGroup::PublicKey::PublicKey(EVP_PKEY* pkey_in)
  : pkey(pkey_in, typed_delete<EVP_PKEY>)
{}

EVPGroup::PrivateKey::PrivateKey(EVP_PKEY* pkey_in)
  : pkey(pkey_in, typed_delete<EVP_PKEY>)
{}

std::unique_ptr<Group::PublicKey>
EVPGroup::PrivateKey::public_key() const
{
  if (1 != EVP_PKEY_up_ref(pkey.get())) {
    throw openssl_error();
  }
  return std::make_unique<PublicKey>(pkey.get());
}

std::unique_ptr<Group::PrivateKey>
EVPGroup::generate_key_pair() const
{
  return derive_key_pair({}, random_bytes(sk_size));
}

bytes
EVPGroup::dh(const Group::PrivateKey& sk, const Group::PublicKey& pk) const
{
  const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
  const auto& rpk = dynamic_cast<const PublicKey&>(pk);

  // This and the next line are acceptable because the OpenSSL
  // functions fail to mark the required EVP_PKEYs as const, even
  // though they are not modified.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  auto* priv_pkey = const_cast<EVP_PKEY*>(rsk.pkey.get());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  auto* pub_pkey = const_cast<EVP_PKEY*>(rpk.pkey.get());

  auto ctx = make_typed_unique(EVP_PKEY_CTX_new(priv_pkey, nullptr));
  if (ctx == nullptr) {
    throw openssl_error();
  }

  if (1 != EVP_PKEY_derive_init(ctx.get())) {
    throw openssl_error();
  }

  if (1 != EVP_PKEY_derive_set_peer(ctx.get(), pub_pkey)) {
    throw openssl_error();
  }

  size_t out_len = 0;
  if (1 != EVP_PKEY_derive(ctx.get(), nullptr, &out_len)) {
    throw openssl_error();
  }

  bytes out(out_len);
  uint8_t* ptr = out.data();
  if (1 != (EVP_PKEY_derive(ctx.get(), ptr, &out_len))) {
    throw openssl_error();
  }

  return out;
}

bytes
EVPGroup::sign(const bytes& data, const Group::PrivateKey& sk) const
{
  const auto& rsk = dynamic_cast<const PrivateKey&>(sk);

  auto ctx = make_typed_unique(EVP_MD_CTX_create());
  if (ctx == nullptr) {
    throw openssl_error();
  }

  if (1 != EVP_DigestSignInit(
             ctx.get(), nullptr, nullptr, nullptr, rsk.pkey.get())) {
    throw openssl_error();
  }

  static const size_t max_sig_size = 200;
  auto siglen = max_sig_size;
  bytes sig(siglen);
  if (1 != EVP_DigestSign(
             ctx.get(), sig.data(), &siglen, data.data(), data.size())) {
    throw openssl_error();
  }

  sig.resize(siglen);
  return sig;
}

bool
EVPGroup::verify(const bytes& data,
                 const bytes& sig,
                 const Group::PublicKey& pk) const
{
  const auto& rpk = dynamic_cast<const PublicKey&>(pk);

  auto ctx = make_typed_unique(EVP_MD_CTX_create());
  if (ctx == nullptr) {
    throw openssl_error();
  }

  if (1 != EVP_DigestVerifyInit(
             ctx.get(), nullptr, nullptr, nullptr, rpk.pkey.get())) {
    throw openssl_error();
  }

  auto rv = EVP_DigestVerify(
    ctx.get(), sig.data(), sig.size(), data.data(), data.size());

  return rv == 1;
}

///
/// DH over "normal" curves
///

struct ECKeyGroup : public EVPGroup
{
  ECKeyGroup(Group::ID group_id, const KDF& kdf)
    : EVPGroup(group_id, kdf)
    , curve_nid(group_to_nid(group_id))
  {}

  std::unique_ptr<Group::PrivateKey> derive_key_pair(
    const bytes& suite_id,
    const bytes& ikm) const override
  {
    static const int retry_limit = 255;
    static const auto label_dkp_prk = to_bytes("dkp_prk");
    static const auto label_candidate = to_bytes("candidate");

    auto dkp_prk = kdf.labeled_extract(suite_id, {}, label_dkp_prk, ikm);

    auto eckey = make_typed_unique(new_ec_key());
    const auto* group = EC_KEY_get0_group(eckey.get());

    auto order = make_typed_unique(BN_new());
    if (1 != EC_GROUP_get_order(group, order.get(), nullptr)) {
      throw openssl_error();
    }

    auto sk = make_typed_unique(BN_new());
    if (1 != BN_zero(sk.get())) {
      throw openssl_error();
    }

    auto counter = int(0);
    while (BN_is_zero(sk.get()) != 0 || BN_cmp(sk.get(), order.get()) != -1) {
      auto ctr = i2osp(counter, 1);
      auto candidate =
        kdf.labeled_expand(suite_id, dkp_prk, label_candidate, ctr, sk_size);
      candidate[0] &= bitmask();
      sk.reset(BN_bin2bn(candidate.data(), candidate.size(), nullptr));

      counter += 1;
      if (counter > retry_limit) {
        throw std::runtime_error("DeriveKeyPair iteration limit exceeded");
      }
    }

    auto pt = make_typed_unique(EC_POINT_new(group));
    EC_POINT_mul(group, pt.get(), sk.get(), nullptr, nullptr, nullptr);

    EC_KEY_set_private_key(eckey.get(), sk.get());
    EC_KEY_set_public_key(eckey.get(), pt.get());

    return std::make_unique<PrivateKey>(to_pkey(eckey.release()));
  }

  bytes serialize(const Group::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const PublicKey&>(pk);
    auto* pub = EVP_PKEY_get0_EC_KEY(rpk.pkey.get());

    auto len = i2o_ECPublicKey(pub, nullptr);
    if (len != static_cast<int>(pk_size)) {
      throw openssl_error();
    }

    bytes out(len);
    auto* data = out.data();
    if (i2o_ECPublicKey(pub, &data) == 0) {
      throw openssl_error();
    }

    return out;
  }

  std::unique_ptr<Group::PublicKey> deserialize(const bytes& enc) const override
  {
    auto eckey = make_typed_unique(new_ec_key());
    auto* eckey_ptr = eckey.get();
    const auto* data_ptr = enc.data();
    if (nullptr == o2i_ECPublicKey(&eckey_ptr, &data_ptr, enc.size())) {
      throw openssl_error();
    }

    return std::make_unique<EVPGroup::PublicKey>(to_pkey(eckey.release()));
  }

  bytes serialize_private(const Group::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    auto* eckey = EVP_PKEY_get0_EC_KEY(rsk.pkey.get());
    const auto* d = EC_KEY_get0_private_key(eckey);

    bytes out(BN_num_bytes(d));
    if (BN_bn2bin(d, out.data()) != int(out.size())) {
      throw openssl_error();
    }

    return out;
  }

  std::unique_ptr<Group::PrivateKey> deserialize_private(
    const bytes& skm) const override
  {
    auto eckey = make_typed_unique(new_ec_key());
    const auto* group = EC_KEY_get0_group(eckey.get());
    const auto d =
      make_typed_unique(BN_bin2bn(skm.data(), skm.size(), nullptr));
    auto pt = make_typed_unique(EC_POINT_new(group));

    EC_POINT_mul(group, pt.get(), d.get(), nullptr, nullptr, nullptr);
    EC_KEY_set_private_key(eckey.get(), d.get());
    EC_KEY_set_public_key(eckey.get(), pt.get());

    return std::make_unique<EVPGroup::PrivateKey>(to_pkey(eckey.release()));
  }

private:
  int curve_nid;

  EC_KEY* new_ec_key() const { return EC_KEY_new_by_curve_name(curve_nid); }

  static EVP_PKEY* to_pkey(EC_KEY* eckey)
  {
    auto* pkey = EVP_PKEY_new();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    return pkey;
  }

  static inline int group_to_nid(Group::ID group_id)
  {
    switch (group_id) {
      case Group::ID::P256:
        return NID_X9_62_prime256v1;
      case Group::ID::P384:
        return NID_secp384r1;
      case Group::ID::P521:
        return NID_secp521r1;
      default:
        throw std::runtime_error("Unsupported algorithm");
    }
  }

  uint8_t bitmask() const
  {
    switch (id) {
      case Group::ID::P256:
      case Group::ID::P384:
        return 0xff;

      case Group::ID::P521:
        return 0x01;

      default:
        throw std::runtime_error("Unsupported algorithm");
    }
  }
};

///
/// DH over "raw" curves
///

struct RawKeyGroup : public EVPGroup
{
  RawKeyGroup(Group::ID group_id, const KDF& kdf)
    : EVPGroup(group_id, kdf)
    , evp_type(group_to_evp(group_id))
  {}

  template<Group::ID id>
  static const RawKeyGroup instance;

  std::unique_ptr<Group::PrivateKey> derive_key_pair(
    const bytes& suite_id,
    const bytes& ikm) const override
  {
    static const auto label_dkp_prk = to_bytes("dkp_prk");
    static const auto label_sk = to_bytes("sk");

    auto dkp_prk = kdf.labeled_extract(suite_id, {}, label_dkp_prk, ikm);
    auto skm = kdf.labeled_expand(suite_id, dkp_prk, label_sk, {}, sk_size);
    return deserialize_private(skm);
  }

  bytes serialize(const Group::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const PublicKey&>(pk);
    auto raw = bytes(pk_size);
    auto* data_ptr = raw.data();
    auto data_len = raw.size();
    if (1 != EVP_PKEY_get_raw_public_key(rpk.pkey.get(), data_ptr, &data_len)) {
      throw openssl_error();
    }

    return raw;
  }

  std::unique_ptr<Group::PublicKey> deserialize(const bytes& enc) const override
  {
    auto* pkey =
      EVP_PKEY_new_raw_public_key(evp_type, nullptr, enc.data(), enc.size());
    if (pkey == nullptr) {
      throw openssl_error();
    }

    return std::make_unique<EVPGroup::PublicKey>(pkey);
  }

  bytes serialize_private(const Group::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    auto raw = bytes(sk_size);
    auto* data_ptr = raw.data();
    auto data_len = raw.size();
    if (1 !=
        EVP_PKEY_get_raw_private_key(rsk.pkey.get(), data_ptr, &data_len)) {
      throw openssl_error();
    }

    return raw;
  }

  std::unique_ptr<Group::PrivateKey> deserialize_private(
    const bytes& skm) const override
  {
    auto* pkey =
      EVP_PKEY_new_raw_private_key(evp_type, nullptr, skm.data(), skm.size());
    if (pkey == nullptr) {
      throw openssl_error();
    }

    return std::make_unique<EVPGroup::PrivateKey>(pkey);
  }

private:
  const int evp_type;

  static inline int group_to_evp(Group::ID group_id)
  {
    switch (group_id) {
      case Group::ID::X25519:
        return EVP_PKEY_X25519;
      case Group::ID::X448:
        return EVP_PKEY_X448;
      case Group::ID::Ed25519:
        return EVP_PKEY_ED25519;
      case Group::ID::Ed448:
        return EVP_PKEY_ED448;
      default:
        throw std::runtime_error("Unsupported algorithm");
    }
  }
};

///
/// General DH group
///

template<>
const Group&
Group::get<Group::ID::P256>()
{
  static const ECKeyGroup instance(Group::ID::P256,
                                   KDF::get<KDF::ID::HKDF_SHA256>());

  return instance;
}

template<>
const Group&
Group::get<Group::ID::P384>()
{
  static const ECKeyGroup instance(Group::ID::P384,
                                   KDF::get<KDF::ID::HKDF_SHA384>());

  return instance;
}

template<>
const Group&
Group::get<Group::ID::P521>()
{
  static const ECKeyGroup instance(Group::ID::P521,
                                   KDF::get<KDF::ID::HKDF_SHA512>());

  return instance;
}

template<>
const Group&
Group::get<Group::ID::X25519>()
{
  static const RawKeyGroup instance(Group::ID::X25519,
                                    KDF::get<KDF::ID::HKDF_SHA256>());
  return instance;
}

template<>
const Group&
Group::get<Group::ID::Ed25519>()
{
  static const RawKeyGroup instance(Group::ID::Ed25519,
                                    KDF::get<KDF::ID::HKDF_SHA256>());
  return instance;
}

template<>
const Group&
Group::get<Group::ID::X448>()
{
  static const RawKeyGroup instance(Group::ID::X448,
                                    KDF::get<KDF::ID::HKDF_SHA512>());
  return instance;
}

template<>
const Group&
Group::get<Group::ID::Ed448>()
{
  static const RawKeyGroup instance(Group::ID::Ed448,
                                    KDF::get<KDF::ID::HKDF_SHA512>());
  return instance;
}

static inline size_t
group_dh_size(Group::ID group_id)
{
  switch (group_id) {
    case Group::ID::P256:
      return 32;
    case Group::ID::P384:
      return 48;
    case Group::ID::P521:
      return 66;
    case Group::ID::X25519:
      return 32;
    case Group::ID::X448:
      return 56;

    // Non-DH groups
    case Group::ID::Ed25519:
    case Group::ID::Ed448:
      return 0;

    default:
      throw std::runtime_error("Unknown group");
  }
}

static inline size_t
group_pk_size(Group::ID group_id)
{
  switch (group_id) {
    case Group::ID::P256:
      return 65;
    case Group::ID::P384:
      return 97;
    case Group::ID::P521:
      return 133;
    case Group::ID::X25519:
    case Group::ID::Ed25519:
      return 32;
    case Group::ID::X448:
      return 56;
    case Group::ID::Ed448:
      return 57;

    default:
      throw std::runtime_error("Unknown group");
  }
}

static inline size_t
group_sk_size(Group::ID group_id)
{
  switch (group_id) {
    case Group::ID::P256:
      return 32;
    case Group::ID::P384:
      return 48;
    case Group::ID::P521:
      return 66;
    case Group::ID::X25519:
    case Group::ID::Ed25519:
      return 32;
    case Group::ID::X448:
      return 56;
    case Group::ID::Ed448:
      return 57;

    default:
      throw std::runtime_error("Unknown group");
  }
}

Group::Group(ID group_id_in, const KDF& kdf_in)
  : id(group_id_in)
  , dh_size(group_dh_size(group_id_in))
  , pk_size(group_pk_size(group_id_in))
  , sk_size(group_sk_size(group_id_in))
  , kdf(kdf_in)
{}

} // namespace hpke
