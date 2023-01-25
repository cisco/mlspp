#include "group.h"

#include <hpke/random.h>

#include "common.h"
#include "openssl_common.h"

#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#if defined(WITH_OPENSSL3)
#include "openssl/core_names.h"
#include "openssl/param_build.h"
#endif

namespace hpke {

static inline size_t
group_dh_size(Group::ID group_id);

///
/// General implementation with OpenSSL EVP_PKEY
///

EVPGroup::EVPGroup(Group::ID group_id, const KDF& kdf)
  : Group(group_id, kdf)
{
}

EVPGroup::PublicKey::PublicKey(EVP_PKEY* pkey_in)
  : pkey(pkey_in, typed_delete<EVP_PKEY>)
{
}

EVPGroup::PrivateKey::PrivateKey(EVP_PKEY* pkey_in)
  : pkey(pkey_in, typed_delete<EVP_PKEY>)
{
}

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

  size_t siglen = EVP_PKEY_size(rsk.pkey.get());
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
  {
  }

#if defined(WITH_OPENSSL3)
  int EVP_PKEY_set_keys(EVP_PKEY* key, const bytes& sk, const bytes& pk) const
  {
    auto d = make_typed_unique(BN_bin2bn(sk.data(), sk.size(), nullptr));
    if (d == nullptr) {
      throw openssl_error();
    }

    auto group = make_typed_unique(
      EC_GROUP_new_by_curve_name_ex(nullptr, nullptr, curve_nid));
    if (group == nullptr) {
      throw openssl_error();
    }

    bytes pub(pk);
    if (pk.size() == 0) {
      auto pt = make_typed_unique(EC_POINT_new(group.get()));
      if (pt == nullptr) {
        throw openssl_error();
      }

      if (1 != EC_POINT_mul(
                 group.get(), pt.get(), d.get(), nullptr, nullptr, nullptr)) {
        throw openssl_error();
      }

      size_t pt_size = EC_POINT_point2oct(group.get(),
                                          pt.get(),
                                          POINT_CONVERSION_UNCOMPRESSED,
                                          nullptr,
                                          0,
                                          nullptr);
      if (!pt_size) {
        return 0;
      }

      pub.resize(pt_size);
      if (EC_POINT_point2oct(group.get(),
                             pt.get(),
                             POINT_CONVERSION_UNCOMPRESSED,
                             pub.data(),
                             pt_size,
                             nullptr) != pt_size) {
        return 0;
      }
    }

    auto bld = make_typed_unique(OSSL_PARAM_BLD_new());
    if (bld == nullptr ||
        !OSSL_PARAM_BLD_push_utf8_string(
          bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(curve_nid), 0) ||
        !OSSL_PARAM_BLD_push_octet_string(
          bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size())) {
      throw openssl_error();
    }

    if (sk.size() > 0 &&
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, d.get())) {
      throw openssl_error();
    }

    auto params = make_typed_unique(OSSL_PARAM_BLD_to_param(bld.get()));
    auto ctx =
      make_typed_unique(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (params == nullptr || ctx == nullptr ||
        EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_KEYPAIR, params.get()) <= 0)
      throw openssl_error();
    ctx.reset();

    ctx = make_typed_unique(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr));
    if (sk.size() > 0) {
      if (EVP_PKEY_check(ctx.get()) <= 0) {
        throw openssl_error();
      }
    } else {
      if (EVP_PKEY_public_check(ctx.get()) <= 0) {
        throw openssl_error();
      }
    }

    return 1;
  }
#endif

  std::unique_ptr<Group::PrivateKey> derive_key_pair(
    const bytes& suite_id,
    const bytes& ikm) const override
  {
    static const int retry_limit = 255;
    static const auto label_dkp_prk = from_ascii("dkp_prk");
    static const auto label_candidate = from_ascii("candidate");

    auto dkp_prk = kdf.labeled_extract(suite_id, {}, label_dkp_prk, ikm);

#if defined(WITH_OPENSSL3)
    EC_GROUP* group =
      EC_GROUP_new_by_curve_name_ex(nullptr, nullptr, curve_nid);
    auto group_ptr = make_typed_unique(group);
#else
    auto eckey = make_typed_unique(new_ec_key());
    const auto* group = EC_KEY_get0_group(eckey.get());
#endif

    auto order = make_typed_unique(BN_new());
    if (1 != EC_GROUP_get_order(group, order.get(), nullptr)) {
      throw openssl_error();
    }

    auto sk = make_typed_unique(BN_new());
    BN_zero(sk.get());

    auto counter = int(0);
    while (BN_is_zero(sk.get()) != 0 || BN_cmp(sk.get(), order.get()) != -1) {
      auto ctr = i2osp(counter, 1);
      auto candidate =
        kdf.labeled_expand(suite_id, dkp_prk, label_candidate, ctr, sk_size);
      candidate.at(0) &= bitmask();
      sk.reset(BN_bin2bn(
        candidate.data(), static_cast<int>(candidate.size()), nullptr));

      counter += 1;
      if (counter > retry_limit) {
        throw std::runtime_error("DeriveKeyPair iteration limit exceeded");
      }
    }

#if defined(WITH_OPENSSL3)
    auto sk_buf = bytes(BN_num_bytes(sk.get()));
    auto* data = sk_buf.data();
    if (BN_bn2bin(sk.get(), data) != int(sk_buf.size())) {
      throw openssl_error();
    }

    auto* key = new_pkey();
    if (!EVP_PKEY_set_keys(key, sk_buf, {})) {
      throw std::runtime_error("DeriveKeyPair fails to create key-pair");
    }

    return std::make_unique<PrivateKey>(key);
#else
    auto pt = make_typed_unique(EC_POINT_new(group));
    EC_POINT_mul(group, pt.get(), sk.get(), nullptr, nullptr, nullptr);

    EC_KEY_set_private_key(eckey.get(), sk.get());
    EC_KEY_set_public_key(eckey.get(), pt.get());

    return std::make_unique<PrivateKey>(to_pkey(eckey.release()));
#endif
  }

  bytes serialize(const Group::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const PublicKey&>(pk);
#if defined(WITH_OPENSSL3)
    OSSL_PARAM* param = nullptr;
    if (!EVP_PKEY_todata(rpk.pkey.get(), EVP_PKEY_PUBLIC_KEY, &param)) {
      throw openssl_error();
    }
    auto param_ptr = make_typed_unique(param);

    const OSSL_PARAM* pk_param =
      OSSL_PARAM_locate_const(param_ptr.get(), OSSL_PKEY_PARAM_PUB_KEY);
    if (pk_param == nullptr) {
      return bytes({}, 0);
    }

    size_t len = 0;
    if (!OSSL_PARAM_get_octet_string(pk_param, nullptr, 0, &len)) {
      return bytes({}, 0);
    }

    bytes out(len);
    auto* data = out.data();
    if (!OSSL_PARAM_get_octet_string(
          pk_param, reinterpret_cast<void**>(&data), len, nullptr)) {
      return bytes({}, 0);
    }
#else
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
#endif
    return out;
  }

  std::unique_ptr<Group::PublicKey> deserialize(const bytes& enc) const override
  {
#if defined(WITH_OPENSSL3)
    auto* key = new_pkey();
    if (!EVP_PKEY_set_keys(key, {}, enc)) {
      throw std::runtime_error("Unable to deserialize the public key");
    }
    return std::make_unique<EVPGroup::PublicKey>(key);
#else
    auto eckey = make_typed_unique(new_ec_key());
    auto* eckey_ptr = eckey.get();
    const auto* data_ptr = enc.data();
    if (nullptr ==
        o2i_ECPublicKey(&eckey_ptr,
                        &data_ptr,
                        static_cast<long>( // NOLINT(google-runtime-int)
                          enc.size()))) {
      throw openssl_error();
    }

    return std::make_unique<EVPGroup::PublicKey>(to_pkey(eckey.release()));
#endif
  }

  bytes serialize_private(const Group::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
#if defined(WITH_OPENSSL3)
    OSSL_PARAM* param = nullptr;
    if (!EVP_PKEY_todata(rsk.pkey.get(), EVP_PKEY_KEYPAIR, &param)) {
      throw openssl_error();
    }
    auto param_ptr = make_typed_unique(param);

    const OSSL_PARAM* sk_param =
      OSSL_PARAM_locate_const(param_ptr.get(), OSSL_PKEY_PARAM_PRIV_KEY);
    if (sk_param == nullptr) {
      return bytes({}, 0);
    }

    BIGNUM* d = nullptr;
    if (!OSSL_PARAM_get_BN(sk_param, &d)) {
      return bytes({}, 0);
    }
    auto d_ptr = make_typed_unique(d);
#else
    auto* eckey = EVP_PKEY_get0_EC_KEY(rsk.pkey.get());
    const auto* d = EC_KEY_get0_private_key(eckey);
#endif

    auto out = bytes(BN_num_bytes(d));
    if (BN_bn2bin(d, out.data()) != int(out.size())) {
      throw openssl_error();
    }

    const auto zeros_needed = group_dh_size(id) - out.size();
    auto leading_zeros = bytes(zeros_needed, 0);
    return leading_zeros + out;
  }

  std::unique_ptr<Group::PrivateKey> deserialize_private(
    const bytes& skm) const override
  {
#if defined(WITH_OPENSSL3)
    auto* key = new_pkey();
    if (!EVP_PKEY_set_keys(key, skm, {})) {
      throw std::runtime_error("Unable to deserialize the private key");
    }
    return std::make_unique<EVPGroup::PrivateKey>(key);
#else
    auto eckey = make_typed_unique(new_ec_key());
    const auto* group = EC_KEY_get0_group(eckey.get());
    const auto d = make_typed_unique(
      BN_bin2bn(skm.data(), static_cast<int>(skm.size()), nullptr));
    auto pt = make_typed_unique(EC_POINT_new(group));

    EC_POINT_mul(group, pt.get(), d.get(), nullptr, nullptr, nullptr);
    EC_KEY_set_private_key(eckey.get(), d.get());
    EC_KEY_set_public_key(eckey.get(), pt.get());

    return std::make_unique<EVPGroup::PrivateKey>(to_pkey(eckey.release()));
#endif
  }

private:
  int curve_nid;

#if defined(WITH_OPENSSL3)
  EVP_PKEY* new_pkey() const
  {
    auto name = OBJ_nid2sn(curve_nid);
    if (name == nullptr) {
      throw std::runtime_error("Unsupported algorithm");
    }
    return EVP_EC_gen(name);
  }
#else
  EC_KEY* new_ec_key() const
  {
    return EC_KEY_new_by_curve_name(curve_nid);
  }

  static EVP_PKEY* to_pkey(EC_KEY* eckey)
  {
    auto* pkey = EVP_PKEY_new();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    return pkey;
  }
#endif

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
  {
  }

  template<Group::ID id>
  static const RawKeyGroup instance;

  std::unique_ptr<Group::PrivateKey> derive_key_pair(
    const bytes& suite_id,
    const bytes& ikm) const override
  {
    static const auto label_dkp_prk = from_ascii("dkp_prk");
    static const auto label_sk = from_ascii("sk");

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
{
}

} // namespace hpke
