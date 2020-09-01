#include "dhkem.h"
#include "common.h"
#include "openssl_common.h"

#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"

namespace hpke {

///
/// General implementation with OpenSSL EVP_PKEY
///

struct EVPGroup : public DHGroup
{
  EVPGroup(DHGroup::ID group_id, KDF::ID kdf_id)
    : DHGroup(group_id, kdf_id)
  {}

  struct PublicKey : public KEM::PublicKey
  {
    explicit PublicKey(EVP_PKEY* pkey_in)
      : pkey(pkey_in, typed_delete<EVP_PKEY>)
    {}

    ~PublicKey() override = default;

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    typed_unique_ptr<EVP_PKEY> pkey;
  };

  struct PrivateKey : public KEM::PrivateKey
  {
    explicit PrivateKey(EVP_PKEY* pkey_in)
      : pkey(pkey_in, typed_delete<EVP_PKEY>)
    {}

    ~PrivateKey() override = default;

    std::unique_ptr<KEM::PublicKey> public_key() const override
    {
      if (1 != EVP_PKEY_up_ref(pkey.get())) {
        throw openssl_error();
      }
      return std::make_unique<PublicKey>(pkey.get());
    }

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    typed_unique_ptr<EVP_PKEY> pkey;
  };

  std::unique_ptr<KEM::PrivateKey> generate_key_pair() const override
  {
    return derive_key_pair(random_bytes(sk_size()));
  }

  bytes dh(const KEM::PrivateKey& sk, const KEM::PublicKey& pk) const override
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
};

///
/// DH over "normal" curves
///

struct ECKeyGroup : public EVPGroup
{
  ECKeyGroup(DHGroup::ID group_id, KDF::ID kdf_id)
    : EVPGroup(group_id, kdf_id)
    , curve_nid(group_to_nid(group_id))
  {}

  std::unique_ptr<KEM::PrivateKey> derive_key_pair(
    const bytes& ikm) const override
  {
    static const int retry_limit = 255;
    static const auto label_dkp_prk = to_bytes("dkp_prk");
    static const auto label_candidate = to_bytes("candidate");

    auto dkp_prk = kdf->labeled_extract(suite_id, {}, label_dkp_prk, ikm);

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
        kdf->labeled_expand(suite_id, dkp_prk, label_candidate, ctr, sk_size());
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

    return std::make_unique<EVPGroup::PrivateKey>(to_pkey(eckey.release()));
  }

  bytes serialize(const KEM::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const PublicKey&>(pk);
    auto* pub = EVP_PKEY_get0_EC_KEY(rpk.pkey.get());

    auto len = i2o_ECPublicKey(pub, nullptr);
    if (len != static_cast<int>(pk_size())) {
      throw openssl_error();
    }

    bytes out(len);
    auto* data = out.data();
    if (i2o_ECPublicKey(pub, &data) == 0) {
      throw openssl_error();
    }

    return out;
  }

  std::unique_ptr<KEM::PublicKey> deserialize(const bytes& enc) const override
  {
    auto eckey = make_typed_unique(new_ec_key());
    auto* eckey_ptr = eckey.get();
    const auto* data_ptr = enc.data();
    if (nullptr == o2i_ECPublicKey(&eckey_ptr, &data_ptr, enc.size())) {
      throw openssl_error();
    }

    return std::make_unique<EVPGroup::PublicKey>(to_pkey(eckey.release()));
  }

  bytes serialize_private(const KEM::PrivateKey& sk) const override
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

  std::unique_ptr<KEM::PrivateKey> deserialize_private(
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

  static inline int group_to_nid(DHGroup::ID group_id)
  {
    switch (group_id) {
      case DHGroup::ID::P256:
        return NID_X9_62_prime256v1;
      case DHGroup::ID::P384:
        return NID_secp384r1;
      case DHGroup::ID::P521:
        return NID_secp521r1;
      default:
        throw std::runtime_error("Unsupported algorithm");
    }
  }

  uint8_t bitmask() const
  {
    switch (group_id) {
      case DHGroup::ID::P256:
      case DHGroup::ID::P384:
        return 0xff;

      case DHGroup::ID::P521:
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
  RawKeyGroup(DHGroup::ID group_id, KDF::ID kdf_id)
    : EVPGroup(group_id, kdf_id)
    , evp_type(group_to_evp(group_id))
  {}

  std::unique_ptr<KEM::PrivateKey> derive_key_pair(
    const bytes& ikm) const override
  {
    static const auto label_dkp_prk = to_bytes("dkp_prk");
    static const auto label_sk = to_bytes("sk");

    auto dkp_prk = kdf->labeled_extract(suite_id, {}, label_dkp_prk, ikm);
    auto skm = kdf->labeled_expand(suite_id, dkp_prk, label_sk, {}, sk_size());
    return deserialize_private(skm);
  }

  bytes serialize(const KEM::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const PublicKey&>(pk);
    auto raw = bytes(pk_size());
    auto* data_ptr = raw.data();
    auto data_len = raw.size();
    if (1 != EVP_PKEY_get_raw_public_key(rpk.pkey.get(), data_ptr, &data_len)) {
      throw openssl_error();
    }

    return raw;
  }

  std::unique_ptr<KEM::PublicKey> deserialize(const bytes& enc) const override
  {
    auto* pkey =
      EVP_PKEY_new_raw_public_key(evp_type, nullptr, enc.data(), enc.size());
    if (pkey == nullptr) {
      throw openssl_error();
    }

    return std::make_unique<EVPGroup::PublicKey>(pkey);
  }

  bytes serialize_private(const KEM::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    auto raw = bytes(sk_size());
    auto* data_ptr = raw.data();
    auto data_len = raw.size();
    if (1 !=
        EVP_PKEY_get_raw_private_key(rsk.pkey.get(), data_ptr, &data_len)) {
      throw openssl_error();
    }

    return raw;
  }

  std::unique_ptr<KEM::PrivateKey> deserialize_private(
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

  static inline int group_to_evp(DHGroup::ID group_id)
  {
    switch (group_id) {
      case DHGroup::ID::X25519:
        return EVP_PKEY_X25519;
      case DHGroup::ID::X448:
        return EVP_PKEY_X448;
      default:
        throw std::runtime_error("Unsupported algorithm");
    }
  }
};

///
/// General DH group
///

std::unique_ptr<DHGroup>
DHGroup::create(DHGroup::ID group_id, KDF::ID kdf_id)
{
  switch (group_id) {
    case DHGroup::ID::P256:
    case DHGroup::ID::P384:
    case DHGroup::ID::P521:
      return std::make_unique<ECKeyGroup>(group_id, kdf_id);

    case DHGroup::ID::X25519:
    case DHGroup::ID::X448:
      return std::make_unique<RawKeyGroup>(group_id, kdf_id);
  }
}

size_t
DHGroup::dh_size() const
{
  switch (group_id) {
    case DHGroup::ID::P256:
      return 32;
    case DHGroup::ID::P384:
      return 48;
    case DHGroup::ID::P521:
      return 66;
    case DHGroup::ID::X25519:
      return 32;
    case DHGroup::ID::X448:
      return 56;
  }
}

size_t
DHGroup::pk_size() const
{
  switch (group_id) {
    case DHGroup::ID::P256:
      return 65;
    case DHGroup::ID::P384:
      return 97;
    case DHGroup::ID::P521:
      return 133;
    case DHGroup::ID::X25519:
      return 32;
    case DHGroup::ID::X448:
      return 56;
  }
}

size_t
DHGroup::sk_size() const
{
  switch (group_id) {
    case DHGroup::ID::P256:
      return 32;
    case DHGroup::ID::P384:
      return 48;
    case DHGroup::ID::P521:
      return 66;
    case DHGroup::ID::X25519:
      return 32;
    case DHGroup::ID::X448:
      return 56;
  }
}

///
/// DHKEM
///

DHKEM::DHKEM(KEM::ID kem_id_in, DHGroup::ID group_id_in, KDF::ID kdf_id_in)
  : kem_id(kem_id_in)
  , group_id(group_id_in)
  , kdf_id(kdf_id_in)
  , dh(DHGroup::create(group_id_in, kdf_id_in))
  , kdf(KDF::create(kdf_id_in))
{
  static const auto label_kem = to_bytes("KEM");
  suite_id = label_kem + i2osp(uint16_t(kem_id_in), 2);
  dh->suite_id = suite_id;
}

std::unique_ptr<KEM>
DHKEM::clone() const
{
  return std::make_unique<DHKEM>(kem_id, group_id, kdf_id);
}

std::unique_ptr<KEM::PrivateKey>
DHKEM::generate_key_pair() const
{
  return dh->generate_key_pair();
}

std::unique_ptr<KEM::PrivateKey>
DHKEM::derive_key_pair(const bytes& ikm) const
{
  return dh->derive_key_pair(ikm);
}

bytes
DHKEM::serialize(const KEM::PublicKey& pk) const
{
  return dh->serialize(pk);
}

std::unique_ptr<KEM::PublicKey>
DHKEM::deserialize(const bytes& enc) const
{
  return dh->deserialize(enc);
}

bytes
DHKEM::serialize_private(const KEM::PrivateKey& sk) const
{
  return dh->serialize_private(sk);
}

std::unique_ptr<KEM::PrivateKey>
DHKEM::deserialize_private(const bytes& skm) const
{
  return dh->deserialize_private(skm);
}

std::pair<bytes, bytes>
DHKEM::encap(const KEM::PublicKey& pkR) const
{
  auto skE = dh->generate_key_pair();
  auto pkE = skE->public_key();

  auto zz = dh->dh(*skE, pkR);
  auto enc = dh->serialize(*pkE);

  auto pkRm = dh->serialize(pkR);
  auto kem_context = enc + pkRm;

  auto shared_secret = extract_and_expand(zz, kem_context);
  return std::make_pair(shared_secret, enc);
}

bytes
DHKEM::decap(const bytes& enc, const KEM::PrivateKey& skR) const
{
  auto pkR = skR.public_key();
  auto pkE = dh->deserialize(enc);
  auto zz = dh->dh(skR, *pkE);

  auto pkRm = dh->serialize(*pkR);
  auto kem_context = enc + pkRm;
  return extract_and_expand(zz, kem_context);
}

std::pair<bytes, bytes>
DHKEM::auth_encap(const KEM::PublicKey& pkR, const KEM::PrivateKey& skS) const
{
  auto skE = dh->generate_key_pair();
  auto pkE = skE->public_key();
  auto pkS = skS.public_key();

  auto zzER = dh->dh(*skE, pkR);
  auto zzSR = dh->dh(skS, pkR);
  auto zz = zzER + zzSR;
  auto enc = dh->serialize(*pkE);

  auto pkRm = dh->serialize(pkR);
  auto pkSm = dh->serialize(*pkS);
  auto kem_context = enc + pkRm + pkSm;

  auto shared_secret = extract_and_expand(zz, kem_context);
  return std::make_pair(shared_secret, enc);
}

bytes
DHKEM::auth_decap(const bytes& enc,
                  const KEM::PublicKey& pkS,
                  const KEM::PrivateKey& skR) const
{
  auto pkE = dh->deserialize(enc);
  auto pkR = skR.public_key();

  auto zzER = dh->dh(skR, *pkE);
  auto zzSR = dh->dh(skR, pkS);
  auto zz = zzER + zzSR;

  auto pkRm = dh->serialize(*pkR);
  auto pkSm = dh->serialize(pkS);
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
  return dh->pk_size();
}

size_t
DHKEM::pk_size() const
{
  return dh->pk_size();
}

size_t
DHKEM::sk_size() const
{
  return dh->sk_size();
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
