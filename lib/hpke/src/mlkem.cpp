#if !defined(WITH_BORINGSSL)

#include "mlkem.h"

#include "common.h"
#include "openssl_common.h"
#include <cassert>
#include <hpke/random.h>
#include <namespace.h>

#if defined(WITH_OPENSSL3)
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <openssl/params.h>
#else
#include <openssl/evp.h>
#include <oqs/oqs.h>
#endif

namespace MLS_NAMESPACE::hpke {

MLKEM::PublicKey::PublicKey(bytes pk_in)
  : pk(std::move(pk_in))
{
}

MLKEM::PrivateKey::PrivateKey(bytes sk_in, bytes expanded_sk_in, bytes pk_in)
  : sk(std::move(sk_in))
  , expanded_sk(std::move(expanded_sk_in))
  , pk(std::move(pk_in))
{
}

std::unique_ptr<KEM::PublicKey>
MLKEM::PrivateKey::public_key() const
{
  return std::make_unique<MLKEM::PublicKey>(pk);
}

static size_t
get_enc_size(KEM::ID kem_id)
{
  switch (kem_id) {
    case KEM::ID::MLKEM512:
      return 768;
    case KEM::ID::MLKEM768:
      return 1088;
    case KEM::ID::MLKEM1024:
      return 1568;
    default:
      throw std::runtime_error("unreachable");
  }
}

static size_t
get_pk_size(KEM::ID kem_id)
{
  switch (kem_id) {
    case KEM::ID::MLKEM512:
      return 800;
    case KEM::ID::MLKEM768:
      return 1184;
    case KEM::ID::MLKEM1024:
      return 1568;
    default:
      throw std::runtime_error("unreachable");
  }
}

MLKEM
make_mlkem(KEM::ID kem_id_in)
{
  return { kem_id_in };
}

template<>
const MLKEM&
MLKEM::get<KEM::ID::MLKEM512>()
{
  static const auto instance = make_mlkem(KEM::ID::MLKEM512);
  return instance;
}

template<>
const MLKEM&
MLKEM::get<KEM::ID::MLKEM768>()
{
  static const auto instance = make_mlkem(KEM::ID::MLKEM768);
  return instance;
}

template<>
const MLKEM&
MLKEM::get<KEM::ID::MLKEM1024>()
{
  static const auto instance = make_mlkem(KEM::ID::MLKEM1024);
  return instance;
}

#if defined(WITH_OPENSSL3)

static const char*
get_algorithm_name(KEM::ID kem_id)
{
  switch (kem_id) {
    case KEM::ID::MLKEM512:
      return "ML-KEM-512";
    case KEM::ID::MLKEM768:
      return "ML-KEM-768";
    case KEM::ID::MLKEM1024:
      return "ML-KEM-1024";
    default:
      throw std::runtime_error("unreachable");
  }
}

static typed_unique_ptr<EVP_PKEY>
evp_pkey_from_seed(KEM::ID kem_id, const bytes& sk)
{
  auto fromdata_ctx = make_typed_unique(
    EVP_PKEY_CTX_new_from_name(nullptr, get_algorithm_name(kem_id), nullptr));
  if (!fromdata_ctx) {
    throw openssl_error();
  }

  if (EVP_PKEY_fromdata_init(fromdata_ctx.get()) <= 0) {
    throw openssl_error();
  }

  auto fromdata_params = std::array{
    OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_ML_KEM_SEED, const_cast<uint8_t*>(sk.data()), sk.size()),
    OSSL_PARAM_construct_end()
  };

  auto* raw_pkey = static_cast<EVP_PKEY*>(nullptr);
  if (EVP_PKEY_fromdata(fromdata_ctx.get(),
                        &raw_pkey,
                        EVP_PKEY_KEYPAIR,
                        fromdata_params.data()) <= 0) {
    throw openssl_error();
  }

  return make_typed_unique(raw_pkey);
}

static std::tuple<bytes, bytes>
expand_secret_key(KEM::ID kem_id, const bytes& sk)
{
  auto pkey = evp_pkey_from_seed(kem_id, sk);

  // Extract public key
  auto pk_size = get_pk_size(kem_id);
  auto pk = bytes(pk_size);
  auto pk_len = pk.size();

  if (EVP_PKEY_get_raw_public_key(pkey.get(), pk.data(), &pk_len) <= 0) {
    throw openssl_error();
  }

  // Extract raw private key
  size_t priv_len = 0;
  if (EVP_PKEY_get_raw_private_key(pkey.get(), nullptr, &priv_len) <= 0) {
    throw openssl_error();
  }

  auto expanded_sk = bytes(priv_len);
  if (EVP_PKEY_get_raw_private_key(pkey.get(), expanded_sk.data(), &priv_len) <=
      0) {
    throw openssl_error();
  }

  return { expanded_sk, pk };
}

static std::pair<bytes, bytes>
do_encap(KEM::ID kem_id, const bytes& pk_bytes)
{
  // Create EVP_PKEY from public key bytes
  auto pkey =
    make_typed_unique(EVP_PKEY_new_raw_public_key_ex(nullptr,
                                                     get_algorithm_name(kem_id),
                                                     nullptr,
                                                     pk_bytes.data(),
                                                     pk_bytes.size()));

  if (!pkey) {
    throw openssl_error();
  }

  auto encap_ctx = make_typed_unique(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (!encap_ctx) {
    throw openssl_error();
  }

  if (EVP_PKEY_encapsulate_init(encap_ctx.get(), nullptr) <= 0) {
    throw openssl_error();
  }

  auto ct_len = size_t{ 0 };
  auto ss_len = size_t{ 0 };
  if (EVP_PKEY_encapsulate(
        encap_ctx.get(), nullptr, &ct_len, nullptr, &ss_len) <= 0) {
    throw openssl_error();
  }

  auto ct = bytes(ct_len);
  auto ss = bytes(ss_len);

  if (EVP_PKEY_encapsulate(
        encap_ctx.get(), ct.data(), &ct_len, ss.data(), &ss_len) <= 0) {
    throw openssl_error();
  }

  return { ss, ct };
}

static bytes
do_decap(KEM::ID kem_id, const bytes& enc, const bytes& expanded_sk)
{
  auto* raw_pkey = EVP_PKEY_new_raw_private_key_ex(nullptr,
                                                   get_algorithm_name(kem_id),
                                                   nullptr,
                                                   expanded_sk.data(),
                                                   expanded_sk.size());

  if (!raw_pkey) {
    throw openssl_error();
  }

  auto pkey = make_typed_unique(raw_pkey);

  auto decap_ctx = make_typed_unique(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (!decap_ctx) {
    throw openssl_error();
  }

  if (EVP_PKEY_decapsulate_init(decap_ctx.get(), nullptr) <= 0) {
    throw openssl_error();
  }

  auto ss_len = size_t{ 0 };
  if (EVP_PKEY_decapsulate(
        decap_ctx.get(), nullptr, &ss_len, enc.data(), enc.size()) <= 0) {
    throw openssl_error();
  }

  auto ss = bytes(ss_len);

  if (EVP_PKEY_decapsulate(
        decap_ctx.get(), ss.data(), &ss_len, enc.data(), enc.size()) <= 0) {
    throw openssl_error();
  }

  return ss;
}

#else

template<>
void
typed_delete(OQS_KEM* ptr)
{
  OQS_KEM_free(ptr);
}

static typed_unique_ptr<OQS_KEM>
get_oqs_kem(KEM::ID kem_id)
{
  OQS_KEM* kem_ptr = nullptr;
  switch (kem_id) {
    case KEM::ID::MLKEM512:
      kem_ptr = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
      break;
    case KEM::ID::MLKEM768:
      kem_ptr = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
      break;
    case KEM::ID::MLKEM1024:
      kem_ptr = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
      break;
    default:
      throw std::runtime_error("unreachable");
  }
  return make_typed_unique(kem_ptr);
}

// XXX Revert comments here once vcpkg updates their version of boringssl
static std::tuple<bytes, bytes>
expand_secret_key(KEM::ID kem_id, const bytes& /* XXX sk */)
{
  auto kem = get_oqs_kem(kem_id);
  // XXX assert(sk.size() == kem->length_keypair_seed);
  auto expanded_sk = bytes(kem->length_secret_key);
  auto pk = bytes(kem->length_public_key);
  // XXX const auto rv = kem->keypair_derand(pk.data(), expanded_sk.data(), sk.data());
  const auto rv = kem->keypair(pk.data(), expanded_sk.data()); // XXX
  if (rv != OQS_SUCCESS) {
    throw std::runtime_error(std::to_string(rv));
  }

  return { expanded_sk, pk };
}

static std::pair<bytes, bytes>
do_encap(KEM::ID kem_id, const bytes& pk_bytes)
{
  auto kem = get_oqs_kem(kem_id);
  auto ct = bytes(kem->length_ciphertext);
  auto ss = bytes(kem->length_shared_secret);
  const auto rv = kem->encaps(ct.data(), ss.data(), pk_bytes.data());
  if (rv != OQS_SUCCESS) {
    throw std::runtime_error(std::to_string(rv));
  }

  return { ss, ct };
}

static bytes
do_decap(KEM::ID kem_id, const bytes& enc, const bytes& expanded_sk)
{
  auto kem = get_oqs_kem(kem_id);
  auto ss = bytes(kem->length_shared_secret);
  const auto rv = kem->decaps(ss.data(), enc.data(), expanded_sk.data());
  if (rv != OQS_SUCCESS) {
    throw std::runtime_error(std::to_string(rv));
  }

  return ss;
}

#endif

static bytes
labeled_derive(KEM::ID kem_id,
               const bytes& ikm,
               const std::string& label,
               const bytes& context,
               size_t length)
{
  const auto hpke_version = from_ascii("HPKE-v1");
  const auto label_kem = from_ascii("KEM");
  const auto suite_id = label_kem + i2osp(uint16_t(kem_id), 2);
  const auto label_bytes = from_ascii(label);
  const auto label_len = i2osp(uint16_t(label_bytes.size()), 2);
  const auto length_bytes = i2osp(uint16_t(length), 2);

  auto labeled_ikm = ikm + hpke_version + suite_id + label_len + label_bytes +
                     length_bytes + context;

  auto ctx = make_typed_unique(EVP_MD_CTX_new());
  if (!ctx) {
    throw openssl_error();
  }

  if (EVP_DigestInit_ex(ctx.get(), EVP_shake256(), nullptr) != 1) {
    throw openssl_error();
  }

  if (EVP_DigestUpdate(ctx.get(), labeled_ikm.data(), labeled_ikm.size()) !=
      1) {
    throw openssl_error();
  }

  auto out = bytes(length);
  if (EVP_DigestFinalXOF(ctx.get(), out.data(), out.size()) != 1) {
    throw openssl_error();
  }

  return out;
}

MLKEM::MLKEM(KEM::ID kem_id_in)
  : KEM(kem_id_in,
        MLKEM::secret_size,
        get_enc_size(kem_id_in),
        get_pk_size(kem_id_in),
        MLKEM::sk_size)
  , kem_id(kem_id_in)
{
#if defined(WITH_BORINGSSL)
  throw std::runtime_error("ML-KEM is not supported with BoringSSL");
#endif

  static const auto label_kem = from_ascii("KEM");
  suite_id = label_kem + i2osp(uint16_t(kem_id_in), 2);
}

std::unique_ptr<KEM::PrivateKey>
MLKEM::generate_key_pair() const
{
  auto sk = random_bytes(MLKEM::sk_size);
  auto [expanded_sk, pk] = expand_secret_key(kem_id, sk);
  return std::make_unique<MLKEM::PrivateKey>(sk, expanded_sk, pk);
}

std::unique_ptr<KEM::PrivateKey>
MLKEM::derive_key_pair(const bytes& ikm) const
{
  const auto empty_context = bytes{};
  auto sk =
    labeled_derive(kem_id, ikm, "DeriveKeyPair", empty_context, MLKEM::sk_size);
  auto [expanded_sk, pk] = expand_secret_key(kem_id, sk);
  return std::make_unique<MLKEM::PrivateKey>(sk, expanded_sk, pk);
}

bytes
MLKEM::serialize(const KEM::PublicKey& pk) const
{
  const auto& rpk = dynamic_cast<const PublicKey&>(pk);
  return rpk.pk;
}

std::unique_ptr<KEM::PublicKey>
MLKEM::deserialize(const bytes& enc) const
{
  return std::make_unique<MLKEM::PublicKey>(enc);
}

bytes
MLKEM::serialize_private(const KEM::PrivateKey& sk) const
{
  const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
  return rsk.sk;
}

std::unique_ptr<KEM::PrivateKey>
MLKEM::deserialize_private(const bytes& skm) const
{
  auto [expanded_sk, pk] = expand_secret_key(kem_id, skm);
  return std::make_unique<MLKEM::PrivateKey>(skm, expanded_sk, pk);
}

std::pair<bytes, bytes>
MLKEM::encap(const KEM::PublicKey& pkR) const
{
  const auto& pk = dynamic_cast<const PublicKey&>(pkR);
  return do_encap(kem_id, pk.pk);
}

bytes
MLKEM::decap(const bytes& enc, const KEM::PrivateKey& skR) const
{
  const auto& sk = dynamic_cast<const PrivateKey&>(skR);
  return do_decap(kem_id, enc, sk.expanded_sk);
}

} // namespace MLS_NAMESPACE::hpke

#endif // !defined(WITH_BORINGSSL)
