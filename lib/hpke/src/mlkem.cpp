#include "mlkem.h"

#include <hpke/random.h>
#include "common.h"
#include "openssl_common.h"
#include <namespace.h>
#include <cassert>

#include <oqs/oqs.h>
#include "openssl/evp.h"

namespace MLS_NAMESPACE::hpke {

MLKEM::PublicKey::PublicKey(bytes pk_in)
  : pk(std::move(pk_in))
{}

MLKEM::PrivateKey::PrivateKey(bytes sk_in, bytes expanded_sk_in, bytes pk_in)
  : sk(std::move(sk_in))
  , expanded_sk(std::move(expanded_sk_in))
  , pk(std::move(pk_in))
{}

std::unique_ptr<KEM::PublicKey>
MLKEM::PrivateKey::public_key() const
{
  return std::make_unique<MLKEM::PublicKey>(pk);
}

size_t get_enc_size(KEM::ID kem_id) {
  switch (kem_id) {
    case KEM::ID::MLKEM512: return OQS_KEM_ml_kem_512_length_ciphertext;
    case KEM::ID::MLKEM768: return OQS_KEM_ml_kem_768_length_ciphertext;
    case KEM::ID::MLKEM1024: return OQS_KEM_ml_kem_1024_length_ciphertext;
    default: throw std::runtime_error("unreachable");
  }
}

size_t get_expanded_sk_size(KEM::ID kem_id) {
  switch (kem_id) {
    case KEM::ID::MLKEM512: return OQS_KEM_ml_kem_512_length_secret_key;
    case KEM::ID::MLKEM768: return OQS_KEM_ml_kem_768_length_secret_key;
    case KEM::ID::MLKEM1024: return OQS_KEM_ml_kem_1024_length_secret_key;
    default: throw std::runtime_error("unreachable");
  }
}

size_t get_pk_size(KEM::ID kem_id) {
  switch (kem_id) {
    case KEM::ID::MLKEM512: return OQS_KEM_ml_kem_512_length_public_key;
    case KEM::ID::MLKEM768: return OQS_KEM_ml_kem_768_length_public_key;
    case KEM::ID::MLKEM1024: return OQS_KEM_ml_kem_1024_length_public_key;
    default: throw std::runtime_error("unreachable");
  }
}

OQS_KEM* get_oqs_kem(KEM::ID kem_id) {
  switch (kem_id) {
    case KEM::ID::MLKEM512: return OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    case KEM::ID::MLKEM768: return OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    case KEM::ID::MLKEM1024: return OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    default: throw std::runtime_error("unreachable");
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

MLKEM::MLKEM(KEM::ID kem_id_in)
  : KEM(kem_id_in,
        MLKEM::secret_size,
        get_enc_size(kem_id_in),
        get_pk_size(kem_id_in),
        MLKEM::sk_size)
  , kem_id(kem_id_in)
  , kem(get_oqs_kem(kem_id_in))
{
  static const auto label_kem = from_ascii("KEM");
  suite_id = label_kem + i2osp(uint16_t(kem_id_in), 2);
}

static std::tuple<bytes, bytes>
expand_secret_key(const OQS_KEM* kem, const bytes& sk)
{
  assert(sk.size() == kem->length_keypair_seed);
  auto expanded_sk = bytes(kem->length_secret_key);
  auto pk = bytes(kem->length_public_key);
  const auto rv = kem->keypair_derand(pk.data(), expanded_sk.data(), sk.data());
  if (rv != OQS_SUCCESS) {
    throw std::runtime_error(std::to_string(rv)); // XXX
  }

  return { expanded_sk, pk };
}

std::unique_ptr<KEM::PrivateKey>
MLKEM::generate_key_pair() const
{
  auto sk = random_bytes(kem->length_keypair_seed);
  auto [expanded_sk, pk] = expand_secret_key(kem.get(), sk);
  return std::make_unique<MLKEM::PrivateKey>(sk, expanded_sk, pk);
}

std::unique_ptr<KEM::PrivateKey>
MLKEM::derive_key_pair(const bytes& ikm) const
{
  // Derive seed with SHAKE
  // TODO(RLB) Actually use LabeledDerive
  auto ctx = make_typed_unique(EVP_MD_CTX_new());
  if (ctx == nullptr) {
    throw openssl_error();
  }

  if (EVP_DigestInit_ex(ctx.get(), EVP_shake256(), NULL) != 1) {
    throw openssl_error();
  }

  if (EVP_DigestUpdate(ctx.get(), ikm.data(), ikm.size()) != 1) {
    throw openssl_error();
  }

  auto sk = bytes(kem->length_keypair_seed);
  if (EVP_DigestFinalXOF(ctx.get(), sk.data(), sk.size()) != 1) {
    throw openssl_error();
  }

  // Expand seed into full key pair
  auto [expanded_sk, pk] = expand_secret_key(kem.get(), sk);
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
  auto [expanded_sk, pk] = expand_secret_key(kem.get(), skm);
  return std::make_unique<MLKEM::PrivateKey>(skm, expanded_sk, pk);
}

std::pair<bytes, bytes>
MLKEM::encap(const KEM::PublicKey& pkR) const
{
  const auto pk = dynamic_cast<const PublicKey&>(pkR);

  auto ct = bytes(kem->length_ciphertext);
  auto ss = bytes(kem->length_shared_secret);
  const auto rv = kem->encaps(ct.data(), ss.data(), pk.pk.data());
  if (rv != OQS_SUCCESS) {
    throw std::runtime_error(std::to_string(rv)); // XXX
  }

  return { ss, ct };
}

bytes
MLKEM::decap(const bytes& enc, const KEM::PrivateKey& skR) const
{
  const auto sk = dynamic_cast<const PrivateKey&>(skR);

  auto ss = bytes(kem->length_shared_secret);
  const auto rv = kem->decaps(ss.data(), enc.data(), sk.expanded_sk.data());
  if (rv != OQS_SUCCESS) {
    throw std::runtime_error(std::to_string(rv)); // XXX
  }

  return ss;
}

} // namespace MLS_NAMESPACE::hpke
