#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

SecretTreeTestVector::SenderData::SenderData(mls::CipherSuite suite,
                                             PseudoRandom::Generator&& prg)
  : sender_data_secret(prg.secret("sender_data_secret"))
  , ciphertext(prg.secret("ciphertext"))
{
  auto key_and_nonce =
    KeyScheduleEpoch::sender_data_keys(suite, sender_data_secret, ciphertext);
  key = key_and_nonce.key;
  nonce = key_and_nonce.nonce;
}

std::optional<std::string>
SecretTreeTestVector::SenderData::verify(mls::CipherSuite suite) const
{
  auto key_and_nonce =
    KeyScheduleEpoch::sender_data_keys(suite, sender_data_secret, ciphertext);
  VERIFY_EQUAL("sender data key", key, key_and_nonce.key);
  VERIFY_EQUAL("sender data nonce", nonce, key_and_nonce.nonce);
  return std::nullopt;
}

SecretTreeTestVector::SecretTreeTestVector(
  mls::CipherSuite suite,
  uint32_t n_leaves,
  const std::vector<uint32_t>& generations)
  : PseudoRandom(suite, "secret-tree")
  , cipher_suite(suite)
  , sender_data(suite, prg.sub("sender_data"))
  , encryption_secret(prg.secret("encryption_secret"))
{
  auto src =
    GroupKeySource(cipher_suite, LeafCount{ n_leaves }, encryption_secret);
  leaves.resize(n_leaves);
  auto zero_reuse_guard = ReuseGuard{ 0, 0, 0, 0 };
  for (uint32_t i = 0; i < n_leaves; i++) {
    auto leaf = LeafIndex{ i };

    for (const auto generation : generations) {
      auto hs =
        src.get(ContentType::proposal, leaf, generation, zero_reuse_guard);
      auto app =
        src.get(ContentType::application, leaf, generation, zero_reuse_guard);

      leaves.at(i).push_back(
        RatchetStep{ generation, hs.key, hs.nonce, app.key, app.nonce });

      src.erase(ContentType::proposal, leaf, generation);
      src.erase(ContentType::application, leaf, generation);
    }
  }
}

std::optional<std::string>
SecretTreeTestVector::verify() const
{
  auto sender_data_error = sender_data.verify(cipher_suite);
  if (sender_data_error) {
    return sender_data_error;
  }

  auto n_leaves = static_cast<uint32_t>(leaves.size());
  auto src =
    GroupKeySource(cipher_suite, LeafCount{ n_leaves }, encryption_secret);
  auto zero_reuse_guard = ReuseGuard{ 0, 0, 0, 0 };
  for (uint32_t i = 0; i < n_leaves; i++) {
    auto leaf = LeafIndex{ i };

    for (const auto& step : leaves[i]) {
      auto generation = step.generation;

      auto hs =
        src.get(ContentType::proposal, leaf, generation, zero_reuse_guard);
      VERIFY_EQUAL("hs key", hs.key, step.handshake_key);
      VERIFY_EQUAL("hs nonce", hs.nonce, step.handshake_nonce);

      auto app =
        src.get(ContentType::application, leaf, generation, zero_reuse_guard);
      VERIFY_EQUAL("app key", app.key, step.application_key);
      VERIFY_EQUAL("app nonce", app.nonce, step.application_nonce);
    }
  }

  return std::nullopt;
}

} // namespace mls_vectors
