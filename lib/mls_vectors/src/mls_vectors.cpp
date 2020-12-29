#include <mls/key_schedule.h>
#include <mls/tree_math.h>
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

///
/// Assertions for verifying test vectors
///

std::ostream&
operator<<(std::ostream& str, const NodeIndex& obj)
{
  return str << obj.val;
}

std::ostream&
operator<<(std::ostream& str, const bytes& obj)
{
  return str << to_hex(obj);
}

template<typename T>
static std::optional<std::string>
verify_equal(std::string label, const T& actual, const T& expected)
{
  if (actual == expected) {
    return std::nullopt;
  }

  auto ss = std::stringstream();
  ss << "Error: " << label << "  " << actual << " != " << expected;
  return ss.str();
}

#define VERIFY_EQUAL(label, actual, expected)                                  \
  if (auto eq = verify_equal(label, actual, expected); !eq) {                  \
    return eq;                                                                 \
  }

///
/// TreeMathTestVector
///
TreeMathTestVector::TreeMathTestVector(uint32_t n_leaves_in)
  : n_leaves(n_leaves_in)
  , root(n_leaves_in - 1)
  , left(NodeCount(n_leaves).val)
  , right(NodeCount(n_leaves).val)
  , parent(NodeCount(n_leaves).val)
  , sibling(NodeCount(n_leaves).val)
{
  // Root is special
  for (LeafCount n{ 1 }; n.val <= n_leaves_in; n.val++) {
    root[n.val - 1] = tree_math::root(n);
  }

  // Left, right, parent, sibling are relative
  auto w = NodeCount(n_leaves);
  for (NodeIndex x{ 0 }; x.val < w.val; x.val++) {
    left[x.val] = tree_math::left(x);
    right[x.val] = tree_math::right(x, n_leaves);
    parent[x.val] = tree_math::parent(x, n_leaves);
    sibling[x.val] = tree_math::sibling(x, n_leaves);
  }
}

std::optional<std::string>
TreeMathTestVector::verify() const
{
  auto ss = std::stringstream();
  for (LeafCount n{ 1 }; n.val <= n_leaves.val; n.val++) {
    VERIFY_EQUAL("root", root[n.val - 1], tree_math::root(n));
  }

  auto w = NodeCount(n_leaves);
  for (NodeIndex x{ 0 }; x.val < w.val; x.val++) {
    VERIFY_EQUAL("left", left[x.val], tree_math::left(x));
    VERIFY_EQUAL("right", right[x.val], tree_math::right(x, n_leaves));
    VERIFY_EQUAL("parent", parent[x.val], tree_math::parent(x, n_leaves));
    VERIFY_EQUAL("sibling", sibling[x.val], tree_math::sibling(x, n_leaves));
  }

  return std::nullopt;
}

///
/// EncryptionKeyTestVector
///

EncryptionKeyTestVector::EncryptionKeyTestVector(CipherSuite suite_in,
                                                 uint32_t n_leaves,
                                                 uint32_t n_generations)
  : suite(suite_in)
  , encryption_secret{ bytes(suite.secret_size(), 0xA0) }
{
  auto leaf_count = LeafCount{ n_leaves };
  auto src = GroupKeySource(suite, leaf_count, encryption_secret.data);

  auto handshake = GroupKeySource::RatchetType::handshake;
  auto application = GroupKeySource::RatchetType::application;
  handshake_keys.resize(n_leaves);
  application_keys.resize(n_leaves);
  for (uint32_t i = 0; i < n_leaves; i++) {
    handshake_keys[i].steps.resize(n_generations);
    application_keys[i].steps.resize(n_generations);

    for (uint32_t j = 0; j < n_generations; ++j) {
      auto hs_key_nonce = src.get(handshake, LeafIndex{ j }, j);
      handshake_keys[i].steps[j].key = { std::move(hs_key_nonce.key) };
      handshake_keys[i].steps[j].nonce = { std::move(hs_key_nonce.nonce) };

      auto app_key_nonce = src.get(application, LeafIndex{ j }, j);
      application_keys[i].steps[j].key = { std::move(app_key_nonce.key) };
      application_keys[i].steps[j].nonce = { std::move(app_key_nonce.nonce) };
    }
  }
}

std::optional<std::string>
EncryptionKeyTestVector::verify() const
{
  if (handshake_keys.size() != application_keys.size()) {
    return "Malformed test vector";
  }

  auto handshake = GroupKeySource::RatchetType::handshake;
  auto application = GroupKeySource::RatchetType::application;
  auto leaf_count = LeafCount{ static_cast<uint32_t>(handshake_keys.size()) };
  auto src = GroupKeySource(suite, leaf_count, encryption_secret.data);

  for (uint32_t i = 0; i < application_keys.size(); i++) {
    for (uint32_t j = 0; j < handshake_keys[i].steps.size(); j++) {
      const auto key_nonce = src.get(handshake, LeafIndex(i), j);
      const auto& key = handshake_keys[i].steps[j].key.data;
      const auto& nonce = handshake_keys[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  for (uint32_t i = 0; i < application_keys.size(); i++) {
    for (uint32_t j = 0; j < application_keys[i].steps.size(); j++) {
      const auto key_nonce = src.get(application, LeafIndex(i), j);
      const auto& key = application_keys[i].steps[j].key.data;
      const auto& nonce = application_keys[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  return std::nullopt;
}

///
/// KeyScheduleTestVector
///

KeyScheduleTestVector::KeyScheduleTestVector(CipherSuite /* suite */,
                                             uint32_t /* n_epochs */)
{}

std::optional<std::string>
KeyScheduleTestVector::verify() const
{
#if 0
  auto epoch = KeyScheduleEpoch(/* TODO */);
  auto transcript_hash =  TranscriptHash(/* TODO */);

  for (const auto& tve : tv.epochs) {
    VERIFY_EQUAL("membership tag",
                 epoch.membership_tag(tve.commit),
                 tve.commit.membership_tag);

    epoch = epoch.next(/* TODO */);
    // TODO verify outputs

    transcript_hash.update(tve.commit);
    // TODO verify transcript hashes

    VERIFY_EQUAL("confirmation_tag",
                 epoch.confirmation_tag(transcript_hash.confirmed),
                 tve.commit.confirmation_tag);
  }
#endif // 0

  return std::nullopt;
}

///
/// TreeHashingTestVector
///

TreeHashingTestVector::TreeHashingTestVector(CipherSuite /* suite */,
                                             uint32_t /* n_leaves */)
{}

std::optional<std::string>
TreeHashingTestVector::verify() const
{
  return std::nullopt;
}

///
/// MessagesTestVector
///

MessagesTestVector::MessagesTestVector() {}

std::optional<std::string>
MessagesTestVector::verify() const
{
  return std::nullopt;
}

} // namespace mls_vectors
