#include <mls/key_schedule.h>
#include <mls/tree_math.h>
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

///
/// Assertions for verifying test vectors
///

std::ostream& operator<<(std::ostream& str, const NodeIndex& obj) {
  return str << obj.val;
}

std::ostream& operator<<(std::ostream& str, const bytes& obj) {
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
TreeMathTestVector
TreeMathTestVector::create(uint32_t n_leaves)
{
  TreeMathTestVector tv;
  tv.n_leaves = LeafCount(n_leaves);

  // Root is special
  tv.root.resize(n_leaves - 1);
  for (LeafCount n{ 1 }; n.val <= n_leaves; n.val++) {
    tv.root[n.val - 1] = tree_math::root(n);
  }

  // Left, right, parent, sibling are relative
  auto w = NodeCount(tv.n_leaves);
  tv.left.resize(w.val);
  tv.right.resize(w.val);
  tv.parent.resize(w.val);
  tv.sibling.resize(w.val);
  for (NodeIndex x{ 0 }; x.val < w.val; x.val++) {
    tv.left[x.val] = tree_math::left(x);
    tv.right[x.val] = tree_math::right(x, tv.n_leaves);
    tv.parent[x.val] = tree_math::parent(x, tv.n_leaves);
    tv.sibling[x.val] = tree_math::sibling(x, tv.n_leaves);
  }

  return tv;
}

std::optional<std::string>
TreeMathTestVector::verify(const TreeMathTestVector& tv)
{
  auto ss = std::stringstream();
  for (LeafCount n{ 1 }; n.val <= tv.n_leaves.val; n.val++) {
    VERIFY_EQUAL("root", tv.root[n.val - 1], tree_math::root(n));
  }

  auto w = NodeCount(tv.n_leaves);
  for (NodeIndex x{ 0 }; x.val < w.val; x.val++) {
    VERIFY_EQUAL("left", tv.left[x.val], tree_math::left(x));
    VERIFY_EQUAL("right", tv.right[x.val], tree_math::right(x, tv.n_leaves));
    VERIFY_EQUAL("parent", tv.parent[x.val], tree_math::parent(x, tv.n_leaves));
    VERIFY_EQUAL("sibling", tv.sibling[x.val], tree_math::sibling(x, tv.n_leaves));
  }

  return std::nullopt;
}

///
/// EncryptionKeyTestVector
///

EncryptionKeyTestVector EncryptionKeyTestVector::create(CipherSuite suite,
  uint32_t n_leaves,
  uint32_t n_generations)
{
  EncryptionKeyTestVector tv;
  tv.suite = suite;
  tv.encryption_secret.data = random_bytes(suite.get().digest.hash_size());

  auto leaf_count = LeafCount{ n_leaves };
  auto src = GroupKeySource(tv.suite, leaf_count, tv.encryption_secret.data);

  auto handshake = GroupKeySource::RatchetType::handshake;
  auto application = GroupKeySource::RatchetType::application;
  tv.handshake_keys.resize(n_leaves);
  tv.application_keys.resize(n_leaves);
  for (uint32_t i = 0; i < n_leaves; i++) {
    tv.handshake_keys[i].steps.resize(n_generations);
    tv.application_keys[i].steps.resize(n_generations);

    for (uint32_t j = 0; j < n_generations; ++j) {
      auto hs_key_nonce = src.get(handshake, LeafIndex{j}, j);
      tv.handshake_keys[i].steps[j].key = { std::move(hs_key_nonce.key) };
      tv.handshake_keys[i].steps[j].nonce = { std::move(hs_key_nonce.nonce) };

      auto app_key_nonce = src.get(application, LeafIndex{j}, j);
      tv.application_keys[i].steps[j].key = { std::move(app_key_nonce.key) };
      tv.application_keys[i].steps[j].nonce = { std::move(app_key_nonce.nonce) };
    }
  }

  return tv;
}

std::optional<std::string>
EncryptionKeyTestVector::verify(const EncryptionKeyTestVector& tv)
{
  if (tv.handshake_keys.size() != tv.application_keys.size()) {
    return "Malformed test vector";
  }

  auto handshake = GroupKeySource::RatchetType::handshake;
  auto application = GroupKeySource::RatchetType::application;
  auto leaf_count = LeafCount{ static_cast<uint32_t>(tv.handshake_keys.size()) };
  auto src = GroupKeySource(tv.suite, leaf_count, tv.encryption_secret.data);

  for (uint32_t i = 0; i < tv.application_keys.size(); i++) {
    for (uint32_t j = 0; j < tv.handshake_keys[i].steps.size(); j++) {
      const auto key_nonce = src.get(handshake, LeafIndex(i), j);
      const auto& key = tv.handshake_keys[i].steps[j].key.data;
      const auto& nonce = tv.handshake_keys[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  for (uint32_t i = 0; i < tv.application_keys.size(); i++) {
    for (uint32_t j = 0; j < tv.application_keys[i].steps.size(); j++) {
      const auto key_nonce = src.get(application, LeafIndex(i), j);
      const auto& key = tv.application_keys[i].steps[j].key.data;
      const auto& nonce = tv.application_keys[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  return std::nullopt;
}

///
/// KeyScheduleTestVector
///

KeyScheduleTestVector KeyScheduleTestVector::create(CipherSuite /* suite */,
                                                    uint32_t /* n_epochs */)
{
  return {};
}

std::optional<std::string>
KeyScheduleTestVector::verify(const KeyScheduleTestVector& /* tv */)
{
  return std::nullopt;
}

///
/// TreeHashingTestVector
///

TreeHashingTestVector TreeHashingTestVector::create(CipherSuite /* suite */,
                                                    uint32_t /* n_leaves */)
{
  return {};
}

std::optional<std::string>
TreeHashingTestVector::verify(const TreeHashingTestVector& /* tv */)
{
  return std::nullopt;
}

///
/// MessagesTestVector
///

MessagesTestVector
MessagesTestVector::create()
{
  return {};
}

std::optional<std::string>
MessagesTestVector::verify(const MessagesTestVector& /* tv */)
{
  return std::nullopt;
}

} // namespace mls_vectors
