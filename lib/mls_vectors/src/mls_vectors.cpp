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
/// HashRatchetTestVector
///

HashRatchetTestVector HashRatchetTestVector::create(
  CipherSuite suite,
  uint32_t n_leaves,
  uint32_t n_generations)
{
  HashRatchetTestVector tv;
  tv.suite = suite;
  tv.base_secret.data = random_bytes(suite.get().digest.hash_size());

  tv.chains.resize(n_leaves);
  for (uint32_t i = 0; i < n_leaves; i++) {
    HashRatchet ratchet{ suite, NodeIndex{ LeafIndex{ i } }, tv.base_secret.data };

    tv.chains[i].steps.resize(n_generations);
    for (uint32_t j = 0; j < n_generations; ++j) {
      auto key_nonce = ratchet.get(j);
      tv.chains[i].steps[j].key = { std::move(key_nonce.key) };
      tv.chains[i].steps[j].nonce = { std::move(key_nonce.nonce) };
    }
  }

  return tv;
}

std::optional<std::string>
HashRatchetTestVector::verify(const HashRatchetTestVector& tv)
{
  for (uint32_t i = 0; i < tv.chains.size(); i++) {
    HashRatchet ratchet{ tv.suite, NodeIndex{ LeafIndex{ i } }, tv.base_secret.data };
    for (uint32_t j = 0; j < tv.chains[i].steps.size(); ++j) {
      const auto key_nonce = ratchet.get(j);
      const auto& key = tv.chains[i].steps[j].key.data;
      const auto& nonce = tv.chains[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  return std::nullopt;
}

///
/// SecretTreeTestVector
///

SecretTreeTestVector SecretTreeTestVector::create(CipherSuite /* suite */,
                                                  uint32_t /* n_leaves */)
{
  return {};
}

std::optional<std::string>
SecretTreeTestVector::verify(const SecretTreeTestVector& /* tv */)
{
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
