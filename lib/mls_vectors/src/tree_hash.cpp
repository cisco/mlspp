#include <mls_vectors/mls_vectors.h>

#include "common.h"
#include "tree.h"

namespace mls_vectors {

using namespace mls;

TreeHashTestVector::TreeHashTestVector(mls::CipherSuite suite,
                                       TreeStructure tree_structure)
  : PseudoRandom(suite, "tree-hashes")
  , cipher_suite(suite)
{
  auto tc = TreeTestCase::with_structure(suite, prg, tree_structure);
  tree = tc.pub;
  group_id = tc.group_id;

  auto width = NodeCount(tree.size);
  for (NodeIndex i{ 0 }; i < width; i.val++) {
    tree_hashes.push_back(tree.get_hash(i));
    resolutions.push_back(tree.resolve(i));
  }
}

std::optional<std::string>
TreeHashTestVector::verify()
{
  // Finish setting up the tree
  tree.suite = cipher_suite;
  tree.set_hash_all();

  // Verify that each leaf node is properly signed
  for (LeafIndex i{ 0 }; i < tree.size; i.val++) {
    auto maybe_leaf = tree.leaf_node(i);
    if (!maybe_leaf) {
      continue;
    }

    auto leaf = opt::get(maybe_leaf);
    auto leaf_valid = leaf.verify(cipher_suite, { { group_id, i } });
    VERIFY("leaf sig valid", leaf_valid);
  }

  // Verify the tree hashes
  auto width = NodeCount{ tree.size };
  for (NodeIndex i{ 0 }; i < width; i.val++) {
    VERIFY_EQUAL("tree hash", tree.get_hash(i), tree_hashes.at(i.val));
    VERIFY_EQUAL("resolution", tree.resolve(i), resolutions.at(i.val));
  }

  // Verify parent hashes
  VERIFY("parent hash valid", tree.parent_hash_valid());

  // Verify the resolutions
  for (NodeIndex i{ 0 }; i < width; i.val++) {
    VERIFY_EQUAL("resolution", tree.resolve(i), resolutions[i.val]);
  }

  return std::nullopt;
}

} // namespace mls_vectors
