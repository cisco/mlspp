#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

// XXX(RLB): This is a hack to get the tests working in the right format.  In
// reality, the tree math functions should be updated to be fallible.
std::optional<mls::NodeIndex>
TreeMathTestVector::null_if_invalid(NodeIndex input, NodeIndex answer) const
{
  // For some invalid cases (e.g., leaf.left()), we currently return the node
  // itself instead of null
  if (input == answer) {
    return std::nullopt;
  }

  // NodeIndex::parent is irrespective of tree size, so we might step out of the
  // tree under consideration.
  if (answer.val >= n_nodes.val) {
    return std::nullopt;
  }

  return answer;
}

TreeMathTestVector::TreeMathTestVector(uint32_t n_leaves_in)
  : n_leaves(n_leaves_in)
  , n_nodes(n_leaves)
  , root(NodeIndex::root(n_leaves))
  , left(n_nodes.val)
  , right(n_nodes.val)
  , parent(n_nodes.val)
  , sibling(n_nodes.val)
{
  for (NodeIndex x{ 0 }; x.val < n_nodes.val; x.val++) {
    left[x.val] = null_if_invalid(x, x.left());
    right[x.val] = null_if_invalid(x, x.right());
    parent[x.val] = null_if_invalid(x, x.parent());
    sibling[x.val] = null_if_invalid(x, x.sibling());
  }
}

std::optional<std::string>
TreeMathTestVector::verify() const
{
  VERIFY_EQUAL("n_nodes", n_nodes, NodeCount(n_leaves));
  VERIFY_EQUAL("root", root, NodeIndex::root(n_leaves));

  for (NodeIndex x{ 0 }; x.val < n_nodes.val; x.val++) {
    VERIFY_EQUAL("left", null_if_invalid(x, x.left()), left[x.val]);
    VERIFY_EQUAL("right", null_if_invalid(x, x.right()), right[x.val]);
    VERIFY_EQUAL("parent", null_if_invalid(x, x.parent()), parent[x.val]);
    VERIFY_EQUAL("sibling", null_if_invalid(x, x.sibling()), sibling[x.val]);
  }

  return std::nullopt;
}

} // namespace mls_vectors
