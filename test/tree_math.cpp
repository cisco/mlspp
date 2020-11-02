#include "test_vectors.h"
#include <doctest/doctest.h>

using namespace mls;

// Uses test vectors from the MLS implementations repo:
// https://github.com/mlswg/mls-implementations

class TreeMathTest
{
protected:
  const TreeMathTestVectors& tv;
  NodeCount width;

  TreeMathTest()
    : tv(TestLoader<TreeMathTestVectors>::get())
  {
    width = NodeCount{ tv.n_leaves };
  }

  template<typename F>
  auto size_scope(F function)
  {
    return [=](NodeIndex x) -> auto { return function(x, width); };
  }

  template<typename F, typename A>
  void vector_test(F function, A answers)
  {
    for (uint32_t i = 0; i < width.val; ++i) {
      REQUIRE(function(NodeIndex{ i }) == answers[i]);
    }
  }

  template<typename F, typename A>
  void matrix_test(F function, A answers)
  {
    for (uint32_t i = 0; i < width.val; ++i) {
      REQUIRE(function(NodeIndex{ i }) == answers[i].nodes);
    }
  }
};

TEST_CASE_FIXTURE(TreeMathTest, "Tree Math")
{
  SUBCASE("Root")
  {
    for (uint32_t n = 1; n <= tv.n_leaves.val; ++n) {
      const auto w = NodeCount{ LeafCount{ n } };
      REQUIRE(tree_math::root(w) == tv.root[n - 1]);
    }
  }

  SUBCASE("Left") { vector_test(tree_math::left, tv.left); }

  SUBCASE("Right") { vector_test(size_scope(tree_math::right), tv.right); }

  SUBCASE("Parent") { vector_test(size_scope(tree_math::parent), tv.parent); }

  SUBCASE("Sibling")
  {
    vector_test(size_scope(tree_math::sibling), tv.sibling);
  }

  SUBCASE("Dirpath")
  {
    matrix_test(size_scope(tree_math::dirpath), tv.dirpath);
  }

  SUBCASE("Copath") { matrix_test(size_scope(tree_math::copath), tv.copath); }

  SUBCASE("Ancestor")
  {
    for (uint32_t l = 0; l < tv.n_leaves.val - 1; ++l) {
      auto ancestors = std::vector<NodeIndex>();
      for (uint32_t r = l + 1; r < tv.n_leaves.val; ++r) {
        ancestors.push_back(tree_math::ancestor(LeafIndex(l), LeafIndex(r)));
      }
      REQUIRE(ancestors == tv.ancestor[l].nodes);
    }
  }
}
