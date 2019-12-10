#include "common.h"
#include "test_vectors.h"
#include "tls_syntax.h"
#include "tree_math.h"

#include <gtest/gtest.h>
#include <vector>

using namespace mls;

// Uses test vectors from the MLS implementations repo:
// https://github.com/mlswg/mls-implementations

class TreeMathTest : public ::testing::Test
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
      ASSERT_EQ(function(NodeIndex{ i }), answers[i]);
    }
  }
};

TEST_F(TreeMathTest, Root)
{
  for (uint32_t n = 1; n <= tv.n_leaves.val; ++n) {
    const auto w = NodeCount{ LeafCount{ n } };
    ASSERT_EQ(tree_math::root(w), tv.root[n - 1]);
  }
}

TEST_F(TreeMathTest, Left)
{
  vector_test(tree_math::left, tv.left);
}

TEST_F(TreeMathTest, Right)
{
  vector_test(size_scope(tree_math::right), tv.right);
}

TEST_F(TreeMathTest, Parent)
{
  vector_test(size_scope(tree_math::parent), tv.parent);
}

TEST_F(TreeMathTest, Sibling)
{
  vector_test(size_scope(tree_math::sibling), tv.sibling);
}
