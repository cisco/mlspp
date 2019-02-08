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
  uint32_t width;

  TreeMathTest()
    : tv(TestLoader<TreeMathTestVectors>::get())
  {
    width = tree_math::node_width(tv.n_leaves);
  }

  template<typename F>
  auto size_scope(F function)
  {
    return [=](uint32_t x) -> auto { return function(x, tv.n_leaves); };
  }

  template<typename F, typename A>
  void vector_test(F function, A answers)
  {
    for (uint32_t i = 0; i < width; ++i) {
      ASSERT_EQ(function(i), answers[i]);
    }
  }
};

TEST_F(TreeMathTest, Root)
{
  for (uint32_t n = 1; n <= tv.n_leaves; ++n) {
    ASSERT_EQ(tree_math::root(n), tv.root[n - 1]);
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

TEST(ResolutionTest, Interop)
{
  auto tv = TestLoader<ResolutionTestVectors>::get();

  auto width = tree_math::node_width(tv.n_leaves);
  auto n_cases = (1 << width);

  for (uint32_t t = 0; t < n_cases; ++t) {
    auto nodes = ResolutionTestVectors::make_tree(t, width);
    for (uint32_t i = 0; i < width; ++i) {
      auto res = tree_math::resolve(nodes, i);
      auto compact = ResolutionTestVectors::compact(res);
      ASSERT_EQ(compact, tv.cases[t][i]);
    }
  }
}
