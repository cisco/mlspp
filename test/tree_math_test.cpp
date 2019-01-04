#include "common.h"
#include "test_vectors.h"
#include "tls_syntax.h"
#include "tree_math.h"

#include <gtest/gtest.h>
#include <vector>

using namespace mls;

// Uses test vectors from the MLS implementations repo:
// https://github.com/mlswg/mls-implementations

template<typename F>
auto
size_scope(F function)
{
  return [=](uint32_t x) -> auto
  {
    return function(x, TreeMathTestVectors::tree_size);
  };
}

template<typename F, typename A>
void
vector_test(F function, A answers)
{
  for (uint32_t i = 0; i < TreeMathTestVectors::tree_size; ++i) {
    ASSERT_EQ(function(i), answers[i]);
  }
}

class TreeMathTest : public ::testing::Test
{
protected:
  const TestVectors& tv;

  TreeMathTest()
    : tv(TestVectors::get())
  {}
};

TEST_F(TreeMathTest, Root)
{
  for (uint32_t n = 1; n <= TreeMathTestVectors::tree_size; ++n) {
    ASSERT_EQ(tree_math::root(n), tv.tree_math.root[n - 1]);
  }
}

TEST_F(TreeMathTest, Left)
{
  vector_test(tree_math::left, tv.tree_math.left);
}

TEST_F(TreeMathTest, Right)
{
  vector_test(size_scope(tree_math::right), tv.tree_math.right);
}

TEST_F(TreeMathTest, Parent)
{
  vector_test(size_scope(tree_math::parent), tv.tree_math.parent);
}

TEST_F(TreeMathTest, Sibling)
{
  vector_test(size_scope(tree_math::sibling), tv.tree_math.sibling);
}
