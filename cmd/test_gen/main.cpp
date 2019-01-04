#include "test_vectors.h"
#include "tree_math.h"
#include <iostream>

void generate_tree_math(TestVectors& vectors) {
  for (int n = 1; n <= TreeMathTestVectors::tree_size; ++n) {
    auto val = mls::tree_math::root(n);
    vectors.tree.root.push_back(val);
  }

  auto n = TreeMathTestVectors::tree_size;
  for (int x = 0; x < TreeMathTestVectors::tree_size; ++x) {
    auto left = mls::tree_math::left(x);
    vectors.tree.left.push_back(left);

    auto right = mls::tree_math::right(x, n);
    vectors.tree.right.push_back(right);

    auto parent = mls::tree_math::parent(x, n);
    vectors.tree.parent.push_back(parent);

    auto sibling = mls::tree_math::sibling(x, n);
    vectors.tree.sibling.push_back(sibling);
  }
}

int main() {
  TestVectors vectors;

  // Generate and write test vectors
  generate_tree_math(vectors);
  vectors.dump();

  // Verify that the test vectors load
  try {
    TestVectors::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }
  return 0;
}
