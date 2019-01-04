#include "common.h"
#include "tls_syntax.h"
#include <string>

struct TreeMathTestVectors
{
  static const std::string file_name;
  static const size_t tree_size = 255;

  tls::vector<uint32_t, 4> root;
  tls::vector<uint32_t, 4> left;
  tls::vector<uint32_t, 4> right;
  tls::vector<uint32_t, 4> parent;
  tls::vector<uint32_t, 4> sibling;
};

struct TestVectors
{
  TreeMathTestVectors tree;

  static const TestVectors& get();
  void dump();

private:
  static bool _initialized;
  static TestVectors _vectors;
};
