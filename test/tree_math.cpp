#include <catch2/catch_all.hpp>
#include <mls_vectors/mls_vectors.h>

#include <vector>

using namespace mls_vectors;

TEST_CASE("Tree Math Test Vectors")
{
  const auto tv = TreeMathTestVector{ 256 };
  REQUIRE(tv.verify() == std::nullopt);
}
