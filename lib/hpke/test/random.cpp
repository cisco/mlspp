#include <catch2/catch_all.hpp>
#include <hpke/random.h>

#include "common.h"

TEST_CASE("Random bytes")
{
  ensure_fips_if_required();

  auto size = size_t(128);
  auto test_val = MLS_NAMESPACE::hpke::random_bytes(size);
  CHECK(test_val.size() == size);
}
