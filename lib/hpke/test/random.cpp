#include <doctest/doctest.h>
#include <hpke/random.h>

TEST_CASE("Random bytes")
{
  auto size = size_t(128);
  auto test_val = hpke::random_bytes(size);
  CHECK(test_val.size() == size);
}
