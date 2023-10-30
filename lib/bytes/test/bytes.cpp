#include <bytes/bytes.h>
#include <doctest/doctest.h>
#include <memory>
#include <sstream>

using namespace MLS_NAMESPACE::bytes_ns;
using namespace std::literals::string_literals;

// To check that memory is safely zeroized on destroy, we have to deliberately
// do a use-after-free.  This will be caught by the sanitizers, so we only do it
// when sanitizers are not enabled.
#ifndef SANITIZERS
TEST_CASE("Zeroization")
{
  const auto size = size_t(1024);
  const auto canary = uint8_t(0xff);

  auto vec = std::make_unique<bytes>(size, canary);
  const auto* begin = vec->data();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  const auto* end = begin + size;
  vec.reset();

  // In principle, the memory previously owned by the vector should be all zero
  // at this point.  However, since this is now unallocated memory, the
  // allocator can do with it what it wants, and may have written something to
  // it when deallocating.  For example, on macOS, the allocator appears to
  // write a single pointer at the beginning.  Assuming other platforms are not
  // too different, we verify that no more than a few pointer's worth of bytes
  // are non-zero.
  const auto non_zero_threshold = 4 * sizeof(void*);
  REQUIRE(std::count(begin, end, 0) >= size - non_zero_threshold);
}
#endif

TEST_CASE("To/from hex/ASCII")
{
  const auto hex = "00010203f0f1f2f3"s;
  const auto bin = bytes{ 0x00, 0x01, 0x02, 0x03, 0xf0, 0xf1, 0xf2, 0xf3 };
  REQUIRE(to_hex(bin) == hex);
  REQUIRE(from_hex(hex) == bin);

  const auto str = "hello"s;
  const auto ascii = bytes{ 0x68, 0x65, 0x6c, 0x6c, 0x6f };
  REQUIRE(from_ascii(str) == ascii);
}

TEST_CASE("Operators")
{
  const auto lhs = from_hex("00010203");
  const auto rhs = from_hex("04050607");
  const auto added = from_hex("0001020304050607");
  const auto xored = from_hex("04040404");

  auto base = lhs;
  base += rhs;

  REQUIRE(base == added);
  REQUIRE(lhs + rhs == added);
  REQUIRE((lhs ^ rhs) == xored);

  auto ss = std::stringstream();
  ss << lhs << rhs;
  REQUIRE(ss.str() == to_hex(added));
}
