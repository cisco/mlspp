#include <bytes/bytes.h>
#include <doctest/doctest.h>
#include <memory>
#include <sstream>

using namespace bytes_ns;
using namespace std::literals::string_literals;

// To check that memory is safely zeroized on destroy, we have to deliberately
// do a use-after-free.  This will be caught by the sanitizers, so we only do it
// when sanitizers are not enabled.
#ifndef SANITIZERS
TEST_CASE("Zeroization")
{
  const auto canary = uint8_t(0xff);
  auto vec = std::make_unique<bytes>(32, canary);
  const auto size = vec->size();
  const auto* ptr = vec->data();
  vec.reset();

  for (size_t i = 0; i < size; i++) {
    // We test for inequality instead of zero because the vector might already
    // be partially overwritten at this point.
    //
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    REQUIRE(*(ptr + i) != canary);
  }
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
