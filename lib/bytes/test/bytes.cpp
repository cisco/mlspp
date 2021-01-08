#include <bytes/bytes.h>
#include <bytes/operators.h>
#include <doctest/doctest.h>
#include <sstream>

using namespace bytes_ns;

TEST_CASE("From ASCII")
{
  auto str = std::string("hello");
  auto ascii = bytes{ 0x68, 0x65, 0x6c, 0x6c, 0x6f };
  REQUIRE(from_ascii(str) == ascii);
}

TEST_CASE("To/from hex")
{
  auto hex = "00010203f0f1f2f3";
  auto bin = bytes{ 0x00, 0x01, 0x02, 0x03, 0xf0, 0xf1, 0xf2, 0xf3 };
  REQUIRE(to_hex(bin) == hex);
  REQUIRE(from_hex(hex) == bin);
}

TEST_CASE("Operators")
{
  auto lhs = from_hex("00010203");
  auto rhs = from_hex("04050607");
  auto added = from_hex("0001020304050607");
  auto xored = from_hex("04040404");

  auto base = lhs;
  base += rhs;

  REQUIRE(base == added);
  REQUIRE(lhs + rhs == added);
  REQUIRE((lhs ^ rhs) == xored);

  auto ss = std::stringstream();
  ss << lhs << rhs;
  REQUIRE(ss.str() == to_hex(added));
}
