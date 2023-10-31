#include <bytes/bytes.h>
#include <doctest/doctest.h>
#include <iostream>
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
  const auto canary = uint8_t(0xa0);

  auto vec = std::make_unique<bytes>(size, canary);
  const auto* begin = vec->data();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  const auto* end = begin + size;
  vec.reset();

  const auto snapshot = std::vector<uint8_t>(begin, end);
  std::cout << "snapshot = " << to_hex(snapshot) << std::endl;

  // In principle, the memory previously owned by the vector should be all zero
  // at this point.  However, since this is now unallocated memory, the
  // allocator can do with it what it wants, and may have written something to
  // it when deallocating.  This means we need to vary the test per OS.
#ifndef _MSC_VER
  // macOS and Linux mostly leave the buffer alone, writing a couple of pointers
  // to the beginning.  So we look for the buffer to be basically all zero.
  const auto threshold = size - 4 * sizeof(void*);
  REQUIRE(std::count(snapshot.begin(), snapshot.end(), 0) >= threshold);
#else
  // Windows appeares to overwrite the buffer with 0xcd, so we test for that
  // behavior.  Note that this is testing for zeroization within a process,
  // different from the page zeroization that happens when a page of memory is
  // reallocated to another process.
  //
  // https://stackoverflow.com/questions/18385556/does-windows-clear-memory-pages
  const auto ms_sentinel = uint8_t(0xcd);
  REQUIRE(std::count(snapshot.begin(), snapshot.end(), ms_sentinel) == size);
#endif
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
