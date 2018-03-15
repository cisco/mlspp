#include "common.h"
#include "tls_syntax.h"
#include <catch.hpp>

// Known-answer tests
uint8_t val_uint8{ 0x11 };
std::vector<uint8_t> enc_uint8 = mls::from_hex("11");

uint16_t val_uint16{ 0x2222 };
std::vector<uint8_t> enc_uint16 = mls::from_hex("2222");

uint32_t val_uint32{ 0x44444444 };
std::vector<uint8_t> enc_uint32 = mls::from_hex("44444444");

uint64_t val_uint64{ 0x8888888888888888 };
std::vector<uint8_t> enc_uint64 = mls::from_hex("8888888888888888");

std::array<uint16_t, 4> val_array{ 1, 2, 3, 4 };
std::vector<uint8_t> enc_array = mls::from_hex("0001000200030004");

tls::vector<uint32_t, 3> val_vector{ 5, 6 };
std::vector<uint8_t> enc_vector = mls::from_hex("0000080000000500000006");

struct ExampleStruct
{
  uint16_t a;
  tls::vector<uint8_t, 2> b;
  std::array<uint32_t, 4> c;
};

bool
operator==(const ExampleStruct& lhs, const ExampleStruct& rhs)
{
  return (lhs.a == rhs.a) && (lhs.b == rhs.b) && (lhs.c == rhs.c);
}

tls::ostream&
operator<<(tls::ostream& out, const ExampleStruct& data)
{
  return out << data.a << data.b << data.c;
}

tls::istream&
operator>>(tls::istream& in, ExampleStruct& data)
{
  return in >> data.a >> data.b >> data.c;
}

ExampleStruct val_struct{ 0x1111,
                          { 0x22, 0x22 },
                          { 0x33333333, 0x44444444, 0x55555555, 0x66666666 } };
std::vector<uint8_t> enc_struct =
  mls::from_hex("11110002222233333333444444445555555566666666");

template<typename T>
void
ostream_test(T val, const std::vector<uint8_t>& enc)
{
  tls::ostream w;
  w << val;
  REQUIRE(w.bytes() == enc);
}

TEST_CASE("TLS ostream correctly marshals", "[tls_syntax]")
{
  SECTION("raw")
  {
    std::vector<uint8_t> answer{ 1, 2, 3, 4 };
    tls::ostream w;
    w.write_raw(answer);
    REQUIRE(w.bytes() == answer);
  }

  SECTION("uint8_t") { ostream_test(val_uint8, enc_uint8); }

  SECTION("uint16_t") { ostream_test(val_uint16, enc_uint16); }

  SECTION("uint32_t") { ostream_test(val_uint32, enc_uint32); }

  SECTION("uint64_t") { ostream_test(val_uint64, enc_uint64); }

  SECTION("array") { ostream_test(val_array, enc_array); }

  SECTION("vector") { ostream_test(val_vector, enc_vector); }

  SECTION("struct") { ostream_test(val_struct, enc_struct); }
}

template<typename T>
void
istream_test(T val, const std::vector<uint8_t>& enc)
{
  T data;
  tls::istream r(enc);
  r >> data;
  REQUIRE(data == val);
}

TEST_CASE("TLS istream correctly unmarshals", "[tls_syntax]")
{
  SECTION("uint8_t") { istream_test(val_uint8, enc_uint8); }

  SECTION("uint16_t") { istream_test(val_uint16, enc_uint16); }

  SECTION("uint32_t") { istream_test(val_uint32, enc_uint32); }

  SECTION("uint64_t") { istream_test(val_uint64, enc_uint64); }

  SECTION("array") { istream_test(val_array, enc_array); }

  SECTION("vector") { istream_test(val_vector, enc_vector); }

  SECTION("struct") { istream_test(val_struct, enc_struct); }
}

// TODO(rlb@ipv.sx) Test failure cases
