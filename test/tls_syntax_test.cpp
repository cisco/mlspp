#include "common.h"
#include "tls_syntax.h"
#include <gtest/gtest.h>

using namespace mls;

// A struct to test struct encoding, and its operators
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

// Known-answer tests
class TLSSyntaxTest : public ::testing::Test
{
protected:
  const uint8_t val_uint8{ 0x11 };
  const bytes enc_uint8 = from_hex("11");

  const uint16_t val_uint16{ 0x2222 };
  const bytes enc_uint16 = from_hex("2222");

  const uint32_t val_uint32{ 0x44444444 };
  const bytes enc_uint32 = from_hex("44444444");

  const uint64_t val_uint64{ 0x8888888888888888 };
  const bytes enc_uint64 = from_hex("8888888888888888");

  const std::array<uint16_t, 4> val_array{ 1, 2, 3, 4 };
  const bytes enc_array = from_hex("0001000200030004");

  const tls::vector<uint32_t, 3> val_vector{ 5, 6 };
  const bytes enc_vector = from_hex("0000080000000500000006");

  const ExampleStruct val_struct{
    0x1111,
    { 0x22, 0x22 },
    { 0x33333333, 0x44444444, 0x55555555, 0x66666666 }
  };
  const bytes enc_struct =
    from_hex("11110002222233333333444444445555555566666666");
};

template<typename T>
void
ostream_test(T val, const std::vector<uint8_t>& enc)
{
  tls::ostream w;
  w << val;
  ASSERT_EQ(w.bytes(), enc);
}

TEST_F(TLSSyntaxTest, OStream)
{
  bytes answer{ 1, 2, 3, 4 };
  tls::ostream w;
  w.write_raw(answer);
  ASSERT_EQ(w.bytes(), answer);

  ostream_test(val_uint8, enc_uint8);
  ostream_test(val_uint16, enc_uint16);
  ostream_test(val_uint32, enc_uint32);
  ostream_test(val_uint64, enc_uint64);
  ostream_test(val_array, enc_array);
  ostream_test(val_vector, enc_vector);
  ostream_test(val_struct, enc_struct);
}

template<typename T>
void
istream_test(T val, const std::vector<uint8_t>& enc)
{
  T data;
  tls::istream r(enc);
  r >> data;
  ASSERT_EQ(data, val);
}

TEST_F(TLSSyntaxTest, IStream)
{
  istream_test(val_uint8, enc_uint8);
  istream_test(val_uint16, enc_uint16);
  istream_test(val_uint32, enc_uint32);
  istream_test(val_uint64, enc_uint64);
  istream_test(val_array, enc_array);
  istream_test(val_vector, enc_vector);
  istream_test(val_struct, enc_struct);
}

// TODO(rlb@ipv.sx) Test failure cases
