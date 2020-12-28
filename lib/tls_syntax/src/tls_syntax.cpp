#include <tls/tls_syntax.h>

// NOLINTNEXTLINE(llvmlibc-implementation-in-namespace)
namespace tls {

void
ostream::write_raw(const std::vector<uint8_t>& bytes)
{
  // Not sure what the default argument is here
  // NOLINTNEXTLINE(fuchsia-default-arguments)
  _buffer.insert(_buffer.end(), bytes.begin(), bytes.end());
}

// Primitive type writers
ostream&
ostream::write_uint(uint64_t value, int length)
{
  for (int i = length - 1; i >= 0; --i) {
    _buffer.push_back(static_cast<uint8_t>(value >> unsigned(8 * i)));
  }
  return *this;
}

ostream&
operator<<(ostream& out, bool data)
{
  if (data) {
    return out << uint8_t(1);
  }

  return out << uint8_t(0);
}

ostream&
operator<<(ostream& out, uint8_t data) // NOLINT(llvmlibc-callee-namespace)
{
  return out.write_uint(data, 1);
}

ostream&
operator<<(ostream& out, uint16_t data)
{
  return out.write_uint(data, 2);
}

ostream&
operator<<(ostream& out, uint32_t data)
{
  return out.write_uint(data, 4);
}

ostream&
operator<<(ostream& out, uint64_t data)
{
  return out.write_uint(data, 8);
}

// Because pop_back() on an empty vector is undefined
uint8_t
istream::next()
{
  if (_buffer.empty()) {
    throw ReadError("Attempt to read from empty buffer");
  }

  uint8_t value = _buffer.back();
  _buffer.pop_back();
  return value;
}

// Primitive type readers

istream&
operator>>(istream& in, bool& data)
{
  uint8_t val = 0;
  in >> val;

  // Linter thinks uint8_t is signed (?)
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  if ((val & 0xFE) != 0) {
    throw ReadError("Malformed boolean");
  }

  data = (val == 1);
  return in;
}

istream&
operator>>(istream& in, uint8_t& data) // NOLINT(llvmlibc-callee-namespace)
{
  return in.read_uint(data, 1);
}

istream&
operator>>(istream& in, uint16_t& data)
{
  return in.read_uint(data, 2);
}

istream&
operator>>(istream& in, uint32_t& data)
{
  return in.read_uint(data, 4);
}

istream&
operator>>(istream& in, uint64_t& data)
{
  return in.read_uint(data, 8);
}

} // namespace tls
