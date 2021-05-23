#include <tls/tls_syntax.h>

// NOLINTNEXTLINE(llvmlibc-implementation-in-namespace)
namespace tls {

void
ostream::check_remaining(size_t length)
{
  if (length > _buffer.size()) {
    throw WriteError("Write size exceeds available size");
  }
}

void
ostream::write_raw(const std::vector<uint8_t>& bytes)
{
  check_remaining(bytes.size());

  // XXX(RLB) This is a hack around the const-ness of string_view
  auto* data = const_cast<uint8_t*>(_buffer.data());
  std::copy(bytes.begin(), bytes.end(), data);

  _buffer.remove_prefix(bytes.size());
  _written += bytes.size();
}

// Primitive type writers
void
ostream::write_uint(uint64_t value, size_t length)
{
  check_remaining(length);
  write_uint(value, _buffer.substr(0, length));
  _buffer.remove_prefix(length);
  _written += length;
}

void
ostream::write_uint(uint64_t value, output_bytes span)
{
  // XXX(RLB) This is a hack around the const-ness of string_view
  auto* data = const_cast<uint8_t*>(span.data());
  for (size_t i = 0; i < span.size(); i++) {
    auto shift = 8 * (span.size() - i  - 1);
    *(data + i) = static_cast<uint8_t>(value >> shift);
  }
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
  out.write_uint(data, 1);
  return out;
}

ostream&
operator<<(ostream& out, uint16_t data)
{
  out.write_uint(data, 2);
  return out;
}

ostream&
operator<<(ostream& out, uint32_t data)
{
  out.write_uint(data, 4);
  return out;
}

ostream&
operator<<(ostream& out, uint64_t data)
{
  out.write_uint(data, 8);
  return out;
}

// Because pop_back() on an empty vector is undefined
uint8_t
istream::next()
{
  if (_buffer.empty()) {
    throw ReadError("Attempt to read from empty buffer");
  }

  uint8_t value = _buffer.at(0);
  _buffer.remove_prefix(1);
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
