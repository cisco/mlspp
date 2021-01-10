#include <bytes/bytes.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace bytes_ns {

bytes
from_ascii(const std::string& ascii)
{
  return bytes(ascii.begin(), ascii.end());
}

std::string
to_hex(const bytes& data)
{
  std::stringstream hex(std::ios_base::out);
  hex.flags(std::ios::hex);
  for (const auto& byte : data) {
    hex << std::setw(2) << std::setfill('0') << int(byte);
  }
  return hex.str();
}

bytes
from_hex(const std::string& hex)
{
  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  int len = static_cast<int>(hex.length()) / 2;
  bytes out(len);
  for (int i = 0; i < len; i += 1) {
    std::string byte = hex.substr(2 * i, 2);
    out[i] = static_cast<bytes::value_type>(strtol(byte.c_str(), nullptr, 16));
  }

  return out;
}

namespace operators {

bytes&
operator+=(bytes& lhs, const bytes& rhs)
{
  // Not sure what the default argument is here
  // NOLINTNEXTLINE(fuchsia-default-arguments)
  lhs.insert(lhs.end(), rhs.begin(), rhs.end());
  return lhs;
}

bytes
operator+(const bytes& lhs, const bytes& rhs)
{
  bytes out = lhs;
  out += rhs;
  return out;
}

bytes
operator^(const bytes& lhs, const bytes& rhs)
{
  if (lhs.size() != rhs.size()) {
    throw std::invalid_argument("XOR with unequal size");
  }

  bytes out(lhs.size());
  for (size_t i = 0; i < lhs.size(); ++i) {
    out[i] = lhs[i] ^ rhs[i];
  }
  return out;
}

std::ostream&
operator<<(std::ostream& out, const bytes& data)
{
  // Adjust this threshold to make output more compact
  size_t threshold = 0xffff;
  if (data.size() < threshold) {
    return out << to_hex(data);
  }

  bytes abbrev(data.begin(), data.begin() + threshold);
  return out << to_hex(abbrev) << "...";
}

} // namespace operators
} // namespace bytes_ns
