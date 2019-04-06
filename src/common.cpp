#include "common.h"
#include "session.h"
#include "state.h"

namespace mls {

bytes
to_bytes(const std::string& ascii)
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

  int len = hex.length() / 2;
  bytes out(len);
  for (int i = 0; i < len; i += 1) {
    std::string byte = hex.substr(2 * i, 2);
    out[i] = strtol(byte.c_str(), nullptr, 16);
  }

  return out;
}

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
  bytes out(lhs);
  out += rhs;
  return out;
}

std::ostream&
operator<<(std::ostream& out, const bytes& data)
{
  auto threshold = 0xffff;
  if (data.size() < threshold) {
    return out << to_hex(data);
  }

  bytes abbrev(data.begin(), data.begin() + threshold);
  return out << to_hex(abbrev) << "...";
}

} // namespace mls
