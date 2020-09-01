#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace bytes_ns {

using bytes = std::vector<uint8_t>;

bytes
to_bytes(const std::string& ascii);

std::string
to_hex(const bytes& data);

bytes
from_hex(const std::string& hex);

bytes&
operator+=(bytes& lhs, const bytes& rhs);

bytes
operator+(const bytes& lhs, const bytes& rhs);

bytes
operator^(const bytes& lhs, const bytes& rhs);

std::ostream&
operator<<(std::ostream& out, const bytes& data);

} // namespace bytes_ns
