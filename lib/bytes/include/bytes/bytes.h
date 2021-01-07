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

} // namespace bytes_ns

// Operators have to be in namespace std because argument-dependent lookup uses
// the unaliased type for bytes (std::vector<uint8_t>)
namespace std {

using bytes_ns::bytes;

bytes&
operator+=(bytes& lhs, const bytes& rhs);

bytes
operator+(const bytes& lhs, const bytes& rhs);

bytes
operator^(const bytes& lhs, const bytes& rhs);

std::ostream&
operator<<(std::ostream& out, const bytes& data);

}
