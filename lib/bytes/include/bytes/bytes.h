#pragma once

#include <string>
#include <vector>

namespace bytes_ns {

using bytes = std::vector<uint8_t>;

bytes
from_ascii(const std::string& ascii);

std::string
to_hex(const bytes& data);

bytes
from_hex(const std::string& hex);

// Operators on bytes are defined in a separate namespace because operator
// resolution requires them to be in the caller namespace.
namespace operators {

bytes_ns::bytes&
operator+=(bytes_ns::bytes& lhs, const bytes_ns::bytes& rhs);

bytes_ns::bytes
operator+(const bytes_ns::bytes& lhs, const bytes_ns::bytes& rhs);

bytes_ns::bytes
operator^(const bytes_ns::bytes& lhs, const bytes_ns::bytes& rhs);

std::ostream&
operator<<(std::ostream& out, const bytes_ns::bytes& data);
} // namespace operators

} // namespace bytes_ns
