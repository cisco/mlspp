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

} // namespace bytes_ns
