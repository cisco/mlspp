#include "json_details.h"

///
/// Bytes
///

namespace bytes_ns {
  void to_json(json& j, const bytes& v) {
    j = to_hex(v);
  }

  void from_json(const json& j, bytes& v) {
    v = from_hex(j.get<std::string>());
  }
} // namespace bytes_ns

// TODO(RLB) Other concrete, non-templated type serializers could be moved here.
