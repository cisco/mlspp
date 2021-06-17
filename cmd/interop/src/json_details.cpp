#include "json_details.h"

///
/// Bytes
///

namespace mls_vectors {

void
to_json(json& j, const HexBytes& v)
{
  j = to_hex(v.data);
}

void
from_json(const json& j, HexBytes& v)
{
  v.data = from_hex(j.get<std::string>());
}

} // namespace mls_vectors

// TODO(RLB) Other concrete, non-templated type serializers could be moved here.
