#include "common.h"

namespace mls_vectors {

using namespace mls;

///
/// Assertions for verifying test vectors
///

std::ostream&
operator<<(std::ostream& str, const NodeIndex& obj)
{
  return str << obj.val;
}

std::ostream&
operator<<(std::ostream& str, const NodeCount& obj)
{
  return str << obj.val;
}

std::ostream&
operator<<(std::ostream& str, const std::vector<uint8_t>& obj)
{
  return str << to_hex(obj);
}

std::ostream&
operator<<(std::ostream& str, const GroupContent::RawContent& obj)
{
  return var::visit(
    overloaded{
      [&](const Proposal&) -> std::ostream& { return str << "[Proposal]"; },
      [&](const Commit&) -> std::ostream& { return str << "[Commit]"; },
      [&](const ApplicationData&) -> std::ostream& {
        return str << "[ApplicationData]";
      },
    },
    obj);
}

} // namespace mls_vectors
