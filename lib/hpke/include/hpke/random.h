#pragma once

#include <bytes/bytes.h>
#include <namespace.h>
using namespace MLS_NAMESPACE::bytes_ns;

namespace MLS_NAMESPACE::hpke {

bytes
random_bytes(size_t size);

} // namespace MLS_NAMESPACE::hpke
