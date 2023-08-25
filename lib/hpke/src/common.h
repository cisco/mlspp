#pragma once

#include <hpke/hpke.h>
#include <namespace.h>

namespace MLS_NAMESPACE::hpke {

bytes
i2osp(uint64_t val, size_t size);

} // namespace MLS_NAMESPACE::hpke
