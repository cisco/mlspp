#include "common.h"

namespace hpke {

bytes
i2osp(uint64_t val, size_t size)
{
  auto out = bytes(size, 0);
  auto max = size;
  if (size > 8) {
    max = 8;
  }

  for (size_t i = 0; i < max; i++) {
    out[size - i - 1] = val >> (8 * i);
  }
  return out;
}

} // namespace hpke
