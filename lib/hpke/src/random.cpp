#include <hpke/random.h>
#include <namespace.h>

#include "openssl_common.h"

#include <openssl/rand.h>

namespace MLS_NAMESPACE::hpke {

bytes
random_bytes(size_t size)
{
  auto rand = bytes(size);
  if (1 != RAND_bytes(rand.data(), static_cast<int>(size))) {
    throw openssl_error();
  }
  return rand;
}

} // namespace MLS_NAMESPACE::hpke
