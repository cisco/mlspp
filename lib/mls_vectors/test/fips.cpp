#include "fips.h"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <set>

using namespace mls;

bool
fips()
{
  return OSSL_PROVIDER_available(nullptr, "fips") == 1 ||
         EVP_default_properties_is_fips_enabled(nullptr) == 1;
}

bool
is_fips_approved(CipherSuite::ID id)
{
  static const auto disallowed = std::set<CipherSuite::ID>{
    CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519,
    CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448,
  };
  return disallowed.count(id) == 0;
}
