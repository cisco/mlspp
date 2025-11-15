#pragma once

#include <memory>

#include <bytes/bytes.h>
#include <hpke/hpke.h>
#include <namespace.h>

using namespace MLS_NAMESPACE::bytes_ns;

namespace MLS_NAMESPACE::hpke {

struct Digest
{
  enum struct ID
  {
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
  };

  template<ID id>
  static const Digest& get();

  const ID id;

  bytes hash(const bytes& data) const;
  bytes hmac(const bytes& key, const bytes& data) const;

  const size_t hash_size;

private:
  explicit Digest(ID id);

  bytes hmac_for_hkdf_extract(const bytes& key, const bytes& data) const;
  friend struct HKDF;
};

#if !defined(WITH_BORINGSSL)
struct SHAKE256
{
  static bytes derive(const bytes& ikm, size_t length);
  static bytes labeled_derive(KEM::ID kem_id,
                              const bytes& ikm,
                              const std::string& label,
                              const bytes& context,
                              size_t length);
};
#endif

} // namespace MLS_NAMESPACE::hpke
