#pragma once

#include <memory>

#include <bytes/bytes.h>
using namespace bytes_ns;

namespace hpke {

struct Digest
{
  enum struct ID
  {
    SHA256,
    SHA384,
    SHA512,
  };

  template<ID id>
  static const Digest& get();

  const ID id;

  bytes hash(const bytes& data) const;
  bytes hmac(const bytes& key, const bytes& data) const;

  size_t hash_size() const;

private:
  const size_t output_size;

  explicit Digest(ID id);
};

} // namespace hpke
