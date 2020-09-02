#pragma once

#include <memory>

#include <bytes/bytes.h>
using namespace bytes_ns;

namespace hpke {

struct Digest
{
  enum struct ID
  {
    sha256,
    sha384,
    sha512,
  };

  static std::unique_ptr<Digest> create(ID id);

  bytes hash(const bytes& data) const;
  bytes hmac(const bytes& key, const bytes& data) const;

  size_t hash_size() const;

private:
  ID id;
  size_t output_size;

  explicit Digest(ID id);
  friend class std::unique_ptr<Digest>;
};

}
