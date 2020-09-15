#pragma once

#include "bytes/bytes.h"
#include <memory>
#include <optional>

using namespace bytes_ns;
using namespace std;

namespace hpke {

// Wrapper around X509 OpenSsl API
struct Certificate
{

  struct Signature
  {
    enum struct ID : uint16_t
    {
      unknown = 0x0000,
      ED25519 = 0x0001,
      ED448 = 0x0002,
    };

    struct PublicKey
    {
      bytes data;
    };

    PublicKey pkey;
    ID algorithm;
  };

  Certificate();
  explicit Certificate(const bytes& der);
  ~Certificate();

  Signature::ID signature_algorithm() const;

  Signature::PublicKey public_key() const;

private:
  Signature signature;

  // Cert implementation
  struct Internals;
  std::unique_ptr<Internals> internal;
};

} // namespace hpke