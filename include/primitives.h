#pragma once

#include "common.h"

namespace mls {
namespace primitive {

// Randomness
bytes
random_bytes(size_t size);

// Digest and HMAC
class Digest
{
public:
  Digest(CipherSuite suite);
  ~Digest();
  Digest& write(uint8_t byte);
  Digest& write(const bytes& data);
  bytes digest();

  size_t output_size() const;

private:
  struct Implementation;
  std::unique_ptr<Implementation> _impl;
};

bytes
hmac(CipherSuite suite, const bytes& key, const bytes& data);

// Symmetric encryption
bytes seal(CipherSuite suite,
           const bytes& key,
           const bytes& nonce,
           const bytes& aad,
           const bytes& plaintext);

bytes open(CipherSuite suite,
           const bytes& key,
           const bytes& nonce,
           const bytes& aad,
           const bytes& ciphertext);

// DHKEM
bytes generate(CipherSuite suite);
bytes derive(CipherSuite suite, const bytes& data);
bytes priv_to_pub(CipherSuite suite, const bytes& data);

bytes dh(CipherSuite suite,
         const bytes& priv,
         const bytes& pub);


// Signing
bytes generate(SignatureScheme scheme);
bytes derive(SignatureScheme scheme, const bytes& data);
bytes priv_to_pub(SignatureScheme scheme, const bytes& data);

bytes sign(SignatureScheme scheme,
           const bytes& priv,
           const bytes& message);

bool verify(SignatureScheme scheme,
             const bytes& pub,
             const bytes& message,
             const bytes& signature);

} // namespace primitive
} // namespace mls
