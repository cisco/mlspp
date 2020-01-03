#include "common.h"
#include "crypto.h"

namespace mls {
namespace primitive {

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

std::tuple<bytes, bytes> encap(CipherSuite suite,
                               const bytes& pub,
                               const bytes& seed);
bytes decap(CipherSuite suite,
            const bytes& priv,
            const bytes& enc);


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

}; // namespace primitive
}; // namespace mls
