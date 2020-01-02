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

}; // namespace primitive
}; // namespace mls
