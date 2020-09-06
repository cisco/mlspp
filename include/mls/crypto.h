#pragma once

#include "mls/common.h"
#include <openssl/evp.h>
#include <tls/tls_syntax.h>
#include <vector>

namespace mls {

// Pass-throughs from the primitives, some with metrics wrappers
using primitive::random_bytes;

class Digest : public primitive::Digest
{
public:
  Digest(CipherSuite suite);
};

bytes
hmac(CipherSuite suite, const bytes& key, const bytes& data);

using primitive::open;
using primitive::seal;

bytes
zero_bytes(size_t size);

bool
constant_time_eq(const bytes& lhs, const bytes& rhs);

bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm);

bytes
hkdf_expand_label(CipherSuite suite,
                  const bytes& secret,
                  const std::string& label,
                  const bytes& context,
                  const size_t length);

// HPKE Keys
struct HPKECiphertext
{
  bytes kem_output;
  bytes ciphertext;

  TLS_SERIALIZABLE(kem_output, ciphertext)
  TLS_TRAITS(tls::vector<2>, tls::vector<4>)
};

struct HPKEPublicKey
{
  bytes data;

  HPKECiphertext encrypt(CipherSuite suite,
                         const bytes& aad,
                         const bytes& pt) const;

  TLS_SERIALIZABLE(data)
  TLS_TRAITS(tls::vector<2>)
};

struct HPKEPrivateKey
{
  static HPKEPrivateKey generate(CipherSuite suite);
  static HPKEPrivateKey parse(CipherSuite suite, const bytes& data);
  static HPKEPrivateKey derive(CipherSuite suite, const bytes& secret);

  HPKEPrivateKey() = default;

  bytes data;
  HPKEPublicKey public_key;

  bytes decrypt(CipherSuite suite,
                const bytes& aad,
                const HPKECiphertext& ct) const;

  TLS_SERIALIZABLE(data, public_key)
  TLS_TRAITS(tls::vector<2>, tls::pass)

private:
  HPKEPrivateKey(bytes priv_data, bytes pub_data);
};

// Signature Keys
struct SignaturePublicKey
{
  bytes data;

  bool verify(const CipherSuite& suite,
              const bytes& message,
              const bytes& signature) const;

  TLS_SERIALIZABLE(data)
  TLS_TRAITS(tls::vector<2>)
};

struct SignaturePrivateKey
{
  static SignaturePrivateKey generate(CipherSuite suite);
  static SignaturePrivateKey parse(CipherSuite suite, const bytes& data);
  static SignaturePrivateKey derive(CipherSuite suite, const bytes& secret);

  bytes data;
  SignaturePublicKey public_key;

  bytes sign(const CipherSuite& suite, const bytes& message) const;

  TLS_SERIALIZABLE(data, public_key)
  TLS_TRAITS(tls::vector<2>, tls::pass)

private:
  SignaturePrivateKey(bytes priv_data, bytes pub_data);
};

} // namespace mls
