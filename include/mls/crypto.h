#pragma once

#include "mls/common.h"
#include "mls/primitives.h"
#include <openssl/evp.h>
#include <tls/tls_syntax.h>
#include <vector>

namespace mls {

// DeterministicHPKE enables RAII-based requests for HPKE to be
// done deterministically.  The RAII pattern is used here to ensure
// that the determinism always gets turned off.  To avoid conflicts
// between multiple requests for determinism, determinism is turned
// off when the last object in the stack is destroyed; it's
// basically a ref-counted bool.
//
// This should only be used for interop testing / test vector
// purposes; it should not be enabled in production systems.
//
// TODO(rlb@ipv.sx): Find a way to hide this API from normal usage.
class DeterministicHPKE
{
public:
  DeterministicHPKE() { _refct += 1; }
  ~DeterministicHPKE() { _refct -= 1; }
  static bool enabled() { return _refct > 0; }

private:
  static int _refct;
};

// Interface to metrics
class CryptoMetrics
{
public:
  struct Report
  {
    uint32_t fixed_base_dh;
    uint32_t var_base_dh;
    uint32_t digest;
    uint32_t hmac;
  };

  static Report snapshot();
  static void reset();

  static void count_fixed_base_dh();
  static void count_var_base_dh();
  static void count_digest();
  static void count_hmac();

private:
  static uint32_t fixed_base_dh;
  static uint32_t var_base_dh;
  static uint32_t digest;
  static uint32_t hmac;
};

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

  HPKEPublicKey() = default;
  HPKEPublicKey(bytes data);

  HPKECiphertext encrypt(CipherSuite suite,
                         const bytes& aad,
                         const bytes& pt) const;
  bytes to_bytes() const;

  TLS_SERIALIZABLE(data)
  TLS_TRAITS(tls::vector<2>)
};

class HPKEPrivateKey
{
public:
  static HPKEPrivateKey generate(CipherSuite suite);
  static HPKEPrivateKey parse(CipherSuite suite, const bytes& data);
  static HPKEPrivateKey derive(CipherSuite suite, const bytes& secret);

  bytes decrypt(CipherSuite suite,
                const bytes& aad,
                const HPKECiphertext& ct) const;
  HPKEPublicKey public_key() const;

  TLS_SERIALIZABLE(_data, _pub_data)
  TLS_TRAITS(tls::vector<2>, tls::vector<2>)

private:
  bytes _data;
  bytes _pub_data;

  HPKEPrivateKey(CipherSuite suite, bytes data);
};

// Signature Keys
class SignaturePublicKey
{
public:
  SignaturePublicKey();
  SignaturePublicKey(CipherSuite suite, bytes data);
  SignaturePublicKey(SignatureScheme scheme, bytes data);
  void set_cipher_suite(CipherSuite suite);
  void set_signature_scheme(SignatureScheme scheme);
  SignatureScheme signature_scheme() const;
  bool verify(const bytes& message, const bytes& signature) const;
  bytes to_bytes() const;

  TLS_SERIALIZABLE(_data)
  TLS_TRAITS(tls::vector<2>)

private:
  SignatureScheme _scheme;
  bytes _data;
};

class SignaturePrivateKey
{
public:
  SignaturePrivateKey();

  static SignaturePrivateKey generate(CipherSuite suite);
  static SignaturePrivateKey parse(CipherSuite suite, const bytes& data);
  static SignaturePrivateKey derive(CipherSuite suite, const bytes& secret);

  bytes sign(const bytes& message) const;
  SignaturePublicKey public_key() const;

  TLS_SERIALIZABLE(_scheme, _data, _pub_data)
  TLS_TRAITS(tls::pass, tls::vector<2>, tls::vector<2>)

private:
  CipherSuite _suite;
  SignatureScheme _scheme;
  bytes _data;
  bytes _pub_data;

  SignaturePrivateKey(CipherSuite suite, const bytes& data);
};

} // namespace mls
