#pragma once

#include "common.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tls_syntax.h"
#include <stdexcept>
#include <vector>

namespace mls {

// Algorithm selectors
enum struct CipherSuite : uint16_t
{
  P256_SHA256_AES128GCM = 0x0000,
  P521_SHA512_AES256GCM = 0x0010,
  X25519_SHA256_AES128GCM = 0x0001,
  X448_SHA512_AES256GCM = 0x0011
};

size_t suite_nonce_size(CipherSuite suite);
size_t suite_key_size(CipherSuite suite);

enum struct SignatureScheme : uint16_t
{
  P256_SHA256 = 0x0403,
  P521_SHA512 = 0x0603,
  Ed25519 = 0x0807,
  Ed448 = 0x0808
};

#define DUMMY_SIGNATURE_SCHEME SignatureScheme::P256_SHA256

// Utility classes to avoid a bit of boilerplate
class CipherAware
{
public:
  CipherAware(CipherSuite suite)
    : _suite(suite)
  {}

  CipherSuite cipher_suite() const { return _suite; }

protected:
  CipherSuite _suite;
};

class SignatureAware
{
public:
  SignatureAware(SignatureScheme scheme)
    : _scheme(scheme)
  {}

  SignatureScheme signature_scheme() const { return _scheme; }

protected:
  SignatureScheme _scheme;
};

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
class CryptoMetrics {
public:
  struct Report {
    uint32_t fixed_base_dh;
    uint32_t var_base_dh;
    uint32_t digest;
    uint32_t digest_bytes;
    uint32_t hmac;
  };

  static Report snapshot();
  static void reset();

  static void count_fixed_base_dh();
  static void count_var_base_dh();
  static void count_digest();
  static void count_digest_bytes(uint32_t count);
  static void count_hmac();

private:
  static uint32_t fixed_base_dh;
  static uint32_t var_base_dh;
  static uint32_t digest;
  static uint32_t digest_bytes;
  static uint32_t hmac;
};

// Adapt standard pointers so that they can be "typed" to handle
// custom deleters more easily.
template<typename T>
void
TypedDelete(T* ptr);

template<>
void
TypedDelete(EVP_MD_CTX* ptr);

template<>
void
TypedDelete(EVP_PKEY* ptr);

template<typename T>
using typed_unique_ptr_base = std::unique_ptr<T, decltype(&TypedDelete<T>)>;

template<typename T>
class typed_unique_ptr : public typed_unique_ptr_base<T>
{
public:
  using parent = typed_unique_ptr_base<T>;

  typed_unique_ptr()
    : parent(nullptr, TypedDelete<T>)
  {}

  typed_unique_ptr(T* ptr)
    : parent(ptr, TypedDelete<T>)
  {}
};

// This shorthand just saves on explicit template arguments
template<typename T>
typed_unique_ptr<T>
make_typed_unique(T* ptr)
{
  return typed_unique_ptr<T>(ptr);
}

// Interface cleanup wrapper for raw OpenSSL EVP keys
struct OpenSSLKey;
enum struct OpenSSLKeyType;

template<>
void
TypedDelete(OpenSSLKey* ptr);

// Digests
enum struct DigestType
{
  SHA256,
  SHA512
};

class Digest
{
public:
  Digest(DigestType type); // XXX(rlb@ipv.sx) delete?
  Digest(CipherSuite suite);
  Digest& write(uint8_t byte);
  Digest& write(const bytes& data);
  bytes digest();

  size_t output_size() const;

private:
  size_t _size;
  typed_unique_ptr<EVP_MD_CTX> _ctx;
};

bytes
zero_bytes(size_t size);

bytes
random_bytes(size_t size);

bytes
hmac(CipherSuite suite, const bytes& key, const bytes& data);

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
  tls::opaque<2> kem_output;
  tls::opaque<4> ciphertext;

  TLS_SERIALIZABLE(kem_output, ciphertext);
};

class HPKEPublicKey
{
public:
  HPKEPublicKey();
  HPKEPublicKey(CipherSuite suite);
  HPKEPublicKey(CipherSuite suite, bytes data);

  CipherSuite cipher_suite() const;
  HPKECiphertext encrypt(const bytes& aad, const bytes& plaintext) const;
  bytes to_bytes() const;

  TLS_SERIALIZABLE(_data);

private:
  CipherSuite _suite;
  tls::opaque<2> _data;
};

class HPKEPrivateKey
{
public:
  static HPKEPrivateKey generate(CipherSuite suite);
  static HPKEPrivateKey parse(CipherSuite suite, const bytes& data);
  static HPKEPrivateKey derive(CipherSuite suite, const bytes& secret);

  CipherSuite cipher_suite() const;
  bytes decrypt(const bytes& aad, const HPKECiphertext& ciphertext) const;

  HPKEPublicKey public_key() const;

  TLS_SERIALIZABLE(_suite, _data, _pub_data);

private:
  CipherSuite _suite;
  tls::opaque<2> _data;
  tls::opaque<2> _pub_data;

  HPKEPrivateKey(CipherSuite suite, bytes data);
};

// Signature Keys
class SignaturePublicKey
{
public:
  SignaturePublicKey();
  SignaturePublicKey(SignatureScheme scheme, bytes data);

  void set_signature_scheme(SignatureScheme scheme);
  SignatureScheme signature_scheme() const;
  bool verify(const bytes& message, const bytes& signature) const;
  bytes to_bytes() const;

  TLS_SERIALIZABLE(_data);

private:
  SignatureScheme _scheme;
  tls::opaque<2> _data;
};

class SignaturePrivateKey
{
public:
  static SignaturePrivateKey generate(SignatureScheme scheme);
  static SignaturePrivateKey parse(SignatureScheme scheme, const bytes& data);
  static SignaturePrivateKey derive(SignatureScheme scheme,
                                    const bytes& secret);

  bytes sign(const bytes& message) const;
  SignaturePublicKey public_key() const;

  TLS_SERIALIZABLE(_scheme, _data, _pub_data);

private:
  SignatureScheme _scheme;
  tls::opaque<2> _data;
  tls::opaque<2> _pub_data;

  SignaturePrivateKey(SignatureScheme scheme, bytes data);
};

} // namespace mls
