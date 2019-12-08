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
  using parent::parent;
  typed_unique_ptr();
  typed_unique_ptr(T* ptr);
};

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

bytes
derive_secret(CipherSuite suite,
              const bytes& secret,
              const std::string& label,
              const bytes& context);

class AESGCM
{
public:
  AESGCM() = delete;
  AESGCM(const AESGCM& other) = delete;
  AESGCM(AESGCM&& other) = delete;
  AESGCM& operator=(const AESGCM& other) = delete;
  AESGCM& operator=(AESGCM&& other) = delete;

  AESGCM(const bytes& key, const bytes& nonce);

  void set_aad(const bytes& aad);
  bytes encrypt(const bytes& plaintext) const;
  bytes decrypt(const bytes& ciphertext) const;

  static size_t key_size(CipherSuite suite);

  static const size_t key_size_128 = 16;
  static const size_t key_size_192 = 24;
  static const size_t key_size_256 = 32;
  static const size_t nonce_size = 12;
  static const size_t tag_size = 16;

private:
  bytes _key;
  bytes _nonce;
  bytes _aad;

  // This raw pointer only ever references memory managed by
  // OpenSSL, so it doesn't need to be scoped.
  const EVP_CIPHER* _cipher;
};

// Generic PublicKey and PrivateKey structs, which are specialized
// to DH and Signature below

class PublicKey
  : public CipherAware
  , public SignatureAware
{
public:
  PublicKey(const PublicKey& other);
  PublicKey& operator=(const PublicKey& other);
  PublicKey& operator=(PublicKey&& other) noexcept;
  virtual ~PublicKey() = default;

  explicit PublicKey(CipherSuite suite);
  PublicKey(CipherSuite suite, const bytes& data);
  PublicKey(CipherSuite suite, OpenSSLKey* key);

  explicit PublicKey(SignatureScheme scheme);
  PublicKey(SignatureScheme scheme, const bytes& data);
  PublicKey(SignatureScheme scheme, OpenSSLKey* key);

  bool operator==(const PublicKey& other) const;
  bool operator!=(const PublicKey& other) const;

  bytes to_bytes() const;
  void reset(const bytes& data);
  void reset(OpenSSLKey* key);

protected:
  typed_unique_ptr<OpenSSLKey> _key;

  friend tls::ostream& operator<<(tls::ostream& out, const PublicKey& obj);
  friend tls::istream& operator>>(tls::istream& in, PublicKey& obj);
};

class PrivateKey
  : public CipherAware
  , public SignatureAware
{
public:
  PrivateKey(const PrivateKey& other);
  PrivateKey& operator=(const PrivateKey& other);
  PrivateKey& operator=(PrivateKey&& other) noexcept;
  virtual ~PrivateKey() = default;

  bool operator==(const PrivateKey& other) const;
  bool operator!=(const PrivateKey& other) const;

protected:
  typed_unique_ptr<OpenSSLKey> _key;
  std::unique_ptr<PublicKey> _pub;

  std::unique_ptr<PublicKey> type_preserving_dup(const PublicKey* pub) const;

  PrivateKey(CipherSuite suite, OpenSSLKey* key);
  PrivateKey(SignatureScheme scheme, OpenSSLKey* key);
};

// DH specialization
struct HPKECiphertext;

class DHPublicKey : public PublicKey
{
public:
  using PublicKey::PublicKey;
  DHPublicKey();
  HPKECiphertext encrypt(const bytes& aad, const bytes& plaintext) const;

private:
  friend class DHPrivateKey;
};

class DHPrivateKey : public PrivateKey
{
public:
  using PrivateKey::PrivateKey;

  static DHPrivateKey generate(CipherSuite suite);
  static DHPrivateKey parse(CipherSuite suite, const bytes& data);
  static DHPrivateKey derive(CipherSuite suite, const bytes& secret);
  static DHPrivateKey node_derive(CipherSuite suite, const bytes& secret);

  bytes derive(const DHPublicKey& pub) const;
  bytes decrypt(const bytes& aad, const HPKECiphertext& ciphertext) const;

  const DHPublicKey& public_key() const;

private:
  DHPrivateKey(CipherSuite suite, OpenSSLKey* key);
};

// Signature specialization
class SignaturePublicKey : public PublicKey
{
public:
  using PublicKey::PublicKey;
  bool verify(const bytes& message, const bytes& signature) const;

private:
  friend class SignaturePrivateKey;
};

class SignaturePrivateKey : public PrivateKey
{
public:
  using PrivateKey::PrivateKey;

  static SignaturePrivateKey generate(SignatureScheme scheme);
  static SignaturePrivateKey parse(SignatureScheme scheme, const bytes& data);
  static SignaturePrivateKey derive(SignatureScheme scheme,
                                    const bytes& secret);

  bytes sign(const bytes& message) const;
  const SignaturePublicKey& public_key() const;

private:
  SignaturePrivateKey(SignatureScheme scheme, OpenSSLKey* key);
};

// A struct for HPKE-encrypted information
struct HPKECiphertext : public CipherAware
{
  DHPublicKey ephemeral;
  tls::opaque<4> content;

  HPKECiphertext(CipherSuite suite)
    : CipherAware(suite)
    , ephemeral(suite)
  {}

  HPKECiphertext(const DHPublicKey& ephemeral_in, const bytes& content_in)
    : CipherAware(ephemeral_in.cipher_suite())
    , ephemeral(ephemeral_in)
    , content(content_in)
  {}

  TLS_SERIALIZABLE(ephemeral, content);
};

} // namespace mls
