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

typedef std::vector<CipherSuite> CipherList;

// Utility class to avoid a bit of boilerplate
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

tls::ostream&
operator<<(tls::ostream& out, const CipherSuite& obj);
tls::istream&
operator>>(tls::istream& in, CipherSuite& obj);

enum struct SignatureScheme : uint16_t
{
  P256_SHA256 = 0x0403,
  P521_SHA512 = 0x0603,
  Ed25519 = 0x0807,
  Ed448 = 0x0808
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

tls::ostream&
operator<<(tls::ostream& out, const SignatureScheme& obj);
tls::istream&
operator>>(tls::istream& in, SignatureScheme& obj);

// Methods to help with testing
namespace test {

// DeterministicECIES enables RAII-based requests for ECIES to be
// done deterministically.  The RAII pattern is used here to ensure
// that the determinism always gets turned off.  To avoid conflicts
// between multiple requests for determinism, determinism is turned
// off when the last object in the stack is destroyed; it's
// basically a ref-counted bool.
class DeterministicECIES
{
public:
  DeterministicECIES() { _refct += 1; }
  ~DeterministicECIES() { _refct -= 1; }
  static bool enabled() { return _refct > 0; }

private:
  static int _refct;
};

bool
deterministic_signature_scheme(SignatureScheme scheme);

}

// Adapt standard pointers so that they can be "typed" to handle
// custom deleters more easily.
template<typename T>
void
TypedDelete(T* ptr);

template<>
void
TypedDelete(EVP_PKEY* ptr);

template<typename T>
using typed_unique_ptr_base = std::unique_ptr<T, decltype(&TypedDelete<T>)>;

template<typename T>
class typed_unique_ptr : public typed_unique_ptr_base<T>
{
public:
  typedef typed_unique_ptr_base<T> parent;
  using parent::parent;

  typed_unique_ptr()
    : typed_unique_ptr_base<T>(nullptr, TypedDelete<T>)
  {}

  typed_unique_ptr(T* ptr)
    : typed_unique_ptr_base<T>(ptr, TypedDelete<T>)
  {}
};

// Interface cleanup wrapper for raw OpenSSL EVP keys
struct OpenSSLKey;
enum struct OpenSSLKeyType;

template<>
void
TypedDelete(OpenSSLKey* ptr);

// Wrapper for OpenSSL errors
class OpenSSLError : public std::runtime_error
{
public:
  typedef std::runtime_error parent;
  using parent::parent;

  static OpenSSLError current();
};

// Digests
enum struct DigestType
{
  SHA256,
  SHA512
};

class Digest
{
public:
  Digest(DigestType type);
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

struct GroupState;

bytes
derive_secret(CipherSuite suite,
              const bytes& secret,
              const std::string& label,
              const GroupState& state,
              const size_t size);

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
struct ECIESCiphertext;

class DHPublicKey : public PublicKey
{
public:
  using PublicKey::PublicKey;
  ECIESCiphertext encrypt(const bytes& plaintext) const;

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

  bytes derive(const DHPublicKey& pub) const;
  bytes decrypt(const ECIESCiphertext& ciphertext) const;

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

// A struct for ECIES-encrypted information
struct ECIESCiphertext : public CipherAware
{
  DHPublicKey ephemeral;
  tls::opaque<3> content;

  ECIESCiphertext(CipherSuite suite)
    : CipherAware(suite)
    , ephemeral(suite)
  {}

  ECIESCiphertext(const DHPublicKey& ephemeral, const bytes& content)
    : CipherAware(ephemeral.cipher_suite())
    , ephemeral(ephemeral)
    , content(content)
  {}

  friend bool operator==(const ECIESCiphertext& lhs,
                         const ECIESCiphertext& rhs);
  friend tls::ostream& operator<<(tls::ostream& out,
                                  const ECIESCiphertext& obj);
  friend tls::istream& operator>>(tls::istream& in, ECIESCiphertext& obj);
};

} // namespace mls
