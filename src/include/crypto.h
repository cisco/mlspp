#pragma once

#include "common.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
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
  P256_SHA256 = 0x0000,
  P521_SHA512 = 0x0010,
  Ed25519 = 0x0001,
  Ed448 = 0x0011
};

tls::ostream&
operator<<(tls::ostream& out, const SignatureScheme& obj);
tls::istream&
operator>>(tls::istream& in, SignatureScheme& obj);

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

  const size_t output_size() const;

private:
  size_t _size;
  typed_unique_ptr<EVP_MD_CTX> _ctx;
};

bytes
zero_bytes(size_t size);

bytes
random_bytes(size_t size);

bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm);

class State;

bytes
derive_secret(CipherSuite suite,
              const bytes& secret,
              const std::string& label,
              const State& state,
              const size_t length);

class AESGCM
{
public:
  AESGCM() = delete;
  AESGCM(const AESGCM& other) = delete;
  AESGCM(AESGCM&& other) = delete;
  AESGCM& operator=(const AESGCM& other) = delete;
  AESGCM& operator=(AESGCM&& other) = delete;

  AESGCM(const bytes& key, const bytes& nonce);

  void set_aad(const bytes& key);
  bytes encrypt(const bytes& plaintext) const;
  bytes decrypt(const bytes& ciphertext) const;

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
{
public:
  PublicKey(const PublicKey& other);
  PublicKey(PublicKey&& other);
  PublicKey& operator=(const PublicKey& other);
  PublicKey& operator=(PublicKey&& other);

  PublicKey(OpenSSLKeyType type);
  PublicKey(OpenSSLKeyType type, const bytes& data);
  PublicKey(OpenSSLKey* key);

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
{
public:
  PrivateKey(const PrivateKey& other);
  PrivateKey(PrivateKey&& other);
  PrivateKey& operator=(const PrivateKey& other);
  PrivateKey& operator=(PrivateKey&& other);

  bool operator==(const PrivateKey& other) const;
  bool operator!=(const PrivateKey& other) const;

protected:
  typed_unique_ptr<OpenSSLKey> _key;
  typed_unique_ptr<PublicKey> _pub;

  PrivateKey(OpenSSLKey* key);
};

// DH specialization
struct ECIESCiphertext;

class DHPublicKey
  : public PublicKey
  , public CipherAware
{
public:
  DHPublicKey(CipherSuite suite);
  DHPublicKey(CipherSuite suite, const bytes& data);

  ECIESCiphertext encrypt(const bytes& plaintext) const;

private:
  CipherSuite _suite;

  DHPublicKey(CipherSuite suite, OpenSSLKey* key);
  friend class DHPrivateKey;
};

class DHPrivateKey
  : public PrivateKey
  , public CipherAware
{
public:
  using PrivateKey::PrivateKey;

  static DHPrivateKey generate(CipherSuite suite);
  static DHPrivateKey derive(CipherSuite suite, const bytes& secret);

  bytes derive(const DHPublicKey& pub) const;
  bytes decrypt(const ECIESCiphertext& ciphertext) const;

  const DHPublicKey& public_key() const;

private:
  CipherSuite _suite;
  DHPrivateKey(CipherSuite suite, OpenSSLKey* key);
};

// Signature specialization
class SignaturePublicKey : public PublicKey
{
public:
  SignaturePublicKey(SignatureScheme scheme);
  SignaturePublicKey(SignatureScheme scheme, const bytes& data);

  bool verify(const bytes& message, const bytes& signature) const;

  SignatureScheme signature_scheme() const;

private:
  SignatureScheme _scheme;

  SignaturePublicKey(SignatureScheme scheme, OpenSSLKey* key);
  friend class SignaturePrivateKey;
};

class SignaturePrivateKey : public PrivateKey
{
public:
  using PrivateKey::PrivateKey;

  static SignaturePrivateKey generate(SignatureScheme scheme);

  bytes sign(const bytes& message) const;
  const SignaturePublicKey& public_key() const;
  SignatureScheme signature_scheme() const;

private:
  SignatureScheme _scheme;

  SignaturePrivateKey(SignatureScheme scheme, OpenSSLKey* key);
};

// A struct for ECIES-encrypted information
struct ECIESCiphertext
{
  DHPublicKey ephemeral;
  tls::opaque<3> content;

  friend tls::ostream& operator<<(tls::ostream& out,
                                  const ECIESCiphertext& obj);
  friend tls::istream& operator>>(tls::istream& in, ECIESCiphertext& obj);
};

} // namespace mls
