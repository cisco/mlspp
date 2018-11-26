#pragma once

#include "common.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "tls_syntax.h"
#include <stdexcept>
#include <vector>

namespace mls {

// Interface cleanup wrapper for raw OpenSSL EVP keys
enum class OpenSSLKeyType : uint8_t
{
  P256,
  X25519,
  Ed25519
};

struct OpenSSLKey;

// Adapt standard pointers so that they can be "typed" to handle
// custom deleters more easily.
template<typename T>
void
TypedDelete(T* ptr);

template<>
void
TypedDelete(EVP_PKEY* ptr);

template<>
void
TypedDelete(OpenSSLKey* ptr);

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

// Wrapper for OpenSSL errors
class OpenSSLError : public std::runtime_error
{
public:
  typedef std::runtime_error parent;
  using parent::parent;

  static OpenSSLError current();
};

class SHA256Digest
{
public:
  SHA256Digest();
  SHA256Digest(uint8_t byte);
  SHA256Digest(const bytes& data);

  SHA256Digest& write(uint8_t byte);
  SHA256Digest& write(const bytes& data);
  bytes digest();

  static const size_t output_size = 32;

private:
  SHA256_CTX _ctx;
};

bytes
zero_bytes(size_t size);

bytes
random_bytes(size_t size);

bytes
hkdf_extract(const bytes& salt, const bytes& ikm);

class State;

bytes
derive_secret(const bytes& secret,
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
  PublicKey(OpenSSLKeyType type);
  PublicKey(const PublicKey& other);
  PublicKey(PublicKey&& other);
  PublicKey(OpenSSLKeyType type, const bytes& data);
  PublicKey(OpenSSLKey* key);

  PublicKey& operator=(const PublicKey& other);
  PublicKey& operator=(PublicKey&& other);

  bool operator==(const PublicKey& other) const;
  bool operator!=(const PublicKey& other) const;

  bytes to_bytes() const;
  void reset(const bytes& data);
  void reset(OpenSSLKey* key);

protected:
  typed_unique_ptr<OpenSSLKey> _key;
};

tls::ostream&
operator<<(tls::ostream& out, const PublicKey& obj);
tls::istream&
operator>>(tls::istream& in, PublicKey& obj);

class PrivateKey
{
public:
  PrivateKey();
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

class DHPublicKey : public PublicKey
{
public:
  using PublicKey::PublicKey;
  DHPublicKey();
  DHPublicKey(const bytes& data);
  ECIESCiphertext encrypt(const bytes& plaintext) const;
  friend class DHPrivateKey;
};

class DHPrivateKey : public PrivateKey
{
public:
  using PrivateKey::PrivateKey;

  static DHPrivateKey generate();
  static DHPrivateKey derive(const bytes& secret);
  const DHPublicKey& public_key() const;

  bytes derive(const DHPublicKey& pub) const;
  bytes decrypt(const ECIESCiphertext& ciphertext) const;
};

// Signature specialization
class SignaturePublicKey : public PublicKey
{
public:
  using PublicKey::PublicKey;

  // XXX(rlb@ipv.sx) These are needed until we get proper crypto
  // agility going.
  SignaturePublicKey();
  SignaturePublicKey(const bytes& data);

  bool verify(const bytes& message, const bytes& signature) const;
};

class SignaturePrivateKey : public PrivateKey
{
public:
  using PrivateKey::PrivateKey;

  static SignaturePrivateKey generate();

  bytes sign(const bytes& message) const;
  const SignaturePublicKey& public_key() const;
};

struct ECIESCiphertext
{
  DHPublicKey ephemeral;
  tls::opaque<3> content;

  friend tls::ostream& operator<<(tls::ostream& out,
                                  const ECIESCiphertext& obj);
  friend tls::istream& operator>>(tls::istream& in, ECIESCiphertext& obj);
};

} // namespace mls
