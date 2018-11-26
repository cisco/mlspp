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

struct ECIESCiphertext;

class DHPublicKey
{
public:
  DHPublicKey();
  DHPublicKey(const DHPublicKey& other);
  DHPublicKey(DHPublicKey&& other);
  DHPublicKey(const bytes& data);
  DHPublicKey& operator=(const DHPublicKey& other);
  DHPublicKey& operator=(DHPublicKey&& other);

  bool operator==(const DHPublicKey& other) const;
  bool operator!=(const DHPublicKey& other) const;

  bytes to_bytes() const;
  void reset(const bytes& data);

  ECIESCiphertext encrypt(const bytes& plaintext) const;

private:
  typed_unique_ptr<OpenSSLKey> _key;

  friend class DHPrivateKey;
};

tls::ostream&
operator<<(tls::ostream& out, const DHPublicKey& obj);
tls::istream&
operator>>(tls::istream& in, DHPublicKey& obj);

class DHPrivateKey
{
public:
  static DHPrivateKey generate();
  static DHPrivateKey derive(const bytes& secret);

  DHPrivateKey();
  DHPrivateKey(const DHPrivateKey& other);
  DHPrivateKey(DHPrivateKey&& other);
  DHPrivateKey& operator=(const DHPrivateKey& other);
  DHPrivateKey& operator=(DHPrivateKey&& other);

  bool operator==(const DHPrivateKey& other) const;
  bool operator!=(const DHPrivateKey& other) const;

  bytes derive(const DHPublicKey& pub) const;
  const DHPublicKey& public_key() const;

  bytes decrypt(const ECIESCiphertext& ciphertext) const;

private:
  typed_unique_ptr<OpenSSLKey> _key;
  DHPublicKey _pub;
};

struct ECIESCiphertext
{
  DHPublicKey ephemeral;
  tls::opaque<3> content;

  friend tls::ostream& operator<<(tls::ostream& out,
                                  const ECIESCiphertext& obj);
  friend tls::istream& operator>>(tls::istream& in, ECIESCiphertext& obj);
};

tls::ostream&
operator<<(tls::ostream& out, const DHPrivateKey& obj);
tls::istream&
operator>>(tls::istream& in, DHPrivateKey& obj);

// XXX(rlb@ipv.sx): There is a *ton* of repeated code between DH and
// Signature keys, both here and in the corresponding .cpp file.
// While this is unfortunate, it's hopefully a temporary state of
// affairs.  We should look into whether these classes can be
// cleaned up leveraging OpenSSLKey.

class SignaturePublicKey
{
public:
  SignaturePublicKey();
  SignaturePublicKey(const SignaturePublicKey& other);
  SignaturePublicKey(SignaturePublicKey&& other);
  SignaturePublicKey(const bytes& data);
  SignaturePublicKey& operator=(const SignaturePublicKey& other);
  SignaturePublicKey& operator=(SignaturePublicKey&& other);

  bool operator==(const SignaturePublicKey& other) const;
  bool operator!=(const SignaturePublicKey& other) const;

  bool verify(const bytes& message, const bytes& signature) const;

  bytes to_bytes() const;
  void reset(const bytes& data);

private:
  typed_unique_ptr<OpenSSLKey> _key;

  friend class SignaturePrivateKey;
};

tls::ostream&
operator<<(tls::ostream& out, const SignaturePublicKey& obj);
tls::istream&
operator>>(tls::istream& in, SignaturePublicKey& obj);

class SignaturePrivateKey
{
public:
  static SignaturePrivateKey generate();

  SignaturePrivateKey();
  SignaturePrivateKey(const SignaturePrivateKey& other);
  SignaturePrivateKey(SignaturePrivateKey&& other);
  SignaturePrivateKey& operator=(const SignaturePrivateKey& other);
  SignaturePrivateKey& operator=(SignaturePrivateKey&& other);

  bool operator==(const SignaturePrivateKey& other) const;
  bool operator!=(const SignaturePrivateKey& other) const;

  bytes sign(const bytes& message) const;
  const SignaturePublicKey& public_key() const;

private:
  typed_unique_ptr<OpenSSLKey> _key;
  SignaturePublicKey _pub;
};

} // namespace mls
