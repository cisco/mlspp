#pragma once

#include "common.h"
#include "openssl/ec.h"
#include "openssl/sha.h"
#include "tls_syntax.h"
#include <stdexcept>
#include <vector>

namespace mls {

// Wrapper for OpenSSL errors
class OpenSSLError : public std::runtime_error
{
public:
  typedef std::runtime_error parent;
  using parent::parent;

  static OpenSSLError current();
};

// Scoped pointers for OpenSSL types
template<typename T>
void
TypedDelete(T* ptr);

template<typename T>
T*
TypedDup(T* ptr);

template<typename T>
class Scoped
{
public:
  Scoped()
    : _raw(nullptr)
  {}

  Scoped(T* raw) { adopt(raw); }

  Scoped(const Scoped& other) { adopt(TypedDup(other._raw)); }

  Scoped(Scoped&& other)
  {
    _raw = other._raw;
    other._raw = nullptr;
  }

  Scoped& operator=(const Scoped& other)
  {
    clear();
    adopt(TypedDup(other._raw));
    return *this;
  }

  Scoped& operator=(Scoped&& other)
  {
    _raw = other._raw;
    other._raw = nullptr;
    return *this;
  }

  ~Scoped() { clear(); }

  void move(Scoped& other)
  {
    adopt(other._raw);
    other._raw = nullptr;
  }

  void adopt(T* raw)
  {
    if (raw == nullptr) {
      throw OpenSSLError::current();
    }
    _raw = raw;
  }

  void clear()
  {
    if (_raw != nullptr) {
      TypedDelete(_raw);
      _raw = nullptr;
    }
  }

  const T* get() const { return _raw; }

  T* get() { return _raw; }

private:
  T* _raw;
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

private:
  SHA256_CTX _ctx;
};

bytes
hkdf_extract(const bytes& salt, const bytes& ikm);

bytes
derive_secret(const bytes& secret,
              const std::string& label,
              const bytes& group_id,
              const epoch_t& epoch,
              const bytes& message);

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

private:
  Scoped<EC_KEY> _key;

  DHPublicKey(const EC_POINT* pt);
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

  DHPrivateKey() = delete;
  DHPrivateKey(const DHPrivateKey& other);
  DHPrivateKey(DHPrivateKey&& other);
  DHPrivateKey& operator=(const DHPrivateKey& other);
  DHPrivateKey& operator=(DHPrivateKey&& other);

  bool operator==(const DHPrivateKey& other) const;
  bool operator!=(const DHPrivateKey& other) const;

  bytes derive(DHPublicKey pub) const;
  DHPublicKey public_key() const;

private:
  Scoped<EC_KEY> _key;
  DHPublicKey _pub;

  DHPrivateKey(EC_KEY* key);
};

// XXX(rlb@ipv.sx): There is a *ton* of repeated code between DH and
// Signature keys, both here and in the corresponding .cpp file.
// While this is unfortunate, it's a temporary state of affairs.  In
// the slightly longer run, we're going to want to refactor this to
// add more crypto agility anyway.  That agility will probably
// require a complete restructure of these classes, e.g., because
// Ed25519 does not use EC_KEY / ECDSA_sign.

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
  Scoped<EC_KEY> _key;

  SignaturePublicKey(const EC_POINT* pt);
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

  SignaturePrivateKey() = delete;
  SignaturePrivateKey(const SignaturePrivateKey& other);
  SignaturePrivateKey(SignaturePrivateKey&& other);
  SignaturePrivateKey& operator=(const SignaturePrivateKey& other);
  SignaturePrivateKey& operator=(SignaturePrivateKey&& other);

  bool operator==(const SignaturePrivateKey& other) const;
  bool operator!=(const SignaturePrivateKey& other) const;

  bytes sign(const bytes& message) const;
  SignaturePublicKey public_key() const;

private:
  Scoped<EC_KEY> _key;
  SignaturePublicKey _pub;

  SignaturePrivateKey(EC_KEY* key);
};

} // namespace mls
