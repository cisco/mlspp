#pragma once

#include "common.h"
#include "crypto.h"
#include "tls_syntax.h"
#include <iosfwd>

#define DUMMY_SIG_SCHEME SignatureScheme::P256_SHA256

namespace mls {

// enum {
//     basic(0),
//     x509(1),
//     (255)
// } CredentialType;
enum struct CredentialType : uint8_t
{
  basic = 0,
  x509 = 1,
};

struct AbstractCredential
{
  virtual ~AbstractCredential() {}
  virtual std::unique_ptr<AbstractCredential> dup() const = 0;
  virtual bytes identity() const = 0;
  virtual SignaturePublicKey public_key() const = 0;
  virtual void read(tls::istream& in) = 0;
  virtual void write(tls::ostream& out) const = 0;
  virtual bool equal(const AbstractCredential* other) const = 0;
};

// struct {
//     opaque identity<0..2^16-1>;
//     SignatureScheme algorithm;
//     SignaturePublicKey public_key;
// } BasicCredential;
class BasicCredential : public AbstractCredential
{
public:
  BasicCredential()
    : _public_key(DUMMY_SIG_SCHEME)
  {}

  BasicCredential(const bytes& identity, const SignaturePublicKey& public_key)
    : _identity(identity)
    , _public_key(public_key)
  {}

  virtual std::unique_ptr<AbstractCredential> dup() const;
  virtual bytes identity() const;
  virtual SignaturePublicKey public_key() const;
  virtual void read(tls::istream& in);
  virtual void write(tls::ostream& out) const;
  virtual bool equal(const AbstractCredential* other) const;

private:
  tls::opaque<2> _identity;
  SignaturePublicKey _public_key;
};

// struct {
//     CredentialType credential_type;
//     select (credential_type) {
//         case basic:
//             BasicCredential;
//
//         case x509:
//             opaque cert_data<1..2^24-1>;
//     };
// } Credential;
class Credential
{
public:
  Credential() = default;

  Credential(const Credential& other)
    : _type(other._type)
    , _cred(nullptr)
  {
    if (other._cred) {
      _cred = other._cred->dup();
    }
  }

  Credential(Credential&& other)
    : _type(other._type)
    , _cred(nullptr)
  {
    if (other._cred) {
      _cred.reset(other._cred.release());
    }
  }

  Credential& operator=(const Credential& other)
  {
    if (this != &other) {
      _type = other._type;
      _cred.reset(nullptr);
      if (other._cred) {
        _cred = other._cred->dup();
      }
    }
    return *this;
  }

  bytes identity() const;
  SignaturePublicKey public_key() const;
  bool valid_for(const SignaturePrivateKey& priv) const;

  static Credential basic(const bytes& identity,
                          const SignaturePublicKey& public_key);
  static Credential basic(const bytes& identity,
                          const SignaturePrivateKey& private_key);

private:
  CredentialType _type;
  std::unique_ptr<AbstractCredential> _cred;

  static AbstractCredential* create(CredentialType type);

  friend bool operator==(const Credential& lhs, const Credential& rhs);
  friend bool operator!=(const Credential& lhs, const Credential& rhs);
  friend tls::ostream& operator<<(tls::ostream& out, const Credential& obj);
  friend tls::istream& operator>>(tls::istream& in, Credential& obj);
};

// XXX(rlb@ipv.sx): We have to subclass optional<T> in order to
// ensure that credentials are populated with blank values on
// unmarshal.  Otherwise, `*opt` will access uninitialized memory.
class OptionalCredential : public optional<Credential>
{
public:
  typedef optional<Credential> parent;
  using parent::parent;

  OptionalCredential()
    : parent(Credential())
  {}
};

bool
operator==(const OptionalCredential& lhs, const OptionalCredential& rhs);

class Roster
{
public:
  void add(const Credential& cred);
  void remove(uint32_t index);
  Credential get(uint32_t index) const;
  size_t size() const;
  void truncate(uint32_t size);

private:
  tls::vector<OptionalCredential, 4> _credentials;

  friend bool operator==(const Roster& lhs, const Roster& rhs);
  friend tls::ostream& operator<<(tls::ostream& out, const Roster& obj);
  friend tls::istream& operator>>(tls::istream& in, Roster& obj);
};

} // namespace mls
