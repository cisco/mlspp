#pragma once

#include "common.h"
#include "crypto.h"
#include <iosfwd>

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

  Credential(const Credential& other);
  Credential(Credential&& other);
  Credential& operator=(const Credential& other);

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

} // namespace mls
