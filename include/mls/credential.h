#pragma once

#include <memory>
#include "mls/common.h"
#include "mls/crypto.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

// struct {
//     opaque identity<0..2^16-1>;
//     SignatureScheme algorithm;
//     SignaturePublicKey public_key;
// } BasicCredential;
struct BasicCredential
{
  BasicCredential() {}

  BasicCredential(bytes identity_in, SignaturePublicKey public_key_in)
    : identity(std::move(identity_in))
    , public_key(std::move(public_key_in))
  {}

  bytes identity;
  SignaturePublicKey public_key;

  static const CredentialType type;
};

tls::ostream&
operator<<(tls::ostream& str, const BasicCredential& obj);
tls::istream&
operator>>(tls::istream& str, BasicCredential& obj);
bool
operator==(const BasicCredential& lhs, const BasicCredential& rhs);

///
/// X509 Credential
///

using X509_ptr = std::shared_ptr<X509>;
// case x509:
//     opaque cert_data<1..2^24-1>;
struct X509Credential
{

  X509Credential() {}
  X509Credential(const std::vector<X509_ptr>& chain_in);

  std::vector<X509_ptr> chain;
  SignaturePublicKey public_key;
  bytes identity;
  SignaturePublicKey scheme_;
  static const CredentialType type;
};

tls::ostream&
operator<<(tls::ostream& str, const X509Credential& obj);
tls::istream&
operator>>(tls::istream& str, X509Credential& obj);
bool
operator==(const X509Credential& lhs, const X509Credential& rhs);

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
  bytes identity() const;
  SignaturePublicKey public_key() const;
  bool valid_for(const SignaturePrivateKey& priv) const;

  static Credential basic(const bytes& identity,
                          const SignaturePublicKey& public_key);

  static Credential x509(const std::vector<X509_ptr>& chain);

  TLS_SERIALIZABLE(_cred)
  TLS_TRAITS(tls::variant<CredentialType>)

private:
  std::variant<BasicCredential, X509Credential> _cred;
};

} // namespace mls
