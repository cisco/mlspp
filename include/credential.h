#pragma once

#include "common.h"
#include "crypto.h"

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
  BasicCredential()
  {}

  BasicCredential(tls::opaque<2> identity_in, SignaturePublicKey public_key_in)
    : identity(std::move(identity_in))
    , public_key(std::move(public_key_in))
  {}

  tls::opaque<2> identity;
  SignaturePublicKey public_key;

  static const CredentialType type;
};

tls::ostream&
operator<<(tls::ostream& str, const BasicCredential& obj);
tls::istream&
operator>>(tls::istream& str, BasicCredential& obj);
bool
operator==(const BasicCredential& lhs, const BasicCredential& rhs);

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
  std::optional<SignaturePrivateKey> private_key() const;
  bool valid_for(const SignaturePrivateKey& priv) const;

  static Credential basic(const bytes& identity,
                          const SignaturePublicKey& public_key);
  static Credential basic(const bytes& identity,
                          const SignaturePrivateKey& private_key);

  TLS_SERIALIZABLE(_cred)

private:
  tls::variant<CredentialType, BasicCredential> _cred;
  std::optional<SignaturePrivateKey> _priv;
};

} // namespace mls
