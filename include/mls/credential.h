#pragma once

#include "hpke/certificate.h"
#include "mls/common.h"
#include "mls/crypto.h"
#include <memory>

using namespace hpke;

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

  TLS_SERIALIZABLE(identity, public_key)
  TLS_TRAITS(tls::vector<2>, tls::pass)

  static const CredentialType type;
};

///
/// X509 Credential
///

// case x509:
//     opaque cert_data<1..2^24-1>;
struct X509Credential
{
  X509Credential() {}

	explicit X509Credential(const std::vector<bytes>& raw_chain);

  std::vector<Certificate> chain;
  SignaturePublicKey public_key;

  TLS_SERIALIZABLE(public_key)

  static const CredentialType type;
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
  bytes identity() const;
  SignaturePublicKey public_key() const;

  bool valid_for(const SignaturePrivateKey& priv) const;

  static Credential basic(const bytes& identity,
                          const SignaturePublicKey& public_key);

  static Credential x509(const std::vector<bytes>& chain);

  TLS_SERIALIZABLE(_cred)
  TLS_TRAITS(tls::variant<CredentialType>)

private:
  std::variant<BasicCredential, X509Credential> _cred;
};

} // namespace mls
