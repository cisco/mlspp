#pragma once

#include <mls/common.h>
#include <mls/crypto.h>

namespace mls {

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
};

struct X509Credential
{
  struct CertData
  {
    bytes data;

    TLS_SERIALIZABLE(data)
    TLS_TRAITS(tls::vector<2>)
  };

  X509Credential() = default;
  explicit X509Credential(const std::vector<bytes>& der_chain_in);

  SignaturePublicKey public_key() const;

  // TODO(rlb) This should be const or exposed via a method
  std::vector<CertData> der_chain;

private:
  SignaturePublicKey _public_key;
  SignatureScheme _signature_scheme;

  friend struct KeyPackage;
};

tls::ostream&
operator<<(tls::ostream& str, const X509Credential& obj);

tls::istream&
operator>>(tls::istream& str, X509Credential& obj);

bool
operator==(const X509Credential& lhs, const X509Credential& rhs);

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
  CredentialType type() const;
  SignaturePublicKey public_key() const;
  bool valid_for(const SignaturePrivateKey& priv) const;

  template<typename T>
  const T& get() const
  {
    return var::get<T>(_cred);
  }

  static Credential basic(const bytes& identity,
                          const SignaturePublicKey& public_key);

  static Credential x509(const std::vector<bytes>& der_chain);

  TLS_SERIALIZABLE(_cred)
  TLS_TRAITS(tls::variant<CredentialType>)

private:
  var::variant<BasicCredential, X509Credential> _cred;
};

} // namespace mls

namespace tls {

using namespace mls;

TLS_VARIANT_MAP(CredentialType, BasicCredential, basic)
TLS_VARIANT_MAP(CredentialType, X509Credential, x509)

} // namespace TLS
