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
  BasicCredential() = default;

  explicit BasicCredential(bytes identity_in)
    : identity(std::move(identity_in))
  {
  }

  bytes identity;

  TLS_SERIALIZABLE(identity)
};

struct X509Credential
{
  struct CertData
  {
    bytes data;

    TLS_SERIALIZABLE(data)
  };

  X509Credential() = default;
  explicit X509Credential(const std::vector<bytes>& der_chain_in);

  SignatureScheme signature_scheme() const;
  SignaturePublicKey public_key() const;
  bool valid_for(const SignaturePublicKey& pub) const;

  // TODO(rlb) This should be const or exposed via a method
  std::vector<CertData> der_chain;

private:
  SignaturePublicKey _public_key;
  SignatureScheme _signature_scheme;
};

struct UserInfoVCCredential
{
  UserInfoVCCredential() = default;

  explicit UserInfoVCCredential(bytes userinfo_vc_jwt)
    : userinfo_vc_jwt(std::move(userinfo_vc_jwt))
  {
  }

  bytes userinfo_vc_jwt;

  TLS_SERIALIZABLE(userinfo_vc_jwt)
};

tls::ostream&
operator<<(tls::ostream& str, const X509Credential& obj);

tls::istream&
operator>>(tls::istream& str, X509Credential& obj);

bool
operator==(const X509Credential& lhs, const X509Credential& rhs);

enum struct CredentialType : uint16_t
{
  reserved = 0,
  basic = 1,
  x509 = 2,
  userinfo_vc = 3,

  // GREASE values, included here mainly so that debugger output looks nice
  GREASE_0 = 0x0A0A,
  GREASE_1 = 0x1A1A,
  GREASE_2 = 0x2A2A,
  GREASE_3 = 0x3A3A,
  GREASE_4 = 0x4A4A,
  GREASE_5 = 0x5A5A,
  GREASE_6 = 0x6A6A,
  GREASE_7 = 0x7A7A,
  GREASE_8 = 0x8A8A,
  GREASE_9 = 0x9A9A,
  GREASE_A = 0xAAAA,
  GREASE_B = 0xBABA,
  GREASE_C = 0xCACA,
  GREASE_D = 0xDADA,
  GREASE_E = 0xEAEA,
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

  template<typename T>
  const T& get() const
  {
    return var::get<T>(_cred);
  }

  static Credential basic(const bytes& identity);
  static Credential x509(const std::vector<bytes>& der_chain);
  static Credential userinfo_vc(const bytes& userinfo_vc_jwt);

  bool valid_for(const SignaturePublicKey& pub) const;

  TLS_SERIALIZABLE(_cred)
  TLS_TRAITS(tls::variant<CredentialType>)

private:
  var::variant<BasicCredential, X509Credential, UserInfoVCCredential> _cred;
};

} // namespace mls

namespace tls {

TLS_VARIANT_MAP(mls::CredentialType, mls::BasicCredential, basic)
TLS_VARIANT_MAP(mls::CredentialType, mls::X509Credential, x509)
TLS_VARIANT_MAP(mls::CredentialType, mls::UserInfoVCCredential, userinfo_vc)

} // namespace TLS
