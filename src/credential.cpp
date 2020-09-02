#include "mls/credential.h"
#include <tls/tls_syntax.h>

namespace mls {

///
/// BasicCredential
///

const CredentialType BasicCredential::type = CredentialType::basic;
const CredentialType X509Credential::type = CredentialType::x509;

tls::ostream&
operator<<(tls::ostream& str, const BasicCredential& obj)
{
  tls::vector<2>::encode(str, obj.identity);
  return str << obj.public_key.signature_scheme() << obj.public_key;
}

tls::istream&
operator>>(tls::istream& str, BasicCredential& obj)
{
  SignatureScheme scheme;
  tls::vector<2>::decode(str, obj.identity);
  str >> scheme >> obj.public_key;
  obj.public_key.set_signature_scheme(scheme);
  return str;
}

bool
operator==(const BasicCredential& lhs, const BasicCredential& rhs)
{
  return (lhs.identity == rhs.identity) && (lhs.public_key == rhs.public_key);
}

///
/// X509 Credential
///

tls::ostream&
operator<<(tls::ostream& str, const X509Credential& obj)
{
    tls::vector<2>::encode(str, obj.identity);
    return str << obj.public_key.signature_scheme() << obj.public_key;
}

tls::istream&
operator>>(tls::istream& str, X509Credential& obj)
{
    SignatureScheme scheme;
    tls::vector<2>::decode(str, obj.identity);
    str >> scheme >> obj.public_key;
    obj.public_key.set_signature_scheme(scheme);
    return str;
}

bool
operator==(const X509Credential& lhs, const X509Credential& rhs)
{
    return (lhs.identity == rhs.identity) && (lhs.public_key == rhs.public_key);
}

///
/// Credential
///

bytes
Credential::identity() const
{
  switch (_cred.index()) {
    case 0:
      return std::get<BasicCredential>(_cred).identity;
    case 1:
      // dummy identity
      return bytes{};
  }

  throw std::bad_variant_access();
}

SignaturePublicKey
Credential::public_key() const
{
  switch (_cred.index()) {
    case 0:
      return std::get<BasicCredential>(_cred).public_key;
    case 1:
      // return dummy signature
      return SignaturePublicKey();
  }

  throw std::bad_variant_access();
}

bool
Credential::valid_for(const SignaturePrivateKey& priv) const
{
  return priv.public_key() == public_key();
}

Credential
Credential::basic(const bytes& identity, const SignaturePublicKey& public_key)
{
  Credential cred;
  cred._cred = BasicCredential{ identity, public_key };
  return cred;
}

Credential
Credential::x509()
{
    Credential cred;
    //cred._cred = X509Credential{};
    return cred;
}


} // namespace mls
