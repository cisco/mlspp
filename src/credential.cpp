#include "credential.h"
#include "tls_syntax.h"

namespace tls {

///
/// CredentialType
///

template<>
inline mls::CredentialType
  variant_value<mls::CredentialType, mls::BasicCredential> =
    mls::CredentialType::basic;

} // namespace tls

namespace mls {

///
/// BasicCredential
///

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
/// Credential
///

bytes
Credential::identity() const
{
  switch (_cred.index()) {
    case 0:
      return std::get<BasicCredential>(_cred).identity;
  }

  throw std::bad_variant_access();
}

SignaturePublicKey
Credential::public_key() const
{
  switch (_cred.index()) {
    case 0:
      return std::get<BasicCredential>(_cred).public_key;
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

} // namespace mls
