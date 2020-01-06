#include "credential.h"
#include "tls_syntax.h"

namespace mls {

///
/// BasicCredential
///

const CredentialType BasicCredential::type = CredentialType::basic;

tls::ostream&
operator<<(tls::ostream& str, const BasicCredential& obj)
{
  return str << obj.identity << obj.public_key.signature_scheme()
             << obj.public_key;
}

tls::istream&
operator>>(tls::istream& str, BasicCredential& obj)
{
  SignatureScheme scheme;
  str >> obj.identity >> scheme >> obj.public_key;
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

std::optional<SignaturePrivateKey>
Credential::private_key() const
{
  return _priv;
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
Credential::basic(const bytes& identity, const SignaturePrivateKey& private_key)
{
  auto cred = basic(identity, private_key.public_key());
  cred._priv = private_key;
  return cred;
}

} // namespace mls
