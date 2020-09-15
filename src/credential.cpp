#include "mls/credential.h"
#include <tls/tls_syntax.h>

namespace mls {

///
/// BasicCredential
///

const CredentialType BasicCredential::type = CredentialType::basic;
const CredentialType X509Credential::type = CredentialType::x509;

///
/// X509 Credential
///

X509Credential::X509Credential(const std::vector<bytes>& raw_chain)
{
  if (raw_chain.empty()) {
    throw InvalidParameterError("x509 credential: empty cert chain");
  }

  for (const auto& der : raw_chain) {
    chain.push_back(std::shared_ptr<Certificate>(new Certificate(der)));
  }
  public_key.data = chain[0]->public_key().data;
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
    case 1:
      return std::get<X509Credential>(_cred).public_key;
  }

  throw std::bad_variant_access();
}

bool
Credential::valid_for(const SignaturePrivateKey& priv) const
{
  return priv.public_key == public_key();
}

Credential
Credential::basic(const bytes& identity, const SignaturePublicKey& public_key)
{
  Credential cred;
  cred._cred = BasicCredential{ identity, public_key };
  return cred;
}

Credential
Credential::x509(const std::vector<bytes>& chain)
{
  Credential cred;
  cred._cred = X509Credential{ chain };
  return cred;
}

} // namespace mls
