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

X509Credential::X509Credential(const std::vector<bytes>& chain_in)
{
  if (chain_in.empty()) {
    throw InvalidParameterError("x509 credential: empty cert chain");
  }

  chain.resize(chain_in.size());
  for (size_t i = 0; i < chain_in.size(); i++) {
    auto p =
      std::shared_ptr<X509Certificate>(X509Certificate::get(chain_in[i]));
    chain[i] = std::move(p);
  }

  // chain[0] is the leaf cert
  public_key.data = chain[0]->public_key();
  identity = chain[0]->subject_name();
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
      return std::get<X509Credential>(_cred).identity;
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
