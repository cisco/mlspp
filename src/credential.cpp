#include "mls/credential.h"
#include "hpke/certificate.h"
#include <tls/tls_syntax.h>

namespace mls {

///
/// BasicCredential
///

const CredentialType BasicCredential::type = CredentialType::basic;

///
/// X509Credential
///

const CredentialType X509Credential::type = CredentialType::x509;

X509Credential::X509Credential(const std::vector<X509Credential::CertData>& der_chain_in)
  : der_chain(der_chain_in)
{
  if (der_chain.empty()) {
    throw std::invalid_argument("empty certificate chain");
  }

 	// first element represents leaf cert
  hpke::Certificate cert{ der_chain_in[0].der };
  public_key = SignaturePublicKey{ cert.public_key.data };

  // TODO(Suhas) : Add verify chain logic
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
Credential::x509(const std::vector<X509Credential::CertData>& der_chain)
{
  Credential cred;
  cred._cred = X509Credential{ der_chain };
  return cred;
}

} // namespace mls
