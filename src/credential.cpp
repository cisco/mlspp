#include "mls/credential.h"
#include <tls/tls_syntax.h>

namespace mls {

///
/// BasicCredential
///

const CredentialType BasicCredential::type = CredentialType::basic;
const CredentialType X509Credential::type = CredentialType::x509;

///
/// X509Credential
///

X509Credential::X509Credential(const std::vector<bytes>& der_chain_in)
{
  if (der_chain_in.empty()) {
    throw std::invalid_argument("empty certificate chain");
  }

  der_chain = der_chain_in;
  // zeroth element represents leaf cert
  hpke::Certificate cert{der_chain_in[0]};
  public_key = SignaturePublicKey{ cert.public_key.data };
}

///
/// X509 Credential
///

struct Bytes2 {
	bytes vec;
	TLS_SERIALIZABLE(vec);
	TLS_TRAITS(tls::vector<2>)
};

tls::ostream&
operator<<(tls::ostream& str, const X509Credential& obj)
{
	tls::ostream temp;
	for (const auto& item : obj.der_chain) {
		Bytes2 b {item};
		temp << b;
	}

	// concatenate all certs
	bytes allCerts;
	uint8_t depth = obj.der_chain.size();
	str << depth;
	tls::vector<4>::encode(str, temp.bytes());
	return str << obj.public_key;
}

tls::istream&
operator>>(tls::istream& str, X509Credential& obj)
{
  uint8_t depth = 0;
  str >> depth;

  bytes allCerts;
	tls::vector<4>::decode(str, allCerts);

	obj.der_chain.resize(depth);
	str >> obj.public_key;

	tls::istream temp(allCerts);
  for (int i = 0; i < depth; i++) {
  	Bytes2 b;
  	temp >> b;
  	obj.der_chain[i] = b.vec;
  }

	return str;
}

bool
operator==(const X509Credential& lhs, const X509Credential& rhs)
{
	return (lhs.der_chain.size() == rhs.der_chain.size()) && (lhs.public_key == rhs.public_key);
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
Credential::x509(const std::vector<bytes>& der_chain)
{
  Credential cred;
  cred._cred = X509Credential{ der_chain };
  return cred;
}

} // namespace mls
