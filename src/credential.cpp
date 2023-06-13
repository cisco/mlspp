#include "mls/credential.h"
#include "hpke/certificate.h"
#include <tls/tls_syntax.h>

namespace mls {

///
/// X509Credential
///

using hpke::Certificate; // NOLINT(misc-unused-using-decls)
using hpke::Signature;   // NOLINT(misc-unused-using-decls)

static const Signature&
find_signature(Signature::ID id)
{
  switch (id) {
    case Signature::ID::P256_SHA256:
      return Signature::get<Signature::ID::P256_SHA256>();
    case Signature::ID::P384_SHA384:
      return Signature::get<Signature::ID::P384_SHA384>();
    case Signature::ID::P521_SHA512:
      return Signature::get<Signature::ID::P521_SHA512>();
    case Signature::ID::Ed25519:
      return Signature::get<Signature::ID::Ed25519>();
    case Signature::ID::Ed448:
      return Signature::get<Signature::ID::Ed448>();
    case Signature::ID::RSA_SHA256:
      return Signature::get<Signature::ID::RSA_SHA256>();
    default:
      throw InvalidParameterError("Unsupported algorithm");
  }
}

static std::vector<X509Credential::CertData>
bytes_to_x509_credential_data(const std::vector<bytes>& data_in)
{
  return stdx::transform<X509Credential::CertData>(
    data_in, [](const bytes& der) { return X509Credential::CertData{ der }; });
}

X509Credential::X509Credential(const std::vector<bytes>& der_chain_in)
  : der_chain(bytes_to_x509_credential_data(der_chain_in))
{
  if (der_chain.empty()) {
    throw std::invalid_argument("empty certificate chain");
  }

  // Parse the chain
  auto parsed = std::vector<Certificate>();
  for (const auto& cert : der_chain) {
    parsed.emplace_back(cert.data);
  }

  // first element represents leaf cert
  const auto& sig = find_signature(parsed[0].public_key_algorithm());
  const auto pub_data = sig.serialize(*parsed[0].public_key);
  _signature_scheme = tls_signature_scheme(parsed[0].public_key_algorithm());
  _public_key = SignaturePublicKey{ pub_data };

  // verify chain for valid signatures
  for (size_t i = 0; i < der_chain.size() - 1; i++) {
    if (!parsed[i].valid_from(parsed[i + 1])) {
      throw std::runtime_error("Certificate Chain validation failure");
    }
  }
}

SignatureScheme
X509Credential::signature_scheme() const
{
  return _signature_scheme;
}

SignaturePublicKey
X509Credential::public_key() const
{
  return _public_key;
}

bool
X509Credential::valid_for(const SignaturePublicKey& pub) const
{
  return pub == public_key();
}

tls::ostream&
operator<<(tls::ostream& str, const X509Credential& obj)
{
  return str << obj.der_chain;
}

tls::istream&
operator>>(tls::istream& str, X509Credential& obj)
{
  auto der_chain = std::vector<X509Credential::CertData>{};
  str >> der_chain;

  auto der_in = stdx::transform<bytes>(
    der_chain, [](const auto& cert_data) { return cert_data.data; });
  obj = X509Credential(der_in);

  return str;
}

bool
operator==(const X509Credential& lhs, const X509Credential& rhs)
{
  return lhs.der_chain == rhs.der_chain;
}

///
/// Credential
///

CredentialType
Credential::type() const
{
  return tls::variant<CredentialType>::type(_cred);
}

Credential
Credential::basic(const bytes& identity)
{
  Credential cred;
  cred._cred = BasicCredential{ identity };
  return cred;
}

Credential
Credential::x509(const std::vector<bytes>& der_chain)
{
  Credential cred;
  cred._cred = X509Credential{ der_chain };
  return cred;
}

Credential
Credential::userinfo_vc(const bytes& userinfo_vc_jwt)
{
  Credential cred;
  cred._cred = UserInfoVCCredential{ userinfo_vc_jwt };
  return cred;
}

bool
Credential::valid_for(const SignaturePublicKey& pub) const
{
  const auto pub_key_match = overloaded{
    [&](const X509Credential& x509) { return x509.valid_for(pub); },

    [](const BasicCredential& /* basic */) { return true; },

    [](const UserInfoVCCredential&) { return true; },
  };

  return var::visit(pub_key_match, _cred);
}

} // namespace mls
