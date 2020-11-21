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
  }
  throw InvalidParameterError("Unsupported algorithm");
}

X509Credential::X509Credential(
  std::vector<X509Credential::CertData> der_chain_in)
  : der_chain(std::move(der_chain_in))
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
  const auto& sig = find_signature(parsed[0].public_key_algorithm);
  const auto pub_data = sig.serialize(*parsed[0].public_key);
  _signature_scheme = tls_signature_scheme(parsed[0].public_key_algorithm);
  _public_key = SignaturePublicKey{ pub_data };

  // verify chain for valid signatures
  for (size_t i = 0; i < der_chain.size() - 1; i++) {
    if (!parsed[i].valid_from(parsed[i + 1])) {
      throw std::runtime_error("Certificate Chain validation failure");
    }
  }
}

SignaturePublicKey
X509Credential::public_key() const
{
  return _public_key;
}

tls::ostream&
operator<<(tls::ostream& str, const X509Credential& obj)
{
  tls::vector<4>::encode(str, obj.der_chain);
  return str;
}

tls::istream&
operator>>(tls::istream& str, X509Credential& obj)
{
  auto der_chain = std::vector<X509Credential::CertData>{};
  tls::vector<4>::decode(str, der_chain);
  obj = X509Credential(der_chain);
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
#if 0
  static const auto get_type = overloaded{
    [](const BasicCredential& /* unused */) {
      return CredentialType::basic;
    },
    [](const X509Credential& /* unused */) {
      return CredentialType::x509;
    },
  };
#endif

  static const auto get_type = [](const auto& v) {
    return tls::variant_map<CredentialType, std::decay_t<decltype(v)>>();
  };
  return var::visit(get_type, _cred);
}

SignaturePublicKey
Credential::public_key() const
{
  static const auto get_public_key = overloaded{
    [](const BasicCredential& cred) { return cred.public_key; },
    [](const X509Credential& cred) { return cred.public_key(); },
  };
  return var::visit(get_public_key, _cred);
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
