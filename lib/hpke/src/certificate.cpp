#include <hpke/certificate.h>
#include <hpke/signature.h>
#include <openssl/x509.h>

#include "group.h"
#include "openssl_common.h"

namespace hpke {

///
/// Certificate X509 Impl
///

struct Certificate::ParsedCertificate
{

  static std::unique_ptr<ParsedCertificate> parse(const bytes& der)
  {
    const auto* buf = der.data();
    auto cert = make_typed_unique(d2i_X509(nullptr, &buf, der.size()));
    if (cert == nullptr) {
      throw openssl_error();
    }

    return std::make_unique<ParsedCertificate>(cert.release());
  }

  explicit ParsedCertificate(X509* x509_in)
    : x509(x509_in, typed_delete<X509>)
    , sig_id(signature_algorithm(x509.get()))
  {}

  ParsedCertificate(const ParsedCertificate& other)
    : x509(nullptr, typed_delete<X509>)
    , sig_id(signature_algorithm(other.x509.get()))
  {
    if (1 != X509_up_ref(other.x509.get())) {
      throw openssl_error();
    }
    x509.reset(other.x509.get());
  }

  static Signature::ID signature_algorithm(X509* cert)
  {
    switch (X509_get_signature_nid(cert)) {
      case EVP_PKEY_ED25519:
        return Signature::ID::Ed25519;
      case EVP_PKEY_ED448:
        return Signature::ID::Ed448;
      default:
        // TODO (Suhas): Add support for ECDSA curves
        break;
    }
    throw std::runtime_error("Unsupported signature algorithm");
  }

  typed_unique_ptr<EVP_PKEY> public_key() const
  {
    return make_typed_unique<EVP_PKEY>(X509_get_pubkey(x509.get()));
  }

  typed_unique_ptr<X509> x509;
  const Signature::ID sig_id;
};

///
/// Certificate
///

Certificate::Certificate(const bytes& der)
  : parsed_cert(ParsedCertificate::parse(der))
  , public_key_algorithm(parsed_cert->sig_id)
  , public_key(std::make_unique<EVPGroup::PublicKey>(
      parsed_cert->public_key().release()))
  , raw(der)
{}

Certificate::Certificate(const Certificate& other)
  : parsed_cert(std::make_unique<ParsedCertificate>(*other.parsed_cert))
  , public_key_algorithm(parsed_cert->sig_id)
  , public_key(std::make_unique<EVPGroup::PublicKey>(
      parsed_cert->public_key().release()))
  , raw(other.raw)
{}

Certificate::~Certificate() = default;

bool
Certificate::valid_from(const Certificate& parent)
{
  auto pub = parent.parsed_cert->public_key();
  return (1 == X509_verify(parsed_cert->x509.get(), pub.get()));
}

} // namespace hpke
