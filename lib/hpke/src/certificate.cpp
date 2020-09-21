#include "openssl_common.h"
#include <hpke/certificate.h>
#include <hpke/signature.h>
#include <openssl/x509.h>

namespace hpke {

///
/// Certificate X509 Impl

struct Certificate::ParsedCertificate
{

  static std::unique_ptr<Certificate::ParsedCertificate> parse(const bytes& der)
  {
    const unsigned char* buf = der.data();
    auto* cert = d2i_X509(nullptr, &buf, der.size());
    if (cert == nullptr) {
      throw openssl_error();
    }

    return  std::make_unique<Certificate::ParsedCertificate>(cert);
  }

  explicit ParsedCertificate(X509* native)
    : openssl_cert(native, typed_delete<X509>)
  {}

	ParsedCertificate(const ParsedCertificate& other)
    : openssl_cert(make_typed_unique<X509>(other.openssl_cert.get()))
  {}

  X509Signature::ID signature_algorithm() const
  {
    int algo_nid = X509_get_signature_nid(openssl_cert.get());
    switch (algo_nid) {
      case EVP_PKEY_ED25519:
        return X509Signature::ID::Ed25519;
      case EVP_PKEY_ED448:
        return X509Signature::ID::Ed448;
      default:
        // TODO (Suhas): Add support for ECDSA curves
        break;
    }
    throw std::runtime_error("signature algorithm retrieval");
  }

  X509Signature::PublicKey public_key() const
  {
    auto key = make_typed_unique<EVP_PKEY>(X509_get_pubkey(openssl_cert.get()));

    size_t raw_len = 0;
    if (1 != EVP_PKEY_get_raw_public_key(key.get(), nullptr, &raw_len)) {
      throw openssl_error();
    }

    bytes pkey(raw_len);
    auto* data_ptr = pkey.data();
    if (1 != EVP_PKEY_get_raw_public_key(key.get(), data_ptr, &raw_len)) {
      throw openssl_error();
    }

    return X509Signature::PublicKey{pkey};
  }

  typed_unique_ptr<X509> openssl_cert;
};

///
/// Certificate
///

Certificate::Certificate(const bytes& der)
  : parsed_cert(ParsedCertificate::parse(der))
  , public_key_algorithm(parsed_cert->signature_algorithm())
  , public_key(parsed_cert->public_key())
  , raw(der)
{}

Certificate::Certificate(const Certificate& other)
  : parsed_cert(ParsedCertificate::parse(other.raw))
  , public_key_algorithm(parsed_cert->signature_algorithm())
  , public_key(parsed_cert->public_key())
  , raw(other.raw)
{}

Certificate::Certificate(Certificate&& other) noexcept
  : parsed_cert(std::move(other.parsed_cert))
  , public_key_algorithm(other.public_key_algorithm)
  , public_key(other.public_key)
{}

Certificate&
Certificate::operator=(const Certificate& other)
{
  if (this == &other) {
    return *this;
  }

  // not much to do here since we have unique_ptr
  // and defining an assignment is not a good idea.
  return *this;
}

Certificate::~Certificate() = default;

} // namespace hpke
