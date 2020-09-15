#include "hpke/certificate.h"
#include "openssl_common.h"
#include <openssl/err.h>
#include <openssl/x509.h>

namespace hpke {

///
/// Private Implementation
///
///

struct Certificate::Internals
{

  static X509* der_to_x509(const bytes& der);

  explicit Internals(const bytes& der)
    : openssl_cert(Internals::der_to_x509(der), typed_delete<X509>)
  {}

  ~Internals() = default;

  Signature::ID signature_algorithm() const;
  std::optional<bytes> public_key() const;

  typed_unique_ptr<X509> openssl_cert;
};

X509*
Certificate::Internals::der_to_x509(const bytes& der)
{
  const unsigned char* buf = der.data();
  auto* cert = d2i_X509(nullptr, &buf, der.size());
  if (cert == nullptr) {
    throw openssl_error();
  }

  return cert;
}

Certificate::Signature::ID
Certificate::Internals::signature_algorithm() const
{
  int algo_nid = X509_get_signature_nid(openssl_cert.get());
  switch (algo_nid) {
    case EVP_PKEY_ED25519:
      return Signature::ID::ED25519;
    case EVP_PKEY_ED448:
      return Signature::ID::ED448;
    default:
      // TODO (Suhas): Add support for ECDSA curves
      return Signature::ID::unknown;
  }
}

std::optional<bytes>
Certificate::Internals::public_key() const
{
  bytes public_key;
  auto algo = signature_algorithm();
  switch (algo) {
    case Signature::ID::ED448:
    case Signature::ID::ED25519: {
      auto key =
        make_typed_unique<EVP_PKEY>(X509_get_pubkey(openssl_cert.get()));
      size_t raw_len = 0;
      if (1 != EVP_PKEY_get_raw_public_key(key.get(), nullptr, &raw_len)) {
        break;
      }
      public_key.resize(raw_len);
      auto* data_ptr = public_key.data();
      if (1 != EVP_PKEY_get_raw_public_key(key.get(), data_ptr, &raw_len)) {
        break;
      }
      return public_key;
    }
    default:
      // todo: add support for ecdsa curves
      break;
  }

  return std::nullopt;
}

///
/// Certificate API
///

Certificate::Certificate() = default;

Certificate::Certificate(const bytes& der)
  : internal(new Internals(der))
{
  signature.pkey.data = internal->public_key().value();
  signature.algorithm = internal->signature_algorithm();
}

Certificate::~Certificate() = default;

Certificate::Signature::ID
Certificate::signature_algorithm() const
{
  return signature.algorithm;
}

Certificate::Signature::PublicKey
Certificate::public_key() const
{
  return signature.pkey;
}

} // namespace hpke
