#include <hpke/certificate.h>
#include <hpke/signature.h>
#include "openssl_common.h"
#include <openssl/x509.h>

namespace hpke {

///
/// Certificate X509 Impl


struct Certificate::Internals
{

	static X509* parse(const bytes& der)
  {
  	const unsigned char* buf = der.data();
		auto* cert = d2i_X509(nullptr, &buf, der.size());
		if (cert == nullptr) {
			throw openssl_error();
		}

		return cert;
  }

  explicit Internals(const bytes& der_in)
    : openssl_cert(parse(der_in), typed_delete<X509>){}

  Signature::ID signature_algorithm() const
  {
		int algo_nid = X509_get_signature_nid(openssl_cert.get());
		switch (algo_nid) {
			case EVP_PKEY_ED25519:
				return Signature::ID::Ed25519;
			case EVP_PKEY_ED448:
				return Signature::ID::Ed448;
			default:
				// TODO (Suhas): Add support for ECDSA curves
				break;
		}
		throw std::runtime_error("signature algorithm retrieval");
  }

  bytes public_key() const {
    auto algo = signature_algorithm();
		switch (algo) {
			case Signature::ID::Ed448:
			case Signature::ID::Ed25519: {
				auto key =
								make_typed_unique<EVP_PKEY>(X509_get_pubkey(openssl_cert.get()));
				size_t raw_len = 0;
				if (1 != EVP_PKEY_get_raw_public_key(key.get(), nullptr, &raw_len)) {
					throw openssl_error();
				}
				bytes pkey(raw_len);
				auto* data_ptr = pkey.data();
				if (1 != EVP_PKEY_get_raw_public_key(key.get(), data_ptr, &raw_len)) {
					throw openssl_error();
				}
				return pkey;
			}

			default:
				// todo: add support for ecdsa curves
				break;
		}
		throw openssl_error();
  }

	typed_unique_ptr<X509> openssl_cert;
};


///
/// Certificate
///

Certificate::Certificate(const bytes &der)
  : internals(std::make_unique<Internals>(der)),
    public_key_algorithm(internals->signature_algorithm()),
    raw(der)
{}

Certificate::Certificate(const Certificate&)
  : internals(nullptr)
  , public_key_algorithm(Signature::ID::Ed25519)
{} // XXX

Certificate::Certificate(Certificate&& other) = default;

Certificate&
Certificate::operator=(const Certificate&)
{
  return *this; // XXX
}

Certificate::~Certificate() = default;


} // namespace hpke
