#include "mls/x509_cert_helper.h"
#include "openssl/asn1.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/objects.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace mls {

///
/// OpenSSL X509 Certificate
///

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&::X509_free)>;

static std::runtime_error
openssl_error()
{
	uint64_t code = ERR_get_error();
	return std::runtime_error(ERR_error_string(code, nullptr));
}


struct OpenSSLCertificate : public X509Certificate {
	explicit OpenSSLCertificate(bytes cert_in) {
		cert_raw = std::move(cert_in);
		const unsigned char *buf = cert_raw.data();
		certificate_ptr = d2i_X509(nullptr, &buf, cert_raw.size());
		if (certificate_ptr == nullptr) {
			throw openssl_error();
		}
	}

	bool verify() const override
	{
	  return false;
	}

	bytes public_key() const override
	{
		return bytes();
	}

	bytes subject_name() const override
	{
		return bytes();
	}

private:
	bytes cert_raw;
	X509* certificate_ptr;
};

std::unique_ptr<X509Certificate>
X509Certificate::get(const bytes& cert_in)
{
	// default to openSSL for now unless we support
	// different types
	return std::make_unique<OpenSSLCertificate>(cert_in);
}

SignatureAlgorithm
cert_export_signature_algorithm(X509* cert)
{
	int algo_nid = X509_get_signature_nid(cert);
	switch (algo_nid) {
		case EVP_PKEY_ED25519:
			return SignatureAlgorithm::ED25519;
		case EVP_PKEY_ED448:
			return SignatureAlgorithm::ED448;
		default:
			return SignatureAlgorithm::unknown;
	}
}

bytes
cert_export_public_key(X509* cert)
{
	bytes public_key;
	auto algo = cert_export_signature_algorithm(cert);
	switch (algo) {
	case mls::SignatureAlgorithm::ED448:
	case mls::SignatureAlgorithm::ED25519:
		{
	    EVP_PKEY_ptr key(X509_get_pubkey(cert), ::EVP_PKEY_free);
	    size_t raw_len = 0;
	    if (1 != EVP_PKEY_get_raw_public_key(key.get(), nullptr, &raw_len))
	    {
	      break;
      }
			public_key.resize(raw_len);
      uint8_t* data_ptr = public_key.data();
      if (1 != EVP_PKEY_get_raw_public_key(key.get(), data_ptr, &raw_len))
      {
   	    break;
      }
			return public_key;
	  }
  default:
    // todo: add support for other signature schemes
    break;
  }

  return public_key;
}

bytes
cert_export_subject(X509* cert)
{
	std::string subject(
					(X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0)));
	auto ret = bytes(subject.begin(), subject.end());
	return ret;
}



} // namespace mls
