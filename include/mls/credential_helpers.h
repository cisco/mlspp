#pragma once

#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/objects.h>

namespace mls {

// Helpers to parse various things out of X509 certificate and
// map them to internal types
// TODO: refactor this into its X509Lib class

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

SignatureScheme cert_export_signature_algorithm(X509* cert) {
  int algo_nid = X509_get_signature_nid(cert);
  switch (algo_nid) {
    case EVP_PKEY_ED25519:
      return SignatureScheme::Ed25519;
    case EVP_PKEY_ED448:
      return SignatureScheme::Ed448;
    case EVP_PKEY_EC:
      // todo:how to extract curve specific NIDs
      return SignatureScheme::unknown;
  }
  return SignatureScheme::unknown;
}

SignaturePublicKey cert_export_public_key(X509* cert) {
  SignaturePublicKey public_key;

  auto scheme = cert_export_signature_algorithm(cert);

  switch (scheme) {
    case SignatureScheme::Ed448:
    case SignatureScheme::Ed25519: {
      EVP_PKEY_ptr key (X509_get_pubkey(cert), ::EVP_PKEY_free);
      size_t raw_len = 0;
      if (1 != EVP_PKEY_get_raw_public_key(key.get(), nullptr, &raw_len)) {
        break;
      }
      bytes raw(raw_len);
      uint8_t* data_ptr = raw.data();
      if (1 != EVP_PKEY_get_raw_public_key(key.get(), data_ptr, &raw_len)) {
        break;
      }
      public_key = {scheme, raw};
      break;
    }
    default:
      // todo: add support for other signature schemes
      break;
  }
  return public_key;
}

bytes cert_export_subject(X509* cert) {
  std::string subject((X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0)));
  auto ret = bytes(subject.begin(), subject.end());
  return ret;
}

}