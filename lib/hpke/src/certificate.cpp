#include <cstring>
#include <hpke/certificate.h>
#include <hpke/signature.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "group.h"
#include "openssl_common.h"

namespace hpke {

///
/// ParsedCertificate
///

struct ParsedSANInfo
{
  std::vector<std::string> email_addresses;
  std::vector<std::string> domains;
};

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

  // Parse Subject Key Identifier Extension
  static std::string parse_skid(X509* cert)
  {
    int loc = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);
    auto* ext = X509_get_ext(cert, loc);
    std::string skid;
    if (ext != nullptr) {
      auto* ext_value = X509_EXTENSION_get_data(ext);
      const auto* octet_str_data = ext_value->data;
      // NOLINTNEXTLINE(google-runtime-int)
      long xlen = 0;
      int tag = 0;
      int xclass = 0;
      int ret = ASN1_get_object(
        &octet_str_data, &xlen, &tag, &xclass, ext_value->length);
      if (ret == -1) {
        throw openssl_error();
      }
      auto kid = std::make_unique<char*>(hex_to_string(octet_str_data, xlen));
      if (kid == nullptr) {
        throw openssl_error();
      }
      skid.assign(*kid);
    }
    return skid;
  }

  // Parse Authority Key Identifier
  static std::string parse_akid(X509* cert)
  {
    int loc = X509_get_ext_by_NID(cert, NID_authority_key_identifier, -1);
    auto* ext = X509_get_ext(cert, loc);
    std::string akid;
    if (ext != nullptr) {
      auto ext_value = make_typed_unique(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<AUTHORITY_KEYID*>(X509V3_EXT_d2i(ext)));
      auto* key_id = ext_value->keyid;
      auto kid =
        std::make_unique<char*>(hex_to_string(key_id->data, key_id->length));
      if (kid == nullptr) {
        throw openssl_error();
      }
      akid.assign(*kid);
    }
    return akid;
  }

  static ParsedSANInfo parse_san(X509* cert)
  {
    ParsedSANInfo san_info;
    int san_names_nb = -1;
    STACK_OF(GENERAL_NAME)* san_names = nullptr;

    // Try to extract the names within the SAN extension from the certificate
    san_names = static_cast<STACK_OF(GENERAL_NAME)*>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (san_names == nullptr) {
      return san_info;
    }
    san_names_nb = sk_GENERAL_NAME_num(san_names);

    // Check each name within the extension
    for (int i = 0; i < san_names_nb; i++) {
      const GENERAL_NAME* current_name = sk_GENERAL_NAME_value(san_names, i);

      if (current_name->type == GEN_DNS) {
        // NOLINTNEXTLINE (cppcoreguidelines-pro-type-cstyle-cast)
        const char* dns_name = (const char*)(ASN1_STRING_get0_data(
          current_name->d.dNSName)); // NOLINT

        // Make sure there isn't an embedded NUL character in the DNS name
        if (ASN1_STRING_length(current_name->d.dNSName) != // NOLINT
            static_cast<int>(strlen(dns_name))) {
          throw std::runtime_error("Malformed certificate");
        }
        san_info.domains.emplace_back(std::string(dns_name));
      } else if (current_name->type == GEN_EMAIL) {
        const char* email =
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
          (const char*)ASN1_STRING_get0_data(current_name->d.dNSName); // NOLINT

        // Make sure there isn't an embedded NUL character in the DNS name
        if (ASN1_STRING_length(current_name->d.dNSName) != // NOLINT
            static_cast<int>(strlen(email))) {
          throw std::runtime_error("Malformed certificate");
        }
        san_info.email_addresses.emplace_back(email);
      }
    }

    // Clean up
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return san_info;
  }

  explicit ParsedCertificate(X509* x509_in)
    : x509(x509_in, typed_delete<X509>)
    , sig_id(signature_algorithm(x509.get()))
    , issuer(X509_NAME_oneline(X509_get_issuer_name(x509_in), nullptr, 0))
    , subject(X509_NAME_oneline(X509_get_subject_name(x509_in), nullptr, 0))
    , skID(parse_skid(x509.get()))
    , akID(parse_akid(x509.get()))
    , san_info(parse_san(x509.get()))
  {}

  ParsedCertificate(const ParsedCertificate& other)
    : x509(nullptr, typed_delete<X509>)
    , sig_id(signature_algorithm(other.x509.get()))
    , issuer(other.issuer)
    , subject(other.subject)
    , skID(other.skID)
    , akID(other.akID)
    , san_info(other.san_info)
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
      case NID_ecdsa_with_SHA256:
        return Signature::ID::P256_SHA256;
      case NID_ecdsa_with_SHA384:
        return Signature::ID::P384_SHA384;
      case NID_ecdsa_with_SHA512:
        return Signature::ID::P521_SHA512;
      default:
        break;
    }
    auto algo = X509_get_signature_nid(cert);
    (void)algo;
    throw std::runtime_error("Unsupported signature algorithm");
  }

  typed_unique_ptr<EVP_PKEY> public_key() const
  {
    return make_typed_unique<EVP_PKEY>(X509_get_pubkey(x509.get()));
  }

  bool is_ca() const
  {
    auto* bc = static_cast<BASIC_CONSTRAINTS*>(
      X509_get_ext_d2i(x509.get(), NID_basic_constraints, nullptr, nullptr));
    if (bc == nullptr) {
      throw openssl_error();
    }
    return (0 != bc->ca);
  }

  typed_unique_ptr<X509> x509;
  const Signature::ID sig_id;
  const std::string issuer;
  const std::string subject;
  const std::string skID;
  const std::string akID;
  const ParsedSANInfo san_info;
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
Certificate::valid_from(const Certificate& parent) const
{
  auto pub = parent.parsed_cert->public_key();
  return (1 == X509_verify(parsed_cert->x509.get(), pub.get()));
}

std::string
Certificate::issuer() const
{
  return parsed_cert->issuer;
}

std::string
Certificate::subject() const
{
  return parsed_cert->subject;
}

bool
Certificate::is_ca() const
{
  return parsed_cert->is_ca();
}

std::string
Certificate::subject_key_id() const
{
  return parsed_cert->skID;
}

std::string
Certificate::authority_key_id() const
{
  return parsed_cert->akID;
}

std::vector<std::string>
Certificate::email_addresses() const
{
  return parsed_cert->san_info.email_addresses;
}

std::vector<std::string>
Certificate::dns_names() const
{
  return parsed_cert->san_info.domains;
}



} // namespace hpke
