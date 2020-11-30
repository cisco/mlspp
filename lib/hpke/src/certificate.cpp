#include "group.h"
#include "openssl_common.h"
#include <cstring>
#include <hpke/certificate.h>
#include <hpke/signature.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <tls/compat.h>

namespace hpke {

///
/// ParsedCertificate
///

struct RFC822Name
{
  std::string value;
};

struct DNSName
{
  std::string value;
};

using GeneralName = tls::var::variant<RFC822Name, DNSName>;

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
  static bytes parse_skid(X509* cert)
  {
    const auto* asn_skid = X509_get0_subject_key_id(cert);
    if (asn_skid == nullptr) {
      return bytes{};
    }
    const auto* octet_skid = ASN1_STRING_get0_data(asn_skid);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string skid_str(reinterpret_cast<const char*>(octet_skid));
    return bytes(skid_str.begin(), skid_str.end());
  }

  // Parse Authority Key Identifier
  static bytes parse_akid(X509* cert)
  {
    const auto* asn_akid = X509_get0_authority_key_id(cert);
    if (asn_akid == nullptr) {
      return bytes{};
    }
    const auto* octet_akid = ASN1_STRING_get0_data(asn_akid);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string akid_str(reinterpret_cast<const char*>(octet_akid));
    return bytes(akid_str.begin(), akid_str.end());
  }

  static std::vector<GeneralName> parse_san(X509* cert)
  {
    std::vector<GeneralName> san_info;
    int san_names_nb = -1;

    const auto san_names =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      make_typed_unique(reinterpret_cast<STACK_OF(GENERAL_NAME)*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)));
    san_names_nb = sk_GENERAL_NAME_num(san_names.get());

    // Check each name within the extension
    for (int i = 0; i < san_names_nb; i++) {
      auto* current_name = sk_GENERAL_NAME_value(san_names.get(), i);

      if (current_name->type == GEN_DNS) {
        const char* dns_name =
          // NOLINTNEXTLINE (cppcoreguidelines-pro-type-reinterpret-cast)
          reinterpret_cast<const char*>((ASN1_STRING_get0_data(
            current_name->d
              .dNSName))); // NOLINT(cppcoreguidelines-pro-type-union-access)

        // Make sure there isn't an embedded NUL character in the DNS name
        if (ASN1_STRING_length(
              current_name->d
                .dNSName) != // NOLINT(cppcoreguidelines-pro-type-union-access)
            static_cast<int>(strlen(dns_name))) {
          throw std::runtime_error("Malformed certificate");
        }
        san_info.emplace_back(DNSName{ dns_name });

      } else if (current_name->type == GEN_EMAIL) {
        const char* email =
          // NOLINTNEXTLINE (cppcoreguidelines-pro-type-reinterpret-cast)
          reinterpret_cast<const char*>(ASN1_STRING_get0_data(
            current_name->d
              .dNSName)); // NOLINT(cppcoreguidelines-pro-type-union-access)

        // Make sure there isn't an embedded NUL character in the DNS name
        if (ASN1_STRING_length(
              current_name->d
                .dNSName) != // NOLINT(cppcoreguidelines-pro-type-union-access)
            static_cast<int>(strlen(email))) {
          throw std::runtime_error("Malformed certificate");
        }
        san_info.emplace_back(RFC822Name{ email });
      }
    }

    return san_info;
  }

  explicit ParsedCertificate(X509* x509_in)
    : x509(x509_in, typed_delete<X509>)
    , sig_id(signature_algorithm(x509.get()))
    , issuer(X509_NAME_oneline(X509_get_issuer_name(x509.get()), nullptr, 0))
    , subject(X509_NAME_oneline(X509_get_subject_name(x509.get()), nullptr, 0))
    , subject_key_id(parse_skid(x509.get()))
    , authority_key_id(parse_akid(x509.get()))
    , san_info(parse_san(x509.get()))
    , is_ca(X509_check_ca(x509.get()) != 0)
  {}

  ParsedCertificate(const ParsedCertificate& other)
    : x509(nullptr, typed_delete<X509>)
    , sig_id(signature_algorithm(other.x509.get()))
    , issuer(other.issuer)
    , subject(other.subject)
    , subject_key_id(other.subject_key_id)
    , authority_key_id(other.authority_key_id)
    , san_info(other.san_info)
    , is_ca(other.is_ca)
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
    throw std::runtime_error("Unsupported signature algorithm");
  }

  typed_unique_ptr<EVP_PKEY> public_key() const
  {
    return make_typed_unique<EVP_PKEY>(X509_get_pubkey(x509.get()));
  }

  typed_unique_ptr<X509> x509;
  const Signature::ID sig_id;
  const std::string issuer;
  const std::string subject;
  const bytes subject_key_id;
  const bytes authority_key_id;
  const std::vector<GeneralName> san_info;
  const bool is_ca;
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

bytes
Certificate::issuer() const
{
  return to_bytes(parsed_cert->issuer);
}

bytes
Certificate::subject() const
{
  return to_bytes(parsed_cert->subject);
}

bool
Certificate::is_ca() const
{
  return parsed_cert->is_ca;
}

bytes
Certificate::subject_key_id() const
{
  return parsed_cert->subject_key_id;
}

bytes
Certificate::authority_key_id() const
{
  return parsed_cert->authority_key_id;
}

std::vector<std::string>
Certificate::email_addresses() const
{
  std::vector<std::string> emails;
  for (const auto& name : parsed_cert->san_info) {
    if (tls::var::holds_alternative<RFC822Name>(name)) {
      emails.emplace_back(tls::var::get<RFC822Name>(name).value);
    }
  }
  return emails;
}

std::vector<std::string>
Certificate::dns_names() const
{
  std::vector<std::string> domains;
  for (const auto& name : parsed_cert->san_info) {
    if (tls::var::holds_alternative<DNSName>(name)) {
      domains.emplace_back(tls::var::get<RFC822Name>(name).value);
    }
  }

  return domains;
}

} // namespace hpke
