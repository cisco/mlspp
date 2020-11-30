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
/// Utility functions
///

static std::optional<bytes>
asn1_octet_string_to_bytes(const ASN1_OCTET_STRING* octets)
{
  if (octets == nullptr) {
    return std::nullopt;
  }
  const auto* ptr = ASN1_STRING_get0_data(octets);
  const auto len = ASN1_STRING_length(octets);
  // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return bytes(ptr, ptr + len);
}

static std::string
asn1_string_to_std_string(const ASN1_STRING* asn1_string)
{
  const auto* data = ASN1_STRING_get0_data(asn1_string);
  const auto data_size = static_cast<size_t>(ASN1_STRING_length(asn1_string));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  auto str = std::string(reinterpret_cast<const char*>(data));
  if (str.size() != data_size) {
    throw std::runtime_error("Malformed ASN.1 string");
  }
  return str;
}

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
  static std::optional<bytes> parse_skid(X509* cert)
  {
    return asn1_octet_string_to_bytes(X509_get0_subject_key_id(cert));
  }

  // Parse Authority Key Identifier
  static std::optional<bytes> parse_akid(X509* cert)
  {
    return asn1_octet_string_to_bytes(X509_get0_authority_key_id(cert));
  }

  static std::vector<GeneralName> parse_san(X509* cert)
  {
    std::vector<GeneralName> names;
    int san_names_nb = -1;

    auto* ext_ptr =
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* san_ptr = reinterpret_cast<STACK_OF(GENERAL_NAME)*>(ext_ptr);
    const auto san_names = make_typed_unique(san_ptr);
    san_names_nb = sk_GENERAL_NAME_num(san_names.get());

    // Check each name within the extension
    for (int i = 0; i < san_names_nb; i++) {
      auto* current_name = sk_GENERAL_NAME_value(san_names.get(), i);
      if (current_name->type == GEN_DNS) {
        const auto dns_name =
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
          asn1_string_to_std_string(current_name->d.dNSName);
        names.emplace_back(DNSName{ dns_name });
      } else if (current_name->type == GEN_EMAIL) {
        const auto email =
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access
          asn1_string_to_std_string(current_name->d.rfc822Name);
        names.emplace_back(RFC822Name{ email });
      }
    }

    return names;
  }

  explicit ParsedCertificate(X509* x509_in)
    : x509(x509_in, typed_delete<X509>)
    , sig_id(signature_algorithm(x509.get()))
    , issuer(X509_issuer_name_hash(x509.get()))
    , subject(X509_subject_name_hash(x509.get()))
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
  const uint64_t issuer;
  const uint64_t subject;
  const std::optional<bytes> subject_key_id;
  const std::optional<bytes> authority_key_id;
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

uint64_t
Certificate::issuer() const
{
  return parsed_cert->issuer;
}

uint64_t
Certificate::subject() const
{
  return parsed_cert->subject;
}

bool
Certificate::is_ca() const
{
  return parsed_cert->is_ca;
}

std::optional<bytes>
Certificate::subject_key_id() const
{
  return parsed_cert->subject_key_id;
}

std::optional<bytes>
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
