#include <hpke/base64.h>
#include <hpke/signature.h>
#include <hpke/userinfo_vc.h>
#include <nlohmann/json.hpp>
#include <tls/compat.h>

using nlohmann::json;

namespace MLS_NAMESPACE::hpke {

///
/// ParsedCredential
///
static const Signature&
signature_from_alg(const std::string& alg)
{
  static const auto alg_sig_map = std::map<std::string, const Signature&>{
    { "ES256", Signature::get<Signature::ID::P256_SHA256>() },
    { "ES384", Signature::get<Signature::ID::P384_SHA384>() },
    { "ES512", Signature::get<Signature::ID::P521_SHA512>() },
    { "Ed25519", Signature::get<Signature::ID::Ed25519>() },
    { "Ed448", Signature::get<Signature::ID::Ed448>() },
    { "RS256", Signature::get<Signature::ID::RSA_SHA256>() },
    { "RS384", Signature::get<Signature::ID::RSA_SHA384>() },
    { "RS512", Signature::get<Signature::ID::RSA_SHA512>() },
  };

  return alg_sig_map.at(alg);
}

static std::chrono::system_clock::time_point
epoch_time(int64_t seconds_since_epoch)
{
  const auto delta = std::chrono::seconds(seconds_since_epoch);
  return std::chrono::system_clock::time_point(delta);
}

static bool
is_ecdsa(const Signature& sig)
{
  return sig.id == Signature::ID::P256_SHA256 ||
         sig.id == Signature::ID::P384_SHA384 ||
         sig.id == Signature::ID::P521_SHA512;
}

// OpenSSL expects ECDSA signatures to be in DER form.  JWS provides the
// signature in raw R||S form.  So we need to do some manual DER encoding.
static bytes
jws_to_der_sig(const bytes& jws_sig)
{
  // Inputs that are too large will result in invalid DER encodings with this
  // code.  At this size, the combination of the DER integer headers and the
  // integer data will overflow the one-byte DER struct length.
  static const auto max_sig_size = size_t(250);
  if (jws_sig.size() > max_sig_size) {
    throw std::runtime_error("JWS signature too large");
  }

  if (jws_sig.size() % 2 != 0) {
    throw std::runtime_error("Malformed JWS signature");
  }

  const auto int_size = jws_sig.size() / 2;
  const auto jws_sig_cut =
    jws_sig.begin() + static_cast<std::ptrdiff_t>(int_size);

  // Compute the encoded size of R and S integer data, adding a zero byte if
  // needed to clear the sign bit
  const auto r_big = (jws_sig.at(0) >= 0x80);
  const auto s_big = (jws_sig.at(int_size) >= 0x80);

  const auto r_size = int_size + (r_big ? 1 : 0);
  const auto s_size = int_size + (s_big ? 1 : 0);

  // Compute the size of the DER-encoded signature
  static const auto int_header_size = 2;
  const auto r_int_size = int_header_size + r_size;
  const auto s_int_size = int_header_size + s_size;

  const auto content_size = r_int_size + s_int_size;
  const auto content_big = (content_size > 0x80);

  auto der_header_size = 2 + (content_big ? 1 : 0);
  const auto der_size = der_header_size + content_size;

  // Allocate the DER buffer
  auto der = bytes(der_size, 0);

  // Write the header
  der.at(0) = 0x30;
  if (content_big) {
    der.at(1) = 0x81;
    der.at(2) = static_cast<uint8_t>(content_size);
  } else {
    der.at(1) = static_cast<uint8_t>(content_size);
  }

  // Write R, virtually padding with a zero byte if needed
  const auto r_start = der_header_size;
  const auto r_data_start = r_start + int_header_size + (r_big ? 1 : 0);
  const auto r_data_begin =
    der.begin() + static_cast<std::ptrdiff_t>(r_data_start);

  der.at(r_start) = 0x02;
  der.at(r_start + 1) = static_cast<uint8_t>(r_size);
  std::copy(jws_sig.begin(), jws_sig_cut, r_data_begin);

  // Write S, virtually padding with a zero byte if needed
  const auto s_start = der_header_size + r_int_size;
  const auto s_data_start = s_start + int_header_size + (s_big ? 1 : 0);
  const auto s_data_begin =
    der.begin() + static_cast<std::ptrdiff_t>(s_data_start);

  der.at(s_start) = 0x02;
  der.at(s_start + 1) = static_cast<uint8_t>(s_size);
  std::copy(jws_sig_cut, jws_sig.end(), s_data_begin);

  return der;
}

struct UserInfoVC::ParsedCredential
{
  // Header fields
  const Signature& signature_algorithm; // `alg`
  std::string key_id;                   // `kid`

  // Top-level Payload fields
  std::string issuer;                               // `iss`
  std::chrono::system_clock::time_point not_before; // `nbf`
  std::chrono::system_clock::time_point not_after;  // `exp`

  // Credential subject fields
  std::shared_ptr<UserInfoClaims> credential_subject;
  Signature::PublicJWK public_key;

  // Signature verification information
  bytes to_be_signed;
  bytes signature;

  ParsedCredential(const Signature& signature_algorithm_in,
                   std::string key_id_in,
                   std::string issuer_in,
                   std::chrono::system_clock::time_point not_before_in,
                   std::chrono::system_clock::time_point not_after_in,
                   std::shared_ptr<UserInfoClaims> credential_subject_in,
                   Signature::PublicJWK&& public_key_in,
                   bytes to_be_signed_in,
                   bytes signature_in)
    : signature_algorithm(signature_algorithm_in)
    , key_id(std::move(key_id_in))
    , issuer(std::move(issuer_in))
    , not_before(not_before_in)
    , not_after(not_after_in)
    , credential_subject(std::move(credential_subject_in))
    , public_key(std::move(public_key_in))
    , to_be_signed(std::move(to_be_signed_in))
    , signature(std::move(signature_in))
  {
  }

  static std::shared_ptr<ParsedCredential> parse(const std::string& jwt)
  {
    // Split the JWT into its header, payload, and signature
    const auto first_dot = jwt.find_first_of('.');
    const auto last_dot = jwt.find_last_of('.');
    if (first_dot == std::string::npos || last_dot == std::string::npos ||
        first_dot == last_dot || last_dot > jwt.length() - 2) {
      throw std::runtime_error("malformed JWT; not enough '.' characters");
    }

    const auto header_b64 = jwt.substr(0, first_dot);
    const auto payload_b64 =
      jwt.substr(first_dot + 1, last_dot - first_dot - 1);
    const auto signature_b64 = jwt.substr(last_dot + 1);

    // Parse the components
    const auto header = json::parse(from_base64url(header_b64));
    const auto payload = json::parse(from_base64url(payload_b64));

    // Prepare the validation inputs
    const auto& sig = signature_from_alg(header.at("alg"));
    const auto to_be_signed = from_ascii(header_b64 + "." + payload_b64);
    auto signature = from_base64url(signature_b64);
    if (is_ecdsa(sig)) {
      signature = jws_to_der_sig(signature);
    }

    // Verify the VC parts
    const auto& vc = payload.at("vc");

    static const auto context =
      std::vector<std::string>{ { "https://www.w3.org/2018/credentials/v1" } };
    const auto vc_context = vc.at("@context").get<std::vector<std::string>>();
    if (vc_context != context) {
      throw std::runtime_error("malformed VC: incorrect context value");
    }

    static const auto type = std::vector<std::string>{
      "VerifiableCredential",
      "UserInfoCredential",
    };
    if (vc.at("type") != type) {
      throw std::runtime_error("malformed VC: incorrect type value");
    }

    // Parse the subject public key
    static const std::string did_jwk_prefix = "did:jwk:";
    const auto id = vc.at("credentialSubject").at("id").get<std::string>();
    if (id.find(did_jwk_prefix) != 0) {
      throw std::runtime_error("malformed UserInfo VC: ID is not did:jwk");
    }

    const auto jwk = to_ascii(from_base64url(id.substr(did_jwk_prefix.size())));
    auto public_key = Signature::parse_jwk(jwk);

    // Extract the salient parts
    return std::make_shared<ParsedCredential>(
      sig,
      header.at("kid"),

      payload.at("iss"),
      epoch_time(payload.at("nbf").get<int64_t>()),
      epoch_time(payload.at("exp").get<int64_t>()),

      UserInfoClaims::from_json(vc.at("credentialSubject").dump()),
      std::move(public_key),

      to_be_signed,
      signature);
  }

  bool verify(const Signature::PublicKey& issuer_key)
  {
    return signature_algorithm.verify(to_be_signed, signature, issuer_key);
  }
};

///
/// UserInfoClaims
///
std::shared_ptr<UserInfoClaims>
UserInfoClaims::from_json(const std::string& cred_subject)
{
  // parse the credentialSubject
  auto cred_subject_json = nlohmann::json::parse(cred_subject);

  // set default value for the nested object, address
  auto cred_subject_address_json = nlohmann::json::object();
  if (cred_subject_json.contains(address_attr)) {
    cred_subject_address_json =
      cred_subject_json.value<nlohmann::json::object_t>(address_attr, {});
  }

  // create the UserInfoClaims object
  return std::make_shared<UserInfoClaims>(UserInfoClaims({
    .sub = cred_subject_json.value<std::string>(UserInfoClaims::sub_attr, ""),
    .name = cred_subject_json.value<std::string>(UserInfoClaims::name_attr, ""),
    .given_name =
      cred_subject_json.value<std::string>(UserInfoClaims::given_name_attr, ""),
    .family_name = cred_subject_json.value<std::string>(
      UserInfoClaims::family_name_attr, ""),
    .middle_name = cred_subject_json.value<std::string>(
      UserInfoClaims::middle_name_attr, ""),
    .nickname =
      cred_subject_json.value<std::string>(UserInfoClaims::nickname_attr, ""),
    .preferred_username = cred_subject_json.value<std::string>(
      UserInfoClaims::preferred_username_attr, ""),
    .profile =
      cred_subject_json.value<std::string>(UserInfoClaims::profile_attr, ""),
    .picture =
      cred_subject_json.value<std::string>(UserInfoClaims::picture_attr, ""),
    .website =
      cred_subject_json.value<std::string>(UserInfoClaims::website_attr, ""),
    .email =
      cred_subject_json.value<std::string>(UserInfoClaims::email_attr, ""),
    .email_verified =
      cred_subject_json.value<bool>(UserInfoClaims::email_verified_attr, false),
    .gender =
      cred_subject_json.value<std::string>(UserInfoClaims::gender_attr, ""),
    .birthdate =
      cred_subject_json.value<std::string>(UserInfoClaims::birthdate_attr, ""),
    .zoneinfo =
      cred_subject_json.value<std::string>(UserInfoClaims::zoneinfo_attr, ""),
    .locale =
      cred_subject_json.value<std::string>(UserInfoClaims::locale_attr, ""),
    .phone_number = cred_subject_json.value<std::string>(
      UserInfoClaims::phone_number_attr, ""),
    .phone_number_verified = cred_subject_json.value<bool>(
      UserInfoClaims::phone_number_verified_attr, false),
    .address_formatted = cred_subject_address_json.value<std::string>(
      UserInfoClaims::address_formatted_attr, ""),
    .address_street_address = cred_subject_address_json.value<std::string>(
      UserInfoClaims::address_street_address_attr, ""),
    .address_locality = cred_subject_address_json.value<std::string>(
      UserInfoClaims::address_locality_attr, ""),
    .address_region = cred_subject_address_json.value<std::string>(
      UserInfoClaims::address_region_attr, ""),
    .address_postal_code = cred_subject_address_json.value<std::string>(
      UserInfoClaims::address_postal_code_attr, ""),
    .address_country = cred_subject_address_json.value<std::string>(
      UserInfoClaims::address_country_attr, ""),
    .updated_at =
      cred_subject_json.value<uint64_t>(UserInfoClaims::updated_at_attr, 0),
  }));
}

///
/// UserInfoVC
///

UserInfoVC::UserInfoVC(std::string jwt)
  : parsed_cred(ParsedCredential::parse(jwt))
  , raw(std::move(jwt))
{
}

std::string
UserInfoVC::issuer() const
{
  return parsed_cred->issuer;
}

std::string
UserInfoVC::key_id() const
{
  return parsed_cred->key_id;
}

bool
UserInfoVC::valid_from(const Signature::PublicKey& issuer_key) const
{
  return parsed_cred->verify(issuer_key);
}

std::shared_ptr<UserInfoClaims>
UserInfoVC::subject() const
{
  return parsed_cred->credential_subject;
}

std::chrono::system_clock::time_point
UserInfoVC::not_before() const
{
  return parsed_cred->not_before;
}

std::chrono::system_clock::time_point
UserInfoVC::not_after() const
{
  return parsed_cred->not_after;
}

const Signature::PublicJWK&
UserInfoVC::public_key() const
{
  return parsed_cred->public_key;
}

bool
operator==(const UserInfoVC& lhs, const UserInfoVC& rhs)
{
  return lhs.raw == rhs.raw;
}

} // namespace MLS_NAMESPACE::hpke
