#include <hpke/base64.h>
#include <hpke/signature.h>
#include <hpke/userinfo_vc.h>
#include <nlohmann/json.hpp>
#include <tls/compat.h>

using nlohmann::json;

namespace hpke {

///
/// ParsedCredential
///
const Signature&
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

std::chrono::system_clock::time_point
epoch_time(int64_t seconds_since_epoch)
{
  const auto delta = std::chrono::seconds(seconds_since_epoch);
  return std::chrono::system_clock::time_point(delta);
}

struct UserInfoVC::ParsedCredential
{
  // Header fields
  const Signature& algorithm; // `alg`
  std::string key_id;         // `kid`

  // Top-level Payload fields
  std::string issuer;                               // `iss`
  std::chrono::system_clock::time_point not_before; // `nbf`
  std::chrono::system_clock::time_point not_after;  // `exp`

  // Credential subject fields
  std::map<std::string, std::string> credential_subject;

  // Signature verification information
  bytes to_be_signed;
  bytes signature;

  static std::unique_ptr<ParsedCredential> parse(const std::string& jwt)
  {
    // Split the JWT into its header, payload, and signature
    const auto first_dot = jwt.find_first_of('.');
    const auto last_dot = jwt.find_last_of('.');
    if (first_dot == std::string::npos || last_dot == std::string::npos ||
        first_dot == last_dot) {
      throw std::runtime_error("malformed JWT; not enough '.' characters");
    }

    const auto header_b64 = jwt.substr(0, first_dot);
    const auto payload_b64 = jwt.substr(first_dot, last_dot - first_dot);
    const auto signature_b64 = jwt.substr(last_dot);

    // Parse the components
    const auto header = json::parse(from_base64url(header_b64));
    const auto payload = json::parse(from_base64url(payload_b64));
    const auto to_be_signed = from_ascii(header_b64 + "." + payload_b64);
    const auto signature = from_base64url(signature_b64);

    // Verify the VC parts
    const auto vc = payload.at("vc");

    static const std::string context = "https://www.w3.org/2018/credentials/v1";
    if (vc.at("context") != context) {
      throw std::runtime_error("malformed VC; incorrect context value");
    }

    static const auto type = std::vector<std::string>{
      "VerifiableCredential",
      "UserInfoCredential",
    };
    if (vc.at("type") != type) {
      throw std::runtime_error("malformed VC; incorrect type value");
    }

    // Extract the salient parts
    const auto cred = ParsedCredential{
      .algorithm = signature_from_alg(header.at("alg")),
      .key_id = header.at("kid"),

      .issuer = payload.at("iss"),
      .not_before = epoch_time(payload.at("nbf").get<int64_t>()),
      .not_after = epoch_time(payload.at("exp").get<int64_t>()),

      .credential_subject =
        vc.at("credentialSubject").get<std::map<std::string, std::string>>(),

      .to_be_signed = to_be_signed,
      .signature = signature,
    };

    return std::make_unique<ParsedCredential>(std::move(cred));
  }

  bool verify(const Signature::PublicKey& issuer_key)
  {
    return algorithm.verify(to_be_signed, signature, issuer_key);
  }
};

///
/// UserInfoVC
///

UserInfoVC::UserInfoVC(std::string jwt)
  : parsed_cred(ParsedCredential::parse(jwt))
  , raw(std::move(jwt))
{
}

UserInfoVC::UserInfoVC(const UserInfoVC& other)
  : parsed_cred(std::make_unique<ParsedCredential>(*other.parsed_cred))
  , raw(other.raw)
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

std::map<std::string, std::string>
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

bool
operator==(const UserInfoVC& lhs, const UserInfoVC& rhs)
{
  return lhs.raw == rhs.raw;
}

} // namespace hpke
