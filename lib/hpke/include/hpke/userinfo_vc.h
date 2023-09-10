#pragma once
#include <memory>
#include <optional>

#include <bytes/bytes.h>
#include <chrono>
#include <hpke/signature.h>
#include <map>

using namespace MLS_NAMESPACE::bytes_ns;

namespace MLS_NAMESPACE::hpke {

struct UserInfoClaims
{
  static inline const std::string name_attr = "name";
  static inline const std::string sub_attr = "sub";
  static inline const std::string given_name_attr = "given_name";
  static inline const std::string family_name_attr = "family_name";
  static inline const std::string middle_name_attr = "middle_name";
  static inline const std::string nickname_attr = "nickname";
  static inline const std::string preferred_username_attr =
    "preferred_username";
  static inline const std::string profile_attr = "profile";
  static inline const std::string picture_attr = "picture";
  static inline const std::string website_attr = "website";
  static inline const std::string email_attr = "email";
  static inline const std::string email_verified_attr = "email_verified";
  static inline const std::string gender_attr = "gender";
  static inline const std::string birthdate_attr = "birthdate";
  static inline const std::string zoneinfo_attr = "zoneinfo";
  static inline const std::string locale_attr = "locale";
  static inline const std::string phone_number_attr = "phone_number";
  static inline const std::string phone_number_verified_attr =
    "phone_number_verified";
  static inline const std::string address_attr = "address";
  static inline const std::string address_formatted_attr = "formatted";
  static inline const std::string address_street_address_attr =
    "street_address";
  static inline const std::string address_locality_attr = "locality";
  static inline const std::string address_region_attr = "region";
  static inline const std::string address_postal_code_attr = "postal_code";
  static inline const std::string address_country_attr = "country";
  static inline const std::string updated_at_attr = "updated_at";

  std::string sub;
  std::string name;
  std::string given_name;
  std::string family_name;
  std::string middle_name;
  std::string nickname;
  std::string preferred_username;
  std::string profile;
  std::string picture;
  std::string website;
  std::string email;
  bool email_verified;
  std::string gender;
  std::string birthdate;
  std::string zoneinfo;
  std::string locale;
  std::string phone_number;
  bool phone_number_verified;
  std::string address_formatted;
  std::string address_street_address;
  std::string address_locality;
  std::string address_region;
  std::string address_postal_code;
  std::string address_country;
  uint64_t updated_at;

  // UserInfoClaims() = default;
  // ~UserInfoClaims() = default;

  static std::shared_ptr<UserInfoClaims> from_json(
    const std::string& cred_subject);
};

struct UserInfoVC
{
private:
  struct ParsedCredential;
  std::shared_ptr<ParsedCredential> parsed_cred;

public:
  explicit UserInfoVC(std::string jwt);
  UserInfoVC() = default;
  UserInfoVC(const UserInfoVC& other) = default;
  ~UserInfoVC() = default;
  UserInfoVC& operator=(const UserInfoVC& other) = default;
  UserInfoVC& operator=(UserInfoVC&& other) = default;

  std::string issuer() const;
  std::string key_id() const;
  std::chrono::system_clock::time_point not_before() const;
  std::chrono::system_clock::time_point not_after() const;
  std::shared_ptr<UserInfoClaims> subject() const;
  const Signature::PublicJWK& public_key() const;

  bool valid_from(const Signature::PublicKey& issuer_key) const;

  std::string raw;
};

bool
operator==(const UserInfoVC& lhs, const UserInfoVC& rhs);

} // namespace MLS_NAMESPACE::hpke
