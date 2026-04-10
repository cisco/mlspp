#include <catch2/catch_all.hpp>
#include <hpke/userinfo_vc.h>
#include <nlohmann/json.hpp>

#include <tls/compat.h>
namespace opt = MLS_NAMESPACE::tls::opt;

using namespace MLS_NAMESPACE::hpke;
using namespace std::string_literals;

namespace MLS_NAMESPACE::hpke {

static bool
operator==(const Signature::PublicJWK& lhs, const Signature::PublicJWK& rhs)
{
  const auto sig = (&lhs.sig == &rhs.sig);
  const auto kid = ((!lhs.key_id && !rhs.key_id) || lhs.key_id == rhs.key_id);

  const auto pkL = lhs.sig.serialize(*lhs.key);
  const auto pkR = rhs.sig.serialize(*rhs.key);
  const auto key = (pkL == pkR);

  return sig && kid && key;
}

} // namespace mls::hpke

TEST_CASE("UserInfoVC Parsing and Validation")
{
  // Parsed contents:
  //
  // Protected header:
  // {
  //   "alg": "ES256",
  //   "typ": "JWT",
  //   "kid": "gyAKXvQA8X-m9JxDBgv9rULPxlU7fjB9O7D_gmIrDXs"
  // }
  //
  // Payload:
  // {
  //   "vc": {
  //     "@context": [
  //       "https://www.w3.org/2018/credentials/v1"
  //     ],
  //     "type": [
  //       "VerifiableCredential",
  //       "UserInfoCredential"
  //     ],
  //     "credentialSubject": {
  //       "id":
  //       "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InAxOXJZemVDYnZ5"
  //             "VHpyWGtqTGIyVkRGYllEc20yVFpxSURselQyQnEzQUEiLCJ5IjoiVVVnRmdwWjZ3"
  //             "WndHZkstWE4tVWtJSlVnTHlwZ3o2MW5xVWY4M1Nza2poRSJ9",
  //       "sub": "248289761001",
  //       "name": "Jane Doe",
  //       "given_name": "Jane",
  //       "family_name": "Doe",
  //       "preferred_username": "j.doe",
  //       "email": "janedoe@example.com",
  //       "picture": "http://example.com/janedoe/me.jpg"
  //     }
  //   },
  //   "nbf": 1693420220,
  //   "exp": 1694025020,
  //   "iss": "https://localhost:3000",
  //   "aud": "client_id",
  //   "iat": 1693506620
  // }
  const auto userinfo_vc_raw =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imd5QUtYdlFBOFgtbTlK"
    "eERCZ3Y5clVMUHhsVTdmakI5TzdEX2dtSXJEWHMifQ"
    "."
    "eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVk"
    "ZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVXNl"
    "ckluZm9DcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlk"
    "Omp3azpleUpyZEhraU9pSkZReUlzSW1OeWRpSTZJbEF0TWpVMklpd2llQ0k2SW5B"
    "eE9YSlplbVZEWW5aNVZIcHlXR3RxVEdJeVZrUkdZbGxFYzIweVZGcHhTVVJzZWxR"
    "eVFuRXpRVUVpTENKNUlqb2lWVlZuUm1kd1dqWjNXbmRIWmtzdFdFNHRWV3RKU2xW"
    "blRIbHdaM28yTVc1eFZXWTRNMU56YTJwb1JTSjkiLCJzdWIiOiIyNDgyODk3NjEw"
    "MDEiLCJuYW1lIjoiSmFuZSBEb2UiLCJnaXZlbl9uYW1lIjoiSmFuZSIsImZhbWls"
    "eV9uYW1lIjoiRG9lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiai5kb2UiLCJlbWFp"
    "bCI6ImphbmVkb2VAZXhhbXBsZS5jb20iLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1w"
    "bGUuY29tL2phbmVkb2UvbWUuanBnIn19LCJuYmYiOjE2OTM0MjAyMjAsImV4cCI6"
    "MTY5NDAyNTAyMCwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6MzAwMCIsImF1ZCI6"
    "ImNsaWVudF9pZCIsImlhdCI6MTY5MzUwNjYyMH0"
    "."
    "lSU3pbjPCcBpQID6w1WeAYO_ZyYRDZ3rsJiPD1uWPOILWzeUIHTwjjyqaL9sko9k"
    "FV0Xch-16qwdOlpTgzaHrw"s;

  const auto known_issuer = "https://localhost:3000"s;
  const auto known_key_id = "gyAKXvQA8X-m9JxDBgv9rULPxlU7fjB9O7D_gmIrDXs"s;
  const auto known_not_before = std::chrono::seconds(1693420220);
  const auto known_not_after = std::chrono::seconds(1694025020);
  const auto known_subject = std::map<std::string, std::string>{
    { { "id",
        "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InAxOXJZemVDYnZ5"
        "VHpyWGtqTGIyVkRGYllEc20yVFpxSURselQyQnEzQUEiLCJ5IjoiVVVnRmdwWjZ3"
        "WndHZkstWE4tVWtJSlVnTHlwZ3o2MW5xVWY4M1Nza2poRSJ9" },
      { "sub", "248289761001" },
      { "name", "Jane Doe" },
      { "given_name", "Jane" },
      { "family_name", "Doe" },
      { "preferred_username", "j.doe" },
      { "email", "janedoe@example.com" },
      { "picture", "http://example.com/janedoe/me.jpg" } }
  };
  const auto known_subject_jwk_raw = R"({
    "kty": "EC",
    "crv": "P-256",
    "x": "p19rYzeCbvyTzrXkjLb2VDFbYDsm2TZqIDlzT2Bq3AA",
    "y": "UUgFgpZ6wZwGfK-XN-UkIJUgLypgz61nqUf83SskjhE"
  })"s;

  const auto issuer_jwk_raw = R"({
    "kty": "EC",
    "use": "sig",
    "kid": "gyAKXvQA8X-m9JxDBgv9rULPxlU7fjB9O7D_gmIrDXs",
    "alg": "ES256",
    "crv": "P-256",
    "x": "2-MG_vi7KtZNzbwrbT2JX4kJTw7iJcnVXj7ucBZHUCg",
    "y":"ZwQq_CgT-1vfeE77uoWGM9Pm-8DyH7p-SIi1RKHEB8E"
  })"s;

  const auto vc = UserInfoVC(userinfo_vc_raw);
  const auto known_subject_jwk = Signature::parse_jwk(known_subject_jwk_raw);
  const auto issuer_jwk = Signature::parse_jwk(issuer_jwk_raw);

  CHECK(vc.valid_from(*issuer_jwk.key));

  CHECK(vc.issuer() == known_issuer);
  CHECK(vc.key_id() == known_key_id);
  CHECK(vc.key_id() == opt::get(issuer_jwk.key_id));
  CHECK(vc.not_before().time_since_epoch() == known_not_before);
  CHECK(vc.not_after().time_since_epoch() == known_not_after);
  CHECK(vc.public_key() == known_subject_jwk);

  const auto& subject = vc.subject();
  CHECK(subject.sub.value_or("") == known_subject.at("sub"));

  CHECK(vc.subject().name.value_or("") == known_subject.at("name"));
  CHECK(vc.subject().given_name.value_or("") == known_subject.at("given_name"));
  CHECK(vc.subject().family_name.value_or("") ==
        known_subject.at("family_name"));
  CHECK(vc.subject().preferred_username.value_or("") ==
        known_subject.at("preferred_username"));
  CHECK(vc.subject().email.value_or("") == known_subject.at("email"));
  CHECK(vc.subject().picture.value_or("") == known_subject.at("picture"));
}

TEST_CASE("UserInfoClaims Field Parsing")
{
  nlohmann::json credentialSubject = {
    { "test", "test" },
    { "sub", "sub" },
    { "name", "name" },
    { "given_name", "given_name" },
    { "family_name", "family_name" },
    { "middle_name", "middle_name" },
    { "nickname", "nickname" },
    { "preferred_username", "preferred_username" },
    { "profile", "profile" },
    { "picture", "picture" },
    { "website", "website" },
    { "email", "email" },
    { "email_verified", true },
    { "gender", "gender" },
    { "birthdate", "birthdate" },
    { "zoneinfo", "zoneinfo" },
    { "locale", "locale" },
    { "phone_number", "phone_number" },
    { "phone_number_verified", true },
    { "address",
      { { "formatted", "formatted" },
        { "street_address", "street_address" },
        { "locality", "locality" },
        { "region", "region" },
        { "postal_code", "postal_code" },
        { "country", "country" } } },
    { "updated_at", 42 }
  };

  const auto userinfo_claims =
    UserInfoClaims::from_json(credentialSubject.dump());

  CHECK(userinfo_claims.sub == credentialSubject.at("sub"));
  CHECK(userinfo_claims.name == credentialSubject.at("name"));
  CHECK(userinfo_claims.given_name == credentialSubject.at("given_name"));
  CHECK(userinfo_claims.family_name == credentialSubject.at("family_name"));
  CHECK(userinfo_claims.middle_name == credentialSubject.at("middle_name"));
  CHECK(userinfo_claims.nickname == credentialSubject.at("nickname"));
  CHECK(userinfo_claims.preferred_username ==
        credentialSubject.at("preferred_username"));
  CHECK(userinfo_claims.profile == credentialSubject.at("profile"));
  CHECK(userinfo_claims.picture == credentialSubject.at("picture"));
  CHECK(userinfo_claims.website == credentialSubject.at("website"));
  CHECK(userinfo_claims.email == credentialSubject.at("email"));
  CHECK(userinfo_claims.email_verified ==
        credentialSubject.at("email_verified"));
  CHECK(userinfo_claims.gender == credentialSubject.at("gender"));
  CHECK(userinfo_claims.birthdate == credentialSubject.at("birthdate"));
  CHECK(userinfo_claims.zoneinfo == credentialSubject.at("zoneinfo"));
  CHECK(userinfo_claims.locale == credentialSubject.at("locale"));
  CHECK(userinfo_claims.phone_number == credentialSubject.at("phone_number"));
  CHECK(userinfo_claims.phone_number_verified ==
        credentialSubject.at("phone_number_verified"));
  CHECK(userinfo_claims.updated_at == credentialSubject.at("updated_at"));

  auto address = userinfo_claims.address.value_or(UserInfoClaimsAddress());
  CHECK(address.formatted == credentialSubject.at("address").at("formatted"));
  CHECK(address.street_address ==
        credentialSubject.at("address").at("street_address"));
  CHECK(address.locality == credentialSubject.at("address").at("locality"));
  CHECK(address.region == credentialSubject.at("address").at("region"));
  CHECK(address.postal_code ==
        credentialSubject.at("address").at("postal_code"));
  CHECK(address.country == credentialSubject.at("address").at("country"));
}

TEST_CASE("UserInfoClaims Edge Cases")
{
  CHECK_THROWS_WITH(
    UserInfoClaims::from_json(R"({"updated_at": "42"})"),
    "[json.exception.type_error.302] type must be number, but is string");

  CHECK_THROWS_WITH(
    UserInfoClaims::from_json(R"({"name": true})"),
    "[json.exception.type_error.302] type must be string, but is boolean");

  CHECK_THROWS_WITH(
    UserInfoClaims::from_json(R"({"email_verified": "true"})"),
    "[json.exception.type_error.302] type must be boolean, but is string");
}
