#include <doctest/doctest.h>
#include <hpke/userinfo_vc.h>

#include <tls/compat.h>
namespace opt = MLS_NAMESPACE::tls::opt;

using namespace MLS_NAMESPACE::hpke;

bool
operator==(const Signature::PublicJWK& lhs, const Signature::PublicJWK& rhs)
{
  const auto sig = (&lhs.sig == &rhs.sig);
  const auto kid = ((!lhs.key_id && !rhs.key_id) || lhs.key_id == rhs.key_id);

  const auto pkL = lhs.sig.serialize(*lhs.key);
  const auto pkR = rhs.sig.serialize(*rhs.key);
  const auto key = (pkL == pkR);

  return sig && kid && key;
}

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
    "FV0Xch-16qwdOlpTgzaHrw";

  const auto known_issuer = "https://localhost:3000";
  const auto known_key_id = "gyAKXvQA8X-m9JxDBgv9rULPxlU7fjB9O7D_gmIrDXs";
  const auto known_not_before = std::chrono::seconds(1693420220);
  const auto known_not_after = std::chrono::seconds(1694025020);
  const auto known_subject = std::map<std::string, std::string>{
    { { "sub", "248289761001" },
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
  })";

  const auto issuer_jwk_raw = R"({
    "kty": "EC",
    "use": "sig",
    "kid": "gyAKXvQA8X-m9JxDBgv9rULPxlU7fjB9O7D_gmIrDXs",
    "alg": "ES256",
    "crv": "P-256",
    "x": "2-MG_vi7KtZNzbwrbT2JX4kJTw7iJcnVXj7ucBZHUCg",
    "y":"ZwQq_CgT-1vfeE77uoWGM9Pm-8DyH7p-SIi1RKHEB8E"
  })";

  const auto vc = UserInfoVC(userinfo_vc_raw);
  const auto known_subject_jwk = Signature::parse_jwk(known_subject_jwk_raw);
  const auto issuer_jwk = Signature::parse_jwk(issuer_jwk_raw);

  CHECK(vc.valid_from(*issuer_jwk.key));

  CHECK(vc.issuer() == known_issuer);
  CHECK(vc.key_id() == known_key_id);
  CHECK(vc.key_id() == opt::get(issuer_jwk.key_id));
  CHECK(vc.not_before().time_since_epoch() == known_not_before);
  CHECK(vc.not_after().time_since_epoch() == known_not_after);
  CHECK(vc.subject() == known_subject);
  CHECK(vc.public_key() == known_subject_jwk);
}
