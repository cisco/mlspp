#include <doctest/doctest.h>
#include <hpke/userinfo_vc.h>

#include "common.h"

#include <tls/compat.h>
namespace opt = tls::opt;

TEST_CASE("UserInfoVC Parsing and Validation")
{
  const auto userinfo_vc_raw =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjBGdHhaT1N0UWZUbmRt"
    "TE1vbDhaSnZ0emVpbEVRMGhEa3RZS001eWt0LWsifQ"
    "."
    "eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVk"
    "ZW50aWFscy92MSIsImh0dHBzOi8vb3BlbmlkLm9yZy92Yy91c2VyaW5mby92MSJd"
    "LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiT3BlbklEQ3JlZGVudGlh"
    "bCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJzdWIiOiJiYWNrZW5kLjExMzMwNDE4"
    "ODMwNjI2NzA4NzMyNCIsImVtYWlsIjoicmxiQGlwdi5zeCIsImVtYWlsX3Zlcmlm"
    "aWVkIjp0cnVlLCJmYW1pbHlfbmFtZSI6IkJhcm5lcyIsImdpdmVuX25hbWUiOiJS"
    "aWNoYXJkIiwibG9jYWxlIjoiZW4iLCJuYW1lIjoiUmljaGFyZCBCYXJuZXMiLCJp"
    "ZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdp"
    "ZUNJNklsRnZaVzV2UlhWaU1USnBaVTFMY2xKM1UyZDNTMXA1ZWpsellUVkxWVFp4"
    "YWxKcGNVMHRVM0JFVm1jaUxDSjVJam9pUm1kUmVXWkNPV1p1YjJwWVlrNXZRVVJ4"
    "Y1VOaFJqZGlSMHRwZURKUVZFcHVhalpYZDNKeWRqZG9keUo5In19LCJhdWQiOiJj"
    "bGllbnRfaWQiLCJpYXQiOjE2OTMzMzg5MDUsImlzcyI6Imh0dHBzOi8vbG9jYWxo"
    "b3N0OjMwMDAifQ"
    "."
    "bqiyvrHm2eD2KQHpJmJLFy_etuBnjCNAGHScPzVHefzctBn2_YawFSiLsDbdq7Jb"
    "priBugarjX4Dzx245NWABw";

  const auto issuer_jwk_raw = R"({
    "kty":"EC",
    "use":"sig",
    "kid":"0FtxZOStQfTndmLMol8ZJvtzeilEQ0hDktYKM5ykt-k",
    "alg":"ES256",
    "crv":"P-256",
    "x": "NQuJT8FkPrAtwdgqOWU9i6z9OaQHp5USzAoplKIItEc",
    "y": "CRtlkCCG9LfwMlt9laStka-6ZRKFEUpHv0eYJb_-2-c"
  })";

  const auto userinfo_vc = UserInfoVC(userinfo_vc_raw);
  const auto issuer_jwk = Signature::parse_jwk(issuer_jwk);

  CHECK(vc.issuer() == "");
}
