#include <doctest/doctest.h>
#include <hpke/base64.h>

using namespace MLS_NAMESPACE::hpke;
using namespace MLS_NAMESPACE::bytes_ns;

TEST_CASE("To Base64 / To Base64Url")
{
  struct KnownAnswerTest
  {
    bytes data;
    std::string base64;
    std::string base64u;
  };

  const std::vector<KnownAnswerTest> cases{
    { from_ascii("hello there"), "aGVsbG8gdGhlcmU=", "aGVsbG8gdGhlcmU" },
    { from_ascii("A B C D E F "), "QSBCIEMgRCBFIEYg", "QSBCIEMgRCBFIEYg" },
    { from_ascii("hello\xfethere"), "aGVsbG/+dGhlcmU=", "aGVsbG_-dGhlcmU" },
    { from_ascii("\xfe"), "/g==", "_g" },
    { from_ascii("\x01\x02"), "AQI=", "AQI" },
    { from_ascii("\x01"), "AQ==", "AQ" },
    { from_ascii(""), "", "" },
  };

  for (const auto& tc : cases) {
    REQUIRE(to_base64(tc.data) == tc.base64);
    REQUIRE(to_base64url(tc.data) == tc.base64u);
    REQUIRE(from_base64(tc.base64) == tc.data);
    REQUIRE(from_base64url(tc.base64u) == tc.data);
  }
}
