#include <doctest/doctest.h>
#include <hpke/hpke.h>

#include "common.h"

TEST_CASE("KDF Known-Answer")
{
  ensure_fips_if_required();

  struct KnownAnswerTest
  {
    KDF::ID id;
    bytes suite_id;
    bytes extracted;
    bytes expanded;
    bytes labeled_extracted;
    bytes labeled_expanded;
  };

  // https://tools.ietf.org/html/rfc5869#appendix-A.1
  const auto expand_size = size_t(42);
  const auto ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const auto salt = from_hex("000102030405060708090a0b0c");
  const auto info = from_hex("f0f1f2f3f4f5f6f7f8f9");

  // see scripts/hkdf-tests.go
  const auto label_str = std::string("test");
  const auto label = bytes(label_str.begin(), label_str.end());
  const auto cases = std::vector<KnownAnswerTest>{
    {
      KDF::ID::HKDF_SHA256,
      from_hex("4b44460001"),
      from_hex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
      from_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
               "f34007208d5b887185865"),
      from_hex(
        "0d49c73b424a1a811a561969011c17a8f8274da9d972296c19fd699e0479b539"),
      from_hex("9c302814651c8bb4369af9ae64a7a27be968ceab9e8a9bb4d2cb20d77014ce7"
               "8422a60cfb6258664cf76"),
    },
    {
      KDF::ID::HKDF_SHA384,
      from_hex("4b44460002"),
      from_hex("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8d"
               "ec70ee9a7e1f3e293ef68eceb072a5ade"),
      from_hex("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f"
               "748b6457763e4f0204fc5"),
      from_hex("1e49e7289df25b71632d01652e326c37dc7a9b73b09bd0b7b94981d880bf957"
               "0b92d7fbc74c6645f8975952e61e1f344"),
      from_hex("1ff240b2aac3dd7017994f5da9419955c5493d1e6fce3eec73f915873cd2350"
               "59173029998f3acf6785a"),
    },
    {
      KDF::ID::HKDF_SHA512,
      from_hex("4b44460003"),
      from_hex(
        "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238"
        "127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237"),
      from_hex("832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579"
               "338da362cb8d9f925d7cb"),
      from_hex(
        "5019ddbb5155a0b5085393236760d2535d0761b668284f96062d779a80aefe391aee1a"
        "f484ff60698706297abad419c1223bb0271d07f887868b6ffbc54afb27"),
      from_hex("6ce7b9415c53ab65daab5bc463d83cea29a342fd3145fe40708e0144834a90a"
               "01f24bc9b76a8fda3375e"),
    },
  };

  for (const auto& tc : cases) {
    const auto& kdf = select_kdf(tc.id);

    auto extracted = kdf.extract(salt, ikm);
    CHECK(extracted == tc.extracted);

    auto expanded = kdf.expand(extracted, info, expand_size);
    CHECK(expanded == tc.expanded);

    auto labeled_extracted = kdf.labeled_extract(tc.suite_id, salt, label, ikm);
    CHECK(labeled_extracted == tc.labeled_extracted);

    auto labeled_expanded = kdf.labeled_expand(
      tc.suite_id, labeled_extracted, label, info, expand_size);
    CHECK(labeled_expanded == tc.labeled_expanded);
  }
}
