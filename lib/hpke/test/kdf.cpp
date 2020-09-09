#include <doctest/doctest.h>
#include <hpke/hpke.h>

#include "common.h"

TEST_CASE("KDF Known-Answer")
{
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
        "b3ff2930e482ac10e3b256863288c2b0ebe3c5b999462b281e7119e1e05d8a55"),
      from_hex("c38019a12154353cb7659d003c55853856a29953234508729909a4144c1f21f"
               "000319302ab20b381e321"),
    },
    {
      KDF::ID::HKDF_SHA384,
      from_hex("4b44460002"),
      from_hex("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8d"
               "ec70ee9a7e1f3e293ef68eceb072a5ade"),
      from_hex("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f"
               "748b6457763e4f0204fc5"),
      from_hex("aa52397877bbae9d7fa36dd7e4dfc387145954dfdffbfd5d81570a067095fa1"
               "7bb1f90cf1805f4f132f2e2759a6d1bef"),
      from_hex("61f6f019651351cb09135fe66b0b078f6c421fb1a138d4f050e70d1e013e4aa"
               "c77d83cee050bc5597d54"),
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
        "06feddff04160100e3587a5b652af12d06f128b4cb9cb39a44526acf5c9bc9e8bf3b0c"
        "ef579c969a2beb54b070797bb920d6b85561036397f6e163c9cd12b210"),
      from_hex("0ec647b801d616313ccb45cda27d1f7e50eb2c9d03dffc4c3bb0a73a15030d9"
               "8a7ba09de1973304c1742"),
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
