#include <doctest/doctest.h>
#include <mls/crypto.h>

#include "test_vectors.h"

#include <string>

using namespace mls;

TEST_CASE("Crypto Interop")
{
  const auto& tv = TestLoader<CryptoTestVectors>::get();

  for (const auto& tc : tv.cases) {
    auto suite = tc.cipher_suite;

    auto kdf_extract_out = suite.hpke->kdf->extract(tv.kdf_extract_salt, tv.kdf_extract_ikm);
    REQUIRE(kdf_extract_out == tc.kdf_extract_out);

    auto derive_key_pair_priv =
      HPKEPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto derive_key_pair_pub = derive_key_pair_priv.public_key;
    REQUIRE(derive_key_pair_pub == tc.derive_key_pair_pub);

    auto hpke_plaintext =
      derive_key_pair_priv.decrypt(suite, tv.hpke_aad, tc.hpke_out);
    REQUIRE(hpke_plaintext == tv.hpke_plaintext);
  }
}

TEST_CASE("Basic HPKE")
{
  auto aad = random_bytes(100);
  auto original = random_bytes(100);

  for (auto suite : all_supported_suites) {
    auto s = bytes{ 0, 1, 2, 3 };

    auto x = HPKEPrivateKey::generate(suite);
    auto y = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });

    REQUIRE(x == x);
    REQUIRE(y == y);
    REQUIRE(x != y);

    auto gX = x.public_key;
    auto gY = y.public_key;
    REQUIRE(gX == gX);
    REQUIRE(gY == gY);
    REQUIRE(gX != gY);

    auto encrypted = gX.encrypt(suite, aad, original);
    auto decrypted = x.decrypt(suite, aad, encrypted);

    REQUIRE(original == decrypted);
  }
}

TEST_CASE("HPKE Key Serialization")
{
  for (auto suite : all_supported_suites) {
    auto x = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key;

    HPKEPublicKey parsed{ gX.data };
    REQUIRE(parsed == gX);

    auto gX2 = tls::get<HPKEPublicKey>(tls::marshal(gX));
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE("Basic Signature")
{
  for (auto suite : all_supported_suites) {
    auto a = SignaturePrivateKey::generate(suite);
    auto b = SignaturePrivateKey::generate(suite);

    REQUIRE(a == a);
    REQUIRE(b == b);
    REQUIRE(a != b);

    REQUIRE(a.public_key == a.public_key);
    REQUIRE(b.public_key == b.public_key);
    REQUIRE(a.public_key != b.public_key);

    auto message = from_hex("01020304");
    auto signature = a.sign(suite, message);

    REQUIRE(a.public_key.verify(suite, message, signature));
  }
}

TEST_CASE("Signature Key Serializion")
{
  for (auto suite : all_supported_suites) {
    auto x = SignaturePrivateKey::generate(suite);
    auto gX = x.public_key;

    SignaturePublicKey parsed{gX.data};
    REQUIRE(parsed == gX);

    auto gX2 = tls::get<SignaturePublicKey>(tls::marshal(gX));
    REQUIRE(gX2 == gX);
  }
}
