#include <catch2/catch_all.hpp>
#include <mls/crypto.h>
#include <mls_vectors/mls_vectors.h>
#include <string>

using namespace MLS_NAMESPACE;
using namespace mls_vectors;

TEST_CASE("Basic HPKE")
{
  const auto label = "label"s;
  auto context = random_bytes(100);
  auto original = random_bytes(100);

  for (auto suite_id : all_supported_suites) {
    auto suite = CipherSuite{ suite_id };
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

    auto encrypted = gX.encrypt(suite, label, context, original);
    auto decrypted = x.decrypt(suite, label, context, encrypted);

    REQUIRE(original == decrypted);
  }
}

TEST_CASE("HPKE Key Serialization")
{
  for (auto suite_id : all_supported_suites) {
    auto suite = CipherSuite{ suite_id };
    auto x = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key;

    HPKEPublicKey parsed{ gX.data };
    REQUIRE(parsed == gX);

    auto marshaled = tls::marshal(gX);
    auto gX2 = tls::get<HPKEPublicKey>(marshaled);
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE("Basic Signature")
{
  for (auto suite_id : all_supported_suites) {
    auto suite = CipherSuite{ suite_id };
    auto a = SignaturePrivateKey::generate(suite);
    auto b = SignaturePrivateKey::generate(suite);

    REQUIRE(a == a);
    REQUIRE(b == b);
    REQUIRE(a != b);

    REQUIRE(a.public_key == a.public_key);
    REQUIRE(b.public_key == b.public_key);
    REQUIRE(a.public_key != b.public_key);

    const auto label = "label"s;
    auto message = from_hex("01020304");
    auto signature = a.sign(suite, label, message);

    REQUIRE(a.public_key.verify(suite, label, message, signature));
  }
}

TEST_CASE("Signature Key Serializion")
{
  for (auto suite_id : all_supported_suites) {
    auto suite = CipherSuite{ suite_id };
    auto x = SignaturePrivateKey::generate(suite);
    auto gX = x.public_key;

    SignaturePublicKey parsed{ gX.data };
    REQUIRE(parsed == gX);

    auto gX2 = tls::get<SignaturePublicKey>(tls::marshal(gX));
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE("Signature Key JWK Import/Export")
{
  for (auto suite_id : all_supported_suites) {
    const auto suite = CipherSuite{ suite_id };
    const auto priv = SignaturePrivateKey::generate(suite);
    const auto pub = priv.public_key;

    const auto encoded_priv = priv.to_jwk(suite);
    const auto decoded_priv =
      SignaturePrivateKey::from_jwk(suite, encoded_priv);
    REQUIRE(decoded_priv == priv);

    const auto encoded_pub = pub.to_jwk(suite);
    const auto decoded_pub = SignaturePublicKey::from_jwk(suite, encoded_pub);
    REQUIRE(decoded_pub == pub);
  }

  // Test PublicJWK parsing
  const auto full_jwk = R"({
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "059fc2ee-5ef6-456a-91d8-49c422c772b2",
    "x": "miljqilAZV2yFkqIBhrxhvt2wIMvPtkNEFzuziEGOtI"
  })"s;

  const auto known_scheme = SignatureScheme::ed25519;
  const auto known_key_id = std::string("059fc2ee-5ef6-456a-91d8-49c422c772b2");
  const auto knwon_pub_data = from_hex(
    "9a2963aa2940655db2164a88061af186fb76c0832f3ed90d105ceece21063ad2");

  const auto jwk = PublicJWK::parse(full_jwk);
  REQUIRE(jwk.signature_scheme == known_scheme);
  REQUIRE(jwk.key_id == known_key_id);
  REQUIRE(jwk.public_key == SignaturePublicKey{ knwon_pub_data });
}

TEST_CASE("Crypto Interop")
{
  for (auto suite : all_supported_suites) {
    auto tv = CryptoBasicsTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}
