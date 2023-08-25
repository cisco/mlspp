#include <doctest/doctest.h>
#include <mls/crypto.h>
#include <mls_vectors/mls_vectors.h>
#include <nlohmann/json.hpp>
#include <string>

using namespace mls;
using namespace mls_vectors;
using namespace nlohmann;

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

TEST_CASE("Signature Key Serializion To JWK")
{

  struct KnownAnswerTest
  {
    CipherSuite suite;
    bool supported;
    bytes pk;
    std::string kty;
    std::string crv;
    std::string d;
    std::string x;
    std::string y;
  };

  const auto cases = std::vector<KnownAnswerTest>{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256,
      true,
      from_hex(
        "cae90bad54df6973c64f7e4116ee78409045ed43e9668d0d474948a510f38acf"),
      "EC",
      "P-256",
      "yukLrVTfaXPGT35BFu54QJBF7UPpZo0NR0lIpRDzis8",
      "nUV1xGxWcUobNQrV0DsSN_z7P8hwVivmUji8EIJnrGg",
      "2TGu_-lIxa7fn8PW-3gMNod-CjwwoAiLIhkbcsHtSdw" },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519,
      true,
      from_hex(
        "9f959eeebab856bede41bfcd985077f5eaae702dde01c76b48952c35c9a97618"),
      "OKP",
      "Ed25519",
      "n5We7rq4Vr7eQb_NmFB39equcC3eAcdrSJUsNcmpdhg",
      "NmQinNknsQjwPFpujKmLa09alb4kagXy1YJenH3Zs-I",
      "" },
    { CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519,
      true,
      from_hex(
        "f6d9dfcfc3e7f2016df7894b959e3f922d01035292732da12158f0c08b6251ae"),
      "OKP",
      "Ed25519",
      "9tnfz8Pn8gFt94lLlZ4_ki0BA1KScy2hIVjwwItiUa4",
      "kcnJ4z9eHBgiuFSDGlsF8PyibD2seAMncB4iKamamSU",
      "" },
    { CipherSuite::ID::X448_AES256GCM_SHA512_Ed448,
      true,
      from_hex("e8dfd869ebe67fe696f0a0a12e04111cf1e4744e1a045fa73b2285a0168f319"
               "e66522c9ddec741a8dd8011d0fc4b72303053901540c36f1e89"),
      "OKP",
      "Ed448",
      "6N_Yaevmf-aW8KChLgQRHPHkdE4aBF-"
      "nOyKFoBaPMZ5mUiyd3sdBqN2AEdD8S3IwMFOQFUDDbx6J",
      "5uf09bDIVeecX74gv2ljKmvf3eLUXYiB6Jbycwww8ijcbnM04rfJr1agpFC2TuVSm5d0iDCj"
      "EDIA",
      "" },
    { CipherSuite::ID::P521_AES256GCM_SHA512_P521,
      true,
      from_hex(
        "01c58ae6621000da12b682f45248f88b4cef278743a4fa325fc234f8770648d440cab3"
        "367e90a49293c02778732776bd3eb985415c5f9df77a212e2097f0026298b8"),
      "EC",
      "P-521",
      "AcWK5mIQANoStoL0Ukj4i0zvJ4dDpPoyX8I0-"
      "HcGSNRAyrM2fpCkkpPAJ3hzJ3a9PrmFQVxfnfd6IS4gl_ACYpi4",
      "AFLfr4vhftq9G6axgJ8g6xdukrUFn2cD5HDIxp8uzSbYW_"
      "QIjKdUV1pF2vzzcz7Vj185LE6kl1SqTX6Z551W38mC",
      "AbPIkuJkgfBZCidxSFrJALD1_e8-tKE0Ygy1dF2PZXJMGcHQRPbnytg-"
      "4iVVGbjVdcakGIuUq3aAO09NqLi8j81d" },
    { CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448,
      true,
      from_hex("5535d624e127fed3bc20d24a51269ce842e1ce36d6a62002b7f59696fcd3d9e"
               "7d865da15e8e690caf22c34bf04bd34bd761be1eacb26fec193"),
      "OKP",
      "Ed448",
      "VTXWJOEn_tO8INJKUSac6ELhzjbWpiACt_"
      "WWlvzT2efYZdoV6OaQyvIsNL8EvTS9dhvh6ssm_sGT",
      "jfbh2FAWZ57XmEEgrlGLAk6Am-qZ1IibFy2qip1uU3zOfWJ-TXmq4Ty-"
      "yssJdZ5c0niU3SNO7JkA",
      "" },
    { CipherSuite::ID::P384_AES256GCM_SHA384_P384,
      true,
      from_hex("33500ad0e749f53707e1f5ebef7d80758f95923c5b02acd89c21ffb2eb9f4f0"
               "ccc5db144cd92e1577963dfb1b4e3fa68"),
      "EC",
      "P-384",
      "M1AK0OdJ9TcH4fXr732AdY-VkjxbAqzYnCH_suufTwzMXbFEzZLhV3lj37G04_po",
      "FyXCw9vukrBkLD_Lu7HvZw6cr-gwvpldN4aqZgtjAuM1rRSL74Lfi3CBBD8LpB0A",
      "UUd8Qs3VdkOTFJlP62TKaVBp0JZlD74b7TU2gNlkDX3o8EIfl4POCooLs920bCJf" }
  };

  for (const auto& tc : cases) {
    const CipherSuite suite{ tc.suite };

    if (!tc.supported) {
      auto private_key = SignaturePrivateKey::generate(suite);
      CHECK_THROWS_WITH(private_key.to_jwk(suite), "Unsupported group");
      continue;
    }

    // Export Private Key
    auto private_key = SignaturePrivateKey::parse(suite, tc.pk);
    auto jwk_str = private_key.to_jwk(tc.suite);
    auto jwk_json = json::parse(jwk_str);
    REQUIRE(jwk_json["kty"] == tc.kty);
    REQUIRE(jwk_json["crv"] == tc.crv);
    REQUIRE(jwk_json["d"] == tc.d);
    REQUIRE(jwk_json["x"] == tc.x);

    if (!tc.y.empty()) {
      REQUIRE(jwk_json["y"] == tc.y);
    }

    // Export Public Key
    auto jwk_pk_str = private_key.public_key.to_jwk(tc.suite);
    auto jwk_pk_json = json::parse(jwk_pk_str);
    REQUIRE(jwk_pk_json["kty"] == tc.kty);
    REQUIRE(jwk_pk_json["crv"] == tc.crv);
    REQUIRE(jwk_pk_json["x"] == tc.x);

    if (!tc.y.empty()) {
      REQUIRE(jwk_pk_json["y"] == tc.y);
    }

    // Import Private Key
    auto import_jwk_sk = SignaturePrivateKey::from_jwk(tc.suite, jwk_str);
    REQUIRE(tc.pk == import_jwk_sk.data);

    // Import Public Key
    auto import_jwk_pk = SignaturePublicKey::from_jwk(tc.suite, jwk_pk_str);
    REQUIRE(private_key.public_key.data == import_jwk_pk.data);
  }
}

TEST_CASE("Crypto Interop")
{
  for (auto suite : all_supported_suites) {
    auto tv = CryptoBasicsTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}
