#include <doctest/doctest.h>
#include <mls/crypto.h>

#include "test_vectors.h"

#include <string>

using namespace mls;

class CryptoTest
{
protected:
  // Known-answer tests of almost individual primitives (except for
  // EDCSA variants, which are non-deterministic):
  //
  // * Digest: SHA256, SHA512
  // * Encryption: AES-128-GCM, AES-256-GCM
  // * DH: P-256, P-521, X25519, X448
  // * Signature: Ed25519, Ed448

  // DH with P-256
  // KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.fax [EC]
  // http://csrc.nist.gov/groups/STM/cavp/documents/keymgmt/kastestvectors.zip
  const bytes p256dh_skA = from_hex("aaafcb133789a51d3428ce4342f2f630"
                                    "db4971b8b429c1957283c81cd9f09b60");
  const bytes p256dh_pkA = from_hex("04"
                                    "14dc091c0f85c274b1e6d297155fe22c"
                                    "de34f206ca507455d3a5a7425cd374de"
                                    "8acf695806a778ae1177199d2dfb2ae4"
                                    "8c22cc39944b6c3c3864bdf6c2a6dde9");
  const bytes p256dh_pkB = from_hex("04"
                                    "5ce7b86e3b32660403e63712ef0998de"
                                    "ae1027faec3c1be9f76f934dfeb58e98"
                                    "f4cf075b39405dd1f1adeb090107edcf"
                                    "b2b4963739d87679e3056cb0557d0adf");
  const bytes p256dh_K = from_hex("35669cd5c244ba6c1ea89b8802c3d1db"
                                  "815cd769979072e6556eb98548c65f7d");

  // DH with X25519
  // https://tools.ietf.org/html/rfc7748#section-6.1
  const bytes x25519_skA = from_hex("77076d0a7318a57d3c16c17251b26645"
                                    "df4c2f87ebc0992ab177fba51db92c2a");
  const bytes x25519_pkA = from_hex("8520f0098930a754748b7ddcb43ef75a"
                                    "0dbf3a0d26381af4eba4a98eaa9b4e6a");
  const bytes x25519_skB = from_hex("5dab087e624a8a4b79e17f8b83800ee6"
                                    "6f3bb1292618b6fd1c2f8b27ff88e0eb");
  const bytes x25519_pkB = from_hex("de9edb7d7b7dc1b4d35b61c2ece43537"
                                    "3f8343c85b78674dadfc7e146f882b4f");
  const bytes x25519_K = from_hex("4a5d9d5ba4ce2de1728e3bf480350f25"
                                  "e07e21c947d19e3376f09b3c1e161742");

  // DH with P-521
  // KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.fax [EE]
  // http://csrc.nist.gov/groups/STM/cavp/documents/keymgmt/kastestvectors.zip
  const bytes p521dh_skA = from_hex("001b6c7e40c615aad053891bededa03e"
                                    "ccc60934fc18b0da6896c541e9c565c7"
                                    "b7aa9fdd874a996ab5c728167e05589c"
                                    "35e216e5293aeb552835fc32912be687"
                                    "bed2");
  const bytes p521dh_pkA = from_hex("04"
                                    "01c0ffe846f803ef1075433bd1ce85d1"
                                    "6b6137592f5787e8852f101dba1de81e"
                                    "32d590d4e78990b8247edc8063715d5c"
                                    "a21d7cbb16f2527e6ccccb8282365488"
                                    "3d32"
                                    "014dd62897dfced9210107ad05768bbd"
                                    "44881daf3b1cc9fcbd9141d389568a91"
                                    "fe4abb2b02eff837eea26a6d0e0f8109"
                                    "d2438c1fc88487bcae8af68ab054739b"
                                    "6fa6");
  const bytes p521dh_pkB = from_hex("04"
                                    "01e08b81167e04fa9f86ae23b78d3df8"
                                    "4dba5475b9976f6aef87076c86d0892f"
                                    "fe19ca9da3ed3cee31dd3d7524b06a6b"
                                    "372a7f45c4d977de2dde9797cd0ce240"
                                    "8aa8"
                                    "019200a7c4159d4f6104e90b49cbf477"
                                    "2e78d2e1ad0561e45a3e031a1f84c61e"
                                    "22599d04f98052f3e1d5c76781fa77c6"
                                    "006132e3e0737e914595f89d392d5383"
                                    "bec9");
  const bytes p521dh_K = from_hex("00561eb17d856552c21b8cbe7d3d60d1"
                                  "ea0db738b77d4050fa2dbd0773edc395"
                                  "09854d9e30e843964ed3fd303339e338"
                                  "f31289120a38f94e9dc9ff7d4b3ea8f2"
                                  "5e01");

  // DH with X448
  // https://tools.ietf.org/html/rfc7748#section-6.2
  const bytes x448_skA = from_hex("9a8f4925d1519f5775cf46b04b58"
                                  "00d4ee9ee8bae8bc5565d498c28d"
                                  "d9c9baf574a94197448973910063"
                                  "82a6f127ab1d9ac2d8c0a598726b");
  const bytes x448_pkA = from_hex("9b08f7cc31b7e3e67d22d5aea121"
                                  "074a273bd2b83de09c63faa73d2c"
                                  "22c5d9bbc836647241d953d40c5b"
                                  "12da88120d53177f80e532c41fa0");
  const bytes x448_skB = from_hex("1c306a7ac2a0e2e0990b294470cb"
                                  "a339e6453772b075811d8fad0d1d"
                                  "6927c120bb5ee8972b0d3e21374c"
                                  "9c921b09d1b0366f10b65173992d");
  const bytes x448_pkB = from_hex("3eb7a829b0cd20f5bcfc0b599b6f"
                                  "eccf6da4627107bdb0d4f345b430"
                                  "27d8b972fc3e34fb4232a13ca706"
                                  "dcb57aec3dae07bdc1c67bf33609");
  const bytes x448_K = from_hex("07fff4181ac6cc95ec1c16a94a0f"
                                "74d12da232ce40a77552281d282b"
                                "b60c0b56fd2464c335543936521c"
                                "24403085d59a449a5037514a879d");

  // Signature with Ed25519
  // https://tools.ietf.org/html/rfc8032#section-7.1
  const bytes ed25519_sk = from_hex("833fe62409237b9d62ec77587520911e"
                                    "9a759cec1d19755b7da901b96dca3d42");
  const bytes ed25519_pk = from_hex("ec172b93ad5e563bf4932c70e1245034"
                                    "c35467ef2efd4d64ebf819683467e2bf");
  const bytes ed25519_msg = from_hex("ddaf35a193617abacc417349ae204131"
                                     "12e6fa4e89a97ea20a9eeee64b55d39a"
                                     "2192992a274fc1a836ba3c23a3feebbd"
                                     "454d4423643ce80e2a9ac94fa54ca49f");
  const bytes ed25519_sig = from_hex("dc2a4459e7369633a52b1bf277839a00"
                                     "201009a3efbf3ecb69bea2186c26b589"
                                     "09351fc9ac90b3ecfdfbc7c66431e030"
                                     "3dca179c138ac17ad9bef1177331a704");

  // Signature with Ed448
  // https://tools.ietf.org/html/rfc8032#section-7.2
  const bytes ed448_sk = from_hex("d65df341ad13e008567688baedda8e9d"
                                  "cdc17dc024974ea5b4227b6530e339bf"
                                  "f21f99e68ca6968f3cca6dfe0fb9f4fa"
                                  "b4fa135d5542ea3f01");
  const bytes ed448_pk = from_hex("df9705f58edbab802c7f8363cfe5560a"
                                  "b1c6132c20a9f1dd163483a26f8ac53a"
                                  "39d6808bf4a1dfbd261b099bb03b3fb5"
                                  "0906cb28bd8a081f00");
  const bytes ed448_msg = from_hex("bd0f6a3747cd561bdddf4640a332461a"
                                   "4a30a12a434cd0bf40d766d9c6d458e5"
                                   "512204a30c17d1f50b5079631f64eb31"
                                   "12182da3005835461113718d1a5ef944");
  const bytes ed448_sig = from_hex("554bc2480860b49eab8532d2a533b7d5"
                                   "78ef473eeb58c98bb2d0e1ce488a98b1"
                                   "8dfde9b9b90775e67f47d4a1c3482058"
                                   "efc9f40d2ca033a0801b63d45b3b722e"
                                   "f552bad3b4ccb667da350192b61c508c"
                                   "f7b6b5adadc2c8d9a446ef003fb05cba"
                                   "5f30e88e36ec2703b349ca229c267083"
                                   "3900");

  const CryptoTestVectors& tv;

  CryptoTest()
    : tv(TestLoader<CryptoTestVectors>::get())
  {}
};

TEST_CASE_FIXTURE(CryptoTest, "Crypto Interop")
{
  for (const auto& tc : tv.cases) {
    auto suite = tc.cipher_suite;

    auto hkdf_extract_out =
      hkdf_extract(suite, tv.hkdf_extract_salt, tv.hkdf_extract_ikm);
    REQUIRE(hkdf_extract_out == tc.hkdf_extract_out);

    auto derive_key_pair_priv =
      HPKEPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto derive_key_pair_pub = derive_key_pair_priv.public_key;
    REQUIRE(derive_key_pair_pub == tc.derive_key_pair_pub);

    auto hpke_plaintext =
      derive_key_pair_priv.decrypt(suite, tv.hpke_aad, tc.hpke_out);
    REQUIRE(hpke_plaintext == tv.hpke_plaintext);
  }
}

TEST_CASE_FIXTURE(CryptoTest, "Basic DH")
{
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
  }
}

TEST_CASE_FIXTURE(CryptoTest, "DH Serialization")
{
  for (auto suite : all_supported_suites) {
    auto x = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key;

    HPKEPublicKey parsed{gX.data};
    REQUIRE(parsed == gX);

    auto gX2 = tls::get<HPKEPublicKey>(tls::marshal(gX));
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE_FIXTURE(CryptoTest, "P256DH")
{
  auto suite = CipherSuite(CipherSuite::ID::P256_AES128GCM_SHA256_P256);

  auto pkA = primitive::priv_to_pub(suite, p256dh_skA);
  REQUIRE(pkA == p256dh_pkA);

  auto kAB = primitive::dh(suite, p256dh_skA, p256dh_pkB);
  REQUIRE(kAB == p256dh_K);
}

TEST_CASE_FIXTURE(CryptoTest, "P521DH")
{
  auto suite = CipherSuite(CipherSuite::ID::P521_AES256GCM_SHA512_P521);

  auto pkA = primitive::priv_to_pub(suite, p521dh_skA);
  REQUIRE(pkA == p521dh_pkA);

  auto kAB = primitive::dh(suite, p521dh_skA, p521dh_pkB);
  REQUIRE(kAB == p521dh_K);
}

TEST_CASE_FIXTURE(CryptoTest, "X25519")
{
  auto suite = CipherSuite(CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519);

  auto pkA = primitive::priv_to_pub(suite, x25519_skA);
  auto pkB = primitive::priv_to_pub(suite, x25519_skB);
  REQUIRE(pkA == x25519_pkA);
  REQUIRE(pkB == x25519_pkB);

  auto kAB = primitive::dh(suite, x25519_skA, pkB);
  auto kBA = primitive::dh(suite, x25519_skB, pkA);
  REQUIRE(kAB == x25519_K);
  REQUIRE(kBA == x25519_K);
}

TEST_CASE_FIXTURE(CryptoTest, "X448")
{
  auto suite = CipherSuite(CipherSuite::ID::X448_AES256GCM_SHA512_Ed448);

  auto pkA = primitive::priv_to_pub(suite, x448_skA);
  auto pkB = primitive::priv_to_pub(suite, x448_skB);
  REQUIRE(pkA == x448_pkA);
  REQUIRE(pkB == x448_pkB);

  auto kAB = primitive::dh(suite, x448_skA, pkB);
  auto kBA = primitive::dh(suite, x448_skB, pkA);
  REQUIRE(kAB == x448_K);
  REQUIRE(kBA == x448_K);
}

TEST_CASE_FIXTURE(CryptoTest, "HPKE")
{
  auto aad = random_bytes(100);
  auto original = random_bytes(100);

  for (auto suite : all_supported_suites) {
    auto x = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key;

    auto encrypted = gX.encrypt(suite, aad, original);
    auto decrypted = x.decrypt(suite, aad, encrypted);

    REQUIRE(original == decrypted);
  }
}

TEST_CASE_FIXTURE(CryptoTest, "Basic Signature")
{
  for (auto suite : all_supported_suites) {
    auto a = SignaturePrivateKey::generate(suite);
    auto b = SignaturePrivateKey::generate(suite);

    REQUIRE(a == a);
    REQUIRE(b == b);
    REQUIRE(a != b);

    REQUIRE(a.public_key() == a.public_key());
    REQUIRE(b.public_key() == b.public_key());
    REQUIRE(a.public_key() != b.public_key());

    auto message = from_hex("01020304");
    auto signature = a.sign(message);

    REQUIRE(a.public_key().verify(message, signature));
  }
}

TEST_CASE_FIXTURE(CryptoTest, "Signature Serializion")
{
  for (auto suite : all_supported_suites) {
    auto x = SignaturePrivateKey::generate(suite);
    auto gX = x.public_key();

    SignaturePublicKey parsed(suite, gX.to_bytes());
    REQUIRE(parsed == gX);

    auto gX2 = tls::get<SignaturePublicKey>(tls::marshal(gX));
    gX2.set_cipher_suite(suite);
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE_FIXTURE(CryptoTest, "Ed25519")
{
  auto suite = CipherSuite(CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519);
  auto sk = SignaturePrivateKey::parse(suite, ed25519_sk);
  auto pk = SignaturePublicKey(suite, ed25519_pk);
  REQUIRE(pk == sk.public_key());

  auto sig = sk.sign(ed25519_msg);
  REQUIRE(sig == ed25519_sig);
  REQUIRE(pk.verify(ed25519_msg, sig));
}

TEST_CASE_FIXTURE(CryptoTest, "Ed448")
{
  auto suite = CipherSuite(CipherSuite::ID::X448_AES256GCM_SHA512_Ed448);
  auto sk = SignaturePrivateKey::parse(suite, ed448_sk);
  auto pk = SignaturePublicKey(suite, ed448_pk);
  REQUIRE(pk == sk.public_key());

  auto sig = sk.sign(ed448_msg);
  REQUIRE(sig == ed448_sig);
  REQUIRE(pk.verify(ed448_msg, sig));
}
