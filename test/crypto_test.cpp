#include "crypto.h"
#include "test_vectors.h"
#include <gtest/gtest.h>
#include <string>

using namespace mls;

#define CIPHERSUITE CipherSuite::P256_SHA256_AES128GCM
#define SIG_SCHEME SignatureScheme::P256_SHA256

class CryptoTest : public ::testing::Test
{
protected:
  // Known-answer tests of almost individual primitives (except for
  // EDCSA variants, which are non-deterministic):
  //
  // * Digest: SHA256, SHA512
  // * Encryption: AES-128-GCM, AES-256-GCM
  // * DH: P-256, P-521, X25519, X448
  // * Signature: Ed25519, Ed448

  // SHA-256 and SHA-512
  const bytes sha2_in =
    from_hex("6162636462636465636465666465666765666768666768696768696a68696a6b6"
             "96a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
  const bytes sha256_out = from_hex(
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  const bytes sha512_out =
    from_hex("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c3359"
             "6fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");

  // AES-GCM
  // https://tools.ietf.org/html/draft-mcgrew-gcm-test-01#section-4
  const bytes aes128gcm_key = from_hex("4c80cdefbb5d10da906ac73c3613a634");
  const bytes aes128gcm_nonce = from_hex("2e443b684956ed7e3b244cfe");
  const bytes aes128gcm_aad = from_hex("000043218765432100000000");
  const bytes aes128gcm_pt = from_hex("45000048699a000080114db7c0a80102"
                                      "c0a801010a9bf15638d3010000010000"
                                      "00000000045f736970045f7564700373"
                                      "69700963796265726369747902646b00"
                                      "0021000101020201");
  const bytes aes128gcm_ct = from_hex("fecf537e729d5b07dc30df528dd22b76"
                                      "8d1b98736696a6fd348509fa13ceac34"
                                      "cfa2436f14a3f3cf65925bf1f4a13c5d"
                                      "15b21e1884f5ff6247aeabb786b93bce"
                                      "61bc17d768fd9732459018148f6cbe72"
                                      "2fd04796562dfdb4");
  const bytes aes256gcm_key = from_hex("abbccddef00112233445566778899aab"
                                       "abbccddef00112233445566778899aab");
  const bytes aes256gcm_nonce = from_hex("112233440102030405060708");
  const bytes aes256gcm_aad = from_hex("4a2cbfe300000002");
  const bytes aes256gcm_pt = from_hex("4500003069a6400080062690c0a80102"
                                      "9389155e0a9e008b2dc57ee000000000"
                                      "7002400020bf0000020405b401010402"
                                      "01020201");
  const bytes aes256gcm_ct = from_hex("ff425c9b724599df7a3bcd510194e00d"
                                      "6a78107f1b0b1cbf06efae9d65a5d763"
                                      "748a637985771d347f0545659f14e99d"
                                      "ef842d8eb335f4eecfdbf831824b4c49"
                                      "15956c96");

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

TEST_F(CryptoTest, Interop)
{
  for (const auto& tc : tv.cases) {
    auto suite = tc.cipher_suite;

    auto hkdf_extract_out =
      hkdf_extract(suite, tv.hkdf_extract_salt, tv.hkdf_extract_ikm);
    ASSERT_EQ(hkdf_extract_out, tc.hkdf_extract_out);

    auto derive_key_pair_priv =
      HPKEPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto derive_key_pair_pub = derive_key_pair_priv.public_key();
    ASSERT_EQ(derive_key_pair_pub, tc.derive_key_pair_pub);

    auto hpke_plaintext =
      derive_key_pair_priv.decrypt(suite, tv.hpke_aad, tc.hpke_out);
    ASSERT_EQ(hpke_plaintext, tv.hpke_plaintext);
  }
}

TEST_F(CryptoTest, SHA2)
{
  auto suite256 = CipherSuite::P256_SHA256_AES128GCM;
  auto suite512 = CipherSuite::P521_SHA512_AES256GCM;

  CryptoMetrics::reset();
  ASSERT_EQ(Digest(suite256).write(sha2_in).digest(), sha256_out);
  auto metrics = CryptoMetrics::snapshot();
  ASSERT_EQ(metrics.digest, 1);

  CryptoMetrics::reset();
  ASSERT_EQ(Digest(suite512).write(sha2_in).digest(), sha512_out);
  metrics = CryptoMetrics::snapshot();
  ASSERT_EQ(metrics.digest, 1);
}

TEST_F(CryptoTest, AES128GCM)
{
  auto suite = CipherSuite::P256_SHA256_AES128GCM;

  auto encrypted = primitive::seal(
    suite, aes128gcm_key, aes128gcm_nonce, aes128gcm_aad, aes128gcm_pt);
  ASSERT_EQ(encrypted, aes128gcm_ct);

  auto decrypted = primitive::open(
    suite, aes128gcm_key, aes128gcm_nonce, aes128gcm_aad, aes128gcm_ct);
  ASSERT_EQ(decrypted, aes128gcm_pt);

  auto rtt_key = random_bytes(suite_key_size(suite));
  auto rtt_nonce = random_bytes(suite_nonce_size(suite));
  auto rtt_aad = random_bytes(100);
  auto rtt_pt = random_bytes(50);

  auto rtt_encrypted =
    primitive::seal(suite, rtt_key, rtt_nonce, rtt_aad, rtt_pt);
  auto rtt_decrypted =
    primitive::open(suite, rtt_key, rtt_nonce, rtt_aad, rtt_encrypted);
  ASSERT_EQ(rtt_decrypted, rtt_pt);
}

TEST_F(CryptoTest, AES256GCM)
{
  auto suite = CipherSuite::P521_SHA512_AES256GCM;

  auto encrypted = primitive::seal(
    suite, aes256gcm_key, aes256gcm_nonce, aes256gcm_aad, aes256gcm_pt);
  ASSERT_EQ(encrypted, aes256gcm_ct);

  auto decrypted = primitive::open(
    suite, aes256gcm_key, aes256gcm_nonce, aes256gcm_aad, aes256gcm_ct);
  ASSERT_EQ(decrypted, aes256gcm_pt);

  auto rtt_key = random_bytes(suite_key_size(suite));
  auto rtt_nonce = random_bytes(suite_nonce_size(suite));
  auto rtt_aad = random_bytes(100);
  auto rtt_pt = random_bytes(50);

  auto rtt_encrypted =
    primitive::seal(suite, rtt_key, rtt_nonce, rtt_aad, rtt_pt);
  auto rtt_decrypted =
    primitive::open(suite, rtt_key, rtt_nonce, rtt_aad, rtt_encrypted);
  ASSERT_EQ(rtt_decrypted, rtt_pt);
}

TEST_F(CryptoTest, BasicDH)
{
  std::vector<CipherSuite> suites{ CipherSuite::P256_SHA256_AES128GCM,
                                   CipherSuite::P521_SHA512_AES256GCM,
                                   CipherSuite::X25519_SHA256_AES128GCM,
                                   CipherSuite::X448_SHA512_AES256GCM };

  for (auto suite : suites) {
    auto s = bytes{ 0, 1, 2, 3 };

    CryptoMetrics::reset();
    auto x = HPKEPrivateKey::generate(suite);
    ASSERT_EQ(CryptoMetrics::snapshot().fixed_base_dh, 1);

    CryptoMetrics::reset();
    auto y = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    ASSERT_EQ(CryptoMetrics::snapshot().fixed_base_dh, 1);

    ASSERT_EQ(x, x);
    ASSERT_EQ(y, y);
    ASSERT_NE(x, y);

    auto gX = x.public_key();
    auto gY = y.public_key();
    ASSERT_EQ(gX, gX);
    ASSERT_EQ(gY, gY);
    ASSERT_NE(gX, gY);

    CryptoMetrics::reset();
    auto se = gX.encrypt(suite, {}, s);
    ASSERT_EQ(CryptoMetrics::snapshot().fixed_base_dh, 1);
    ASSERT_EQ(CryptoMetrics::snapshot().var_base_dh, 1);

    CryptoMetrics::reset();
    auto sd = x.decrypt(suite, {}, se);
    ASSERT_EQ(sd, s);
    ASSERT_EQ(CryptoMetrics::snapshot().fixed_base_dh, 0);
    ASSERT_EQ(CryptoMetrics::snapshot().var_base_dh, 1);
  }
}

TEST_F(CryptoTest, DHSerialize)
{
  std::vector<CipherSuite> suites{ CipherSuite::P256_SHA256_AES128GCM,
                                   CipherSuite::P521_SHA512_AES256GCM,
                                   CipherSuite::X25519_SHA256_AES128GCM,
                                   CipherSuite::X448_SHA512_AES256GCM };

  for (auto suite : suites) {
    auto x = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key();

    HPKEPublicKey parsed(gX.to_bytes());
    ASSERT_EQ(parsed, gX);

    auto gX2 = tls::get<HPKEPublicKey>(tls::marshal(gX));
    ASSERT_EQ(gX2, gX);
  }
}

TEST_F(CryptoTest, P256DH)
{
  auto suite = CipherSuite::P256_SHA256_AES128GCM;

  auto pkA = primitive::priv_to_pub(suite, p256dh_skA);
  ASSERT_EQ(pkA, p256dh_pkA);

  auto kAB = primitive::dh(suite, p256dh_skA, p256dh_pkB);
  ASSERT_EQ(kAB, p256dh_K);
}

TEST_F(CryptoTest, P521DH)
{
  auto suite = CipherSuite::P521_SHA512_AES256GCM;

  auto pkA = primitive::priv_to_pub(suite, p521dh_skA);
  ASSERT_EQ(pkA, p521dh_pkA);

  auto kAB = primitive::dh(suite, p521dh_skA, p521dh_pkB);
  ASSERT_EQ(kAB, p521dh_K);
}

TEST_F(CryptoTest, X25519)
{
  auto suite = CipherSuite::X25519_SHA256_AES128GCM;

  auto pkA = primitive::priv_to_pub(suite, x25519_skA);
  auto pkB = primitive::priv_to_pub(suite, x25519_skB);
  ASSERT_EQ(pkA, x25519_pkA);
  ASSERT_EQ(pkB, x25519_pkB);

  auto kAB = primitive::dh(suite, x25519_skA, pkB);
  auto kBA = primitive::dh(suite, x25519_skB, pkA);
  ASSERT_EQ(kAB, x25519_K);
  ASSERT_EQ(kBA, x25519_K);
}

TEST_F(CryptoTest, X448)
{
  auto suite = CipherSuite::X448_SHA512_AES256GCM;

  auto pkA = primitive::priv_to_pub(suite, x448_skA);
  auto pkB = primitive::priv_to_pub(suite, x448_skB);
  ASSERT_EQ(pkA, x448_pkA);
  ASSERT_EQ(pkB, x448_pkB);

  auto kAB = primitive::dh(suite, x448_skA, pkB);
  auto kBA = primitive::dh(suite, x448_skB, pkA);
  ASSERT_EQ(kAB, x448_K);
  ASSERT_EQ(kBA, x448_K);
}

TEST_F(CryptoTest, HPKE)
{
  std::vector<CipherSuite> suites{ CipherSuite::P256_SHA256_AES128GCM,
                                   CipherSuite::P521_SHA512_AES256GCM,
                                   CipherSuite::X25519_SHA256_AES128GCM,
                                   CipherSuite::X448_SHA512_AES256GCM };

  auto aad = random_bytes(100);
  auto original = random_bytes(100);

  for (auto suite : suites) {
    auto x = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key();

    auto encrypted = gX.encrypt(suite, aad, original);
    auto decrypted = x.decrypt(suite, aad, encrypted);

    ASSERT_EQ(original, decrypted);
  }
}

TEST_F(CryptoTest, BasicSignature)
{
  std::vector<SignatureScheme> schemes{ SignatureScheme::P256_SHA256,
                                        SignatureScheme::P521_SHA512,
                                        SignatureScheme::Ed25519,
                                        SignatureScheme::Ed448 };

  for (auto scheme : schemes) {
    auto a = SignaturePrivateKey::generate(scheme);
    auto b = SignaturePrivateKey::generate(scheme);

    ASSERT_EQ(a, a);
    ASSERT_EQ(b, b);
    ASSERT_NE(a, b);

    ASSERT_EQ(a.public_key(), a.public_key());
    ASSERT_EQ(b.public_key(), b.public_key());
    ASSERT_NE(a.public_key(), b.public_key());

    auto message = from_hex("01020304");
    auto signature = a.sign(message);

    ASSERT_TRUE(a.public_key().verify(message, signature));
  }
}

TEST_F(CryptoTest, SignatureSerialize)
{
  std::vector<SignatureScheme> schemes{
    SignatureScheme::P256_SHA256,
    SignatureScheme::P521_SHA512,
    SignatureScheme::Ed25519,
    SignatureScheme::Ed448,
  };

  for (auto scheme : schemes) {
    auto x = SignaturePrivateKey::generate(scheme);
    auto gX = x.public_key();

    SignaturePublicKey parsed(scheme, gX.to_bytes());
    ASSERT_EQ(parsed, gX);

    auto gX2 = tls::get<SignaturePublicKey>(tls::marshal(gX));
    gX2.set_signature_scheme(scheme);
    ASSERT_EQ(gX2, gX);
  }
}

TEST_F(CryptoTest, Ed25519)
{
  auto scheme = SignatureScheme::Ed25519;
  auto sk = SignaturePrivateKey::parse(scheme, ed25519_sk);
  auto pk = SignaturePublicKey(scheme, ed25519_pk);
  ASSERT_EQ(pk, sk.public_key());

  auto sig = sk.sign(ed25519_msg);
  ASSERT_EQ(sig, ed25519_sig);
  ASSERT_TRUE(pk.verify(ed25519_msg, sig));
}

TEST_F(CryptoTest, Ed448)
{
  auto scheme = SignatureScheme::Ed448;
  auto sk = SignaturePrivateKey::parse(scheme, ed448_sk);
  auto pk = SignaturePublicKey(scheme, ed448_pk);
  ASSERT_EQ(pk, sk.public_key());

  auto sig = sk.sign(ed448_msg);
  ASSERT_EQ(sig, ed448_sig);
  ASSERT_TRUE(pk.verify(ed448_msg, sig));
}
