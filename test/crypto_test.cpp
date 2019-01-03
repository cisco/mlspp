#include "crypto.h"
#include <catch.hpp>
#include <string>

using namespace mls;

#define CIPHERSUITE CipherSuite::P256_SHA256_AES128GCM
#define SIG_SCHEME SignatureScheme::P256_SHA256

// TODO Known-answer tests of all individual primitives:
// * Digest
//    * SHA256      DONE
//    * SHA512      DONE
// * Encryption
//    * AES-128-GCM DONE
//    * AES-256-GCM DONE
// * DH
//    * ECDH P-256  TODO
//    * ECDH P-521  TODO
//    * X25519      TODO https://tools.ietf.org/html/rfc7748#section-6.1
//    * X448        TODO https://tools.ietf.org/html/rfc7748#section-6.2
// * Signature
//    * ECDSA P-256 TODO
//    * ECDSA P-521 TODO
//    * Ed25519     TODO https://tools.ietf.org/html/rfc8032#section-7.1
//    * Ed448       TODO https://tools.ietf.org/html/rfc8032#section-7.4

TEST_CASE("SHA-256 hash produces correct values", "[crypto]")
{
  // https://www.di-mgt.com.au/sha_testvectors.html
  auto input =
    from_hex("6162636462636465636465666465666765666768666768696768696a68696a6b6"
             "96a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
  auto out256 = from_hex(
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  auto out512 =
    from_hex("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c3359"
             "6fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");

  REQUIRE(Digest(DigestType::SHA256).write(input).digest() == out256);
  REQUIRE(Digest(DigestType::SHA512).write(input).digest() == out512);
}

TEST_CASE("AES-GCM encryption produces correct values", "[crypto]")
{
  // https://tools.ietf.org/html/draft-mcgrew-gcm-test-01#section-4
  auto key128 = from_hex("4c80cdefbb5d10da906ac73c3613a634");
  auto nonce128 = from_hex("2e443b684956ed7e3b244cfe");
  auto aad128 = from_hex("000043218765432100000000");
  auto plaintext128 = from_hex("45000048699a000080114db7c0a80102"
                               "c0a801010a9bf15638d3010000010000"
                               "00000000045f736970045f7564700373"
                               "69700963796265726369747902646b00"
                               "0021000101020201");
  auto ciphertext128 = from_hex("fecf537e729d5b07dc30df528dd22b76"
                                "8d1b98736696a6fd348509fa13ceac34"
                                "cfa2436f14a3f3cf65925bf1f4a13c5d"
                                "15b21e1884f5ff6247aeabb786b93bce"
                                "61bc17d768fd9732459018148f6cbe72"
                                "2fd04796562dfdb4");

  auto key256 = from_hex("abbccddef00112233445566778899aab"
                         "abbccddef00112233445566778899aab");
  auto nonce256 = from_hex("112233440102030405060708");
  auto aad256 = from_hex("4a2cbfe300000002");
  auto plaintext256 = from_hex("4500003069a6400080062690c0a80102"
                               "9389155e0a9e008b2dc57ee000000000"
                               "7002400020bf0000020405b401010402"
                               "01020201");
  auto ciphertext256 = from_hex("ff425c9b724599df7a3bcd510194e00d"
                                "6a78107f1b0b1cbf06efae9d65a5d763"
                                "748a637985771d347f0545659f14e99d"
                                "ef842d8eb335f4eecfdbf831824b4c49"
                                "15956c96");

  SECTION("For encryption")
  {
    AESGCM gcm128(key128, nonce128);
    gcm128.set_aad(aad128);
    REQUIRE(gcm128.encrypt(plaintext128) == ciphertext128);

    AESGCM gcm256(key256, nonce256);
    gcm256.set_aad(aad256);
    REQUIRE(gcm256.encrypt(plaintext256) == ciphertext256);
  }

  SECTION("For decryption")
  {
    AESGCM gcm128(key128, nonce128);
    gcm128.set_aad(aad128);
    REQUIRE(gcm128.decrypt(ciphertext128) == plaintext128);

    AESGCM gcm256(key256, nonce256);
    gcm256.set_aad(aad256);
    REQUIRE(gcm256.decrypt(ciphertext256) == plaintext256);
  }

  SECTION("For an encrypt/decrypt round-trip (128 bits)")
  {
    std::vector<size_t> key_sizes = { AESGCM::key_size_128,
                                      AESGCM::key_size_256 };
    for (auto key_size : key_sizes) {
      auto key = random_bytes(AESGCM::key_size_128);
      auto nonce = random_bytes(AESGCM::nonce_size);
      auto aad = random_bytes(100);
      auto original = random_bytes(100);

      AESGCM gcm1(key, nonce);
      gcm1.set_aad(aad);
      auto encrypted = gcm1.encrypt(original);

      AESGCM gcm2(key, nonce);
      gcm2.set_aad(aad);
      auto decrypted = gcm2.decrypt(encrypted);

      REQUIRE(decrypted == original);
    }
  }
}

TEST_CASE("Diffie-Hellman key pairs can be created and combined", "[crypto]")
{
  std::vector<CipherSuite> suites{ CipherSuite::P256_SHA256_AES128GCM,
                                   CipherSuite::P521_SHA512_AES256GCM,
                                   CipherSuite::X25519_SHA256_AES128GCM,
                                   CipherSuite::X448_SHA512_AES256GCM };

  for (auto suite : suites) {
    auto x = DHPrivateKey::generate(suite);
    auto y = DHPrivateKey::derive(suite, { 0, 1, 2, 3 });

    REQUIRE(x == x);
    REQUIRE(y == y);
    REQUIRE(x != y);

    auto gX = x.public_key();
    auto gY = y.public_key();
    REQUIRE(gX == gX);
    REQUIRE(gY == gY);
    REQUIRE(gX != gY);

    auto gXY = x.derive(gY);
    auto gYX = y.derive(gX);
    REQUIRE(gXY == gYX);
  }
}

TEST_CASE("Diffie-Hellman public keys serialize and deserialize", "[crypto]")
{
  std::vector<CipherSuite> suites{ CipherSuite::P256_SHA256_AES128GCM,
                                   CipherSuite::P521_SHA512_AES256GCM,
                                   CipherSuite::X25519_SHA256_AES128GCM,
                                   CipherSuite::X448_SHA512_AES256GCM };

  for (auto suite : suites) {
    auto x = DHPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key();

    SECTION("Directly")
    {
      DHPublicKey parsed(suite, gX.to_bytes());
      REQUIRE(parsed == gX);
    }

    SECTION("Via TLS syntax")
    {
      DHPublicKey gX2(suite);
      tls::unmarshal(tls::marshal(gX), gX2);
      REQUIRE(gX2 == gX);
    }
  }
}

TEST_CASE("Diffie-Hellman key pairs encrypt and decrypt ECIES", "[crypto]")
{
  std::vector<CipherSuite> suites{ CipherSuite::P256_SHA256_AES128GCM,
                                   CipherSuite::P521_SHA512_AES256GCM,
                                   CipherSuite::X25519_SHA256_AES128GCM,
                                   CipherSuite::X448_SHA512_AES256GCM };

  for (auto suite : suites) {
    auto x = DHPrivateKey::derive(CIPHERSUITE, { 0, 1, 2, 3 });
    auto gX = x.public_key();

    auto original = random_bytes(100);
    auto encrypted = gX.encrypt(original);
    auto decrypted = x.decrypt(encrypted);

    REQUIRE(original == decrypted);
  }
}

TEST_CASE("Signature key pairs can sign and verify", "[crypto]")
{
  std::vector<SignatureScheme> schemes{ SignatureScheme::P256_SHA256,
                                        SignatureScheme::P521_SHA512,
                                        SignatureScheme::Ed25519,
                                        SignatureScheme::Ed448 };

  for (auto scheme : schemes) {
    auto a = SignaturePrivateKey::generate(scheme);
    auto b = SignaturePrivateKey::generate(scheme);

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

TEST_CASE("Signature public keys serialize and deserialize", "[crypto]")
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

    SECTION("Directly")
    {
      SignaturePublicKey parsed(scheme, gX.to_bytes());
      REQUIRE(parsed == gX);
    }

    SECTION("Via TLS syntax")
    {
      SignaturePublicKey gX2(scheme);
      tls::unmarshal(tls::marshal(gX), gX2);
      REQUIRE(gX2 == gX);
    }
  }
}
