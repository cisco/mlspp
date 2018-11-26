#include "crypto.h"
#include <catch.hpp>
#include <iostream>
#include <string>

using namespace mls;

TEST_CASE("SHA-256 hash produces correct values", "[crypto]")
{
  uint8_t byte = 0x42;
  auto data = from_hex("01020304");

  SECTION("For a single byte")
  {
    std::string answer =
      "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c";
    REQUIRE(SHA256Digest(byte).digest() == from_hex(answer));
  }

  SECTION("For a byte string")
  {
    std::string answer =
      "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a";
    REQUIRE(SHA256Digest(data).digest() == from_hex(answer));
  }

  SECTION("For input in multiple chunks")
  {
    std::string answer =
      "76a952f18b6c638b028860087e7840a9cc43ed1af489d62a51c71984266789d6";
    REQUIRE(SHA256Digest(byte).write(data).digest() == from_hex(answer));
  }
}

TEST_CASE("AES-GCM encryption produces correct values", "[crypto]")
{
  // https://tools.ietf.org/html/draft-mcgrew-gcm-test-01#section-4
  auto key = from_hex("4c80cdefbb5d10da906ac73c3613a634");
  auto nonce = from_hex("2e443b684956ed7e3b244cfe");
  auto aad = from_hex("000043218765432100000000");
  auto plaintext = from_hex("45000048699a000080114db7c0a80102"
                            "c0a801010a9bf15638d3010000010000"
                            "00000000045f736970045f7564700373"
                            "69700963796265726369747902646b00"
                            "0021000101020201");
  auto ciphertext = from_hex("fecf537e729d5b07dc30df528dd22b76"
                             "8d1b98736696a6fd348509fa13ceac34"
                             "cfa2436f14a3f3cf65925bf1f4a13c5d"
                             "15b21e1884f5ff6247aeabb786b93bce"
                             "61bc17d768fd9732459018148f6cbe72"
                             "2fd04796562dfdb4");

  SECTION("For encryption")
  {
    AESGCM gcm(key, nonce);
    gcm.set_aad(aad);
    REQUIRE(gcm.encrypt(plaintext) == ciphertext);
  }

  SECTION("For decryption")
  {
    AESGCM gcm(key, nonce);
    gcm.set_aad(aad);
    REQUIRE(gcm.decrypt(ciphertext) == plaintext);
  }

  SECTION("For an encrypt/decrypt round-trip")
  {
    auto key = random_bytes(AESGCM::key_size_256);
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

TEST_CASE("Diffie-Hellman key pairs can be created and combined", "[crypto]")
{
  auto x = DHPrivateKey::generate();
  auto y = DHPrivateKey::derive({ 0, 1, 2, 3 });

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

TEST_CASE("Diffie-Hellman public keys serialize and deserialize", "[crypto]")
{
  auto x = DHPrivateKey::derive({ 0, 1, 2, 3 });
  auto gX = x.public_key();

  SECTION("Directly")
  {
    DHPublicKey parsed(gX.to_bytes());
    REQUIRE(parsed == gX);
  }

  SECTION("Via TLS syntax")
  {
    DHPublicKey gX2;
    tls::unmarshal(tls::marshal(gX), gX2);
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE("Diffie-Hellman key pairs encrypt and decrypt ECIES", "[crypto]")
{
  auto x = DHPrivateKey::derive({ 0, 1, 2, 3 });
  auto gX = x.public_key();

  auto original = random_bytes(100);
  auto encrypted = gX.encrypt(original);
  auto decrypted = x.decrypt(encrypted);

  REQUIRE(original == decrypted);
}

TEST_CASE("Signature key pairs can sign and verify", "[crypto]")
{
  auto a = SignaturePrivateKey::generate();
  auto b = SignaturePrivateKey::generate();

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

TEST_CASE("Signature public keys serialize and deserialize", "[crypto]")
{
  auto x = SignaturePrivateKey::generate();
  auto gX = x.public_key();

  SECTION("Directly")
  {
    SignaturePublicKey parsed(gX.to_bytes());
    REQUIRE(parsed == gX);
  }

  SECTION("Via TLS syntax")
  {
    SignaturePublicKey gX2;
    tls::unmarshal(tls::marshal(gX), gX2);
    REQUIRE(gX2 == gX);
  }
}
