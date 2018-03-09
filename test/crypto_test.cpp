#include "crypto.h"
#include "hex.h"
#include <catch.hpp>
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

TEST_CASE("AES-GCM encryption and decryption work", "[crypto]")
{
  auto key = from_hex("000102030405060708090a0b0c0d0e0f");
  auto iv = from_hex("10111213141010101010101010");
  uint64_t seq = 0x05060708090a0b0c;

  auto plaintext = from_hex("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");
  auto ciphertext = from_hex("648ea30fafef164fb77dfd5567874b9e"
                             "ad4b7fadfcf349e07a1336c7e313ec29");

  auto encrypted = aes_gcm_encrypt(seq, key, iv, plaintext);
  REQUIRE(encrypted == ciphertext);

  auto decrypted = aes_gcm_decrypt(seq, key, iv, ciphertext);
  REQUIRE(decrypted == plaintext);
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

  std::string raw =
    "045e2808231accb273fcb6d6fc1d0954e72239628a8e2ba2e5c7cb9c299f98e74"
    "7b185023591e72c2aaa7147a3c273140523675235bd1ba8549046fb39545d4e47";
  std::string header = "0041";

  SECTION("Directly")
  {
    auto data = gX.to_bytes();
    REQUIRE(data == from_hex(raw));

    DHPublicKey parsed(data);
    REQUIRE(parsed == gX);
  }

  SECTION("Via TLS syntax")
  {
    tls::ostream w;
    w << gX;
    REQUIRE(w.bytes() == from_hex(header + raw));

    tls::istream r(w.bytes());
    DHPublicKey gX2;
    r >> gX2;
    REQUIRE(gX2 == gX);
  }
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
    auto data = gX.to_bytes();
    SignaturePublicKey parsed(data);
    REQUIRE(parsed == gX);
  }

  SECTION("Via TLS syntax")
  {
    tls::ostream w;
    w << gX;

    tls::istream r(w.bytes());
    SignaturePublicKey gX2;
    r >> gX2;
    REQUIRE(gX2 == gX);
  }
}
