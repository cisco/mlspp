#include "crypto.h"
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
    auto data = tls::marshal(gX);
    REQUIRE(data == from_hex(header + raw));

    DHPublicKey gX2;
    tls::unmarshal(data, gX2);
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE("Diffie-Hellman private keys serialize and deserialize", "[crypto]")
{
  auto x = DHPrivateKey::derive({ 0, 1, 2, 3 });

  std::string raw =
    "200dd712c4747615f155efdd48a3f9e6c9f50de785d9bb1b9d4f99583ff248133f"
    "4104"
    "5e2808231accb273fcb6d6fc1d0954e72239628a8e2ba2e5c7cb9c299f98e747"
    "b185023591e72c2aaa7147a3c273140523675235bd1ba8549046fb39545d4e47";

  auto marshaled = tls::marshal(x);
  REQUIRE(marshaled == from_hex(raw));

  DHPrivateKey x2;
  tls::unmarshal(marshaled, x2);
  REQUIRE(x2 == x);
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

TEST_CASE("Signature private keys serialize and deserialize", "[crypto]")
{
  auto x = SignaturePrivateKey::generate();

  SignaturePrivateKey x2;
  tls::unmarshal(tls::marshal(x), x2);
  REQUIRE(x2 == x);
}
