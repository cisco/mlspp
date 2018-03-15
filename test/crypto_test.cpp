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

TEST_CASE("AES-GCM encryption and decryption work", "[crypto]")
{
  auto key = from_hex("000102030405060708090a0b0c0d0e0f");
  auto iv = from_hex("101112131010101010101010");
  uint64_t seq = 0x0405060708090a0b;

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

TEST_CASE("Diffie-Hellman private keys serialize and deserialize", "[crypto]")
{
  auto x = DHPrivateKey::derive({ 0, 1, 2, 3 });

  std::string raw =
    "3082016802010104200dd712c4747615f155efdd48a3f9e6c9f50de785d9bb1b"
    "9d4f99583ff248133fa081fa3081f7020101302c06072a8648ce3d0101022100"
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    "305b0420ffffffff00000001000000000000000000000000ffffffffffffffff"
    "fffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce"
    "3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e90044104"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    "022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc"
    "632551020101a144034200045e2808231accb273fcb6d6fc1d0954e72239628a"
    "8e2ba2e5c7cb9c299f98e747b185023591e72c2aaa7147a3c273140523675235"
    "bd1ba8549046fb39545d4e47";
  std::string header = "016c";

  SECTION("Directly")
  {
    auto data = x.to_bytes();
    REQUIRE(data == from_hex(raw));

    DHPrivateKey parsed(data);
    // XXX REQUIRE(parsed == x);
  }

  SECTION("Via TLS syntax")
  {
    auto marshaled = tls::marshal(x);
    REQUIRE(marshaled == from_hex(header + raw));

    DHPrivateKey x2;
    tls::unmarshal(marshaled, x2);
    // XXX REQUIRE(x2 == x);
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

TEST_CASE("Signature private keys serialize and deserialize", "[crypto]")
{
  auto x = SignaturePrivateKey::generate();

  SECTION("Directly")
  {
    auto data = x.to_bytes();
    SignaturePrivateKey parsed(data);
    // XXX REQUIRE(parsed == x);
  }

  SECTION("Via TLS syntax")
  {
    tls::ostream w;
    w << x;

    tls::istream r(w.bytes());
    SignaturePrivateKey x2;
    r >> x2;
    // XXX REQUIRE(x2 == x);
  }
}
