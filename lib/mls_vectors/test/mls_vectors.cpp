#include <doctest/doctest.h>
#include <mls_vectors/mls_vectors.h>
#include <tls/tls_syntax.h>

using namespace mls_vectors;

static const std::vector<mls::CipherSuite> supported_suites{
  { mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  { mls::CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
  { mls::CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519 },
  { mls::CipherSuite::ID::X448_AES256GCM_SHA512_Ed448 },
  { mls::CipherSuite::ID::P521_AES256GCM_SHA512_P521 },
  { mls::CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448 },
};

template<typename T>
T
tls_round_trip(const T& value)
{
  auto marshaled = tls::marshal(value);
  return tls::get<T>(marshaled);
}

TEST_CASE("Tree Math")
{
  const auto tv_in = TreeMathTestVector(256);
  const auto tv_out = tls_round_trip(tv_in);
  REQUIRE(tv_out.verify() == std::nullopt);
}

TEST_CASE("Encryption Keys")
{
  for (auto suite : supported_suites) {
    const auto tv_in = EncryptionKeyTestVector(suite, 15, 10);
    const auto tv_out = tls_round_trip(tv_in);
    REQUIRE(tv_out.verify() == std::nullopt);
  }
}

TEST_CASE("Key Schedule")
{
  for (auto suite : supported_suites) {
    auto tv_in = KeyScheduleTestVector(suite, 15);
    const auto tv_out = tls_round_trip(tv_in);
    REQUIRE(tv_out.verify() == std::nullopt);
  }
}

TEST_CASE("Tree Hashing")
{
  for (auto suite : supported_suites) {
    auto tv_in = TreeHashingTestVector(suite, 10);
    const auto tv_out = tls_round_trip(tv_in);
    REQUIRE(tv_out.verify() == std::nullopt);
  }
}

TEST_CASE("Messages")
{
  auto tv_in = MessagesTestVector();
  const auto tv_out = tls_round_trip(tv_in);
  REQUIRE(tv_out.verify() == std::nullopt);
}
