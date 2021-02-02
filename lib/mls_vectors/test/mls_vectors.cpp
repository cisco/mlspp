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

TEST_CASE("Tree Math")
{
  const auto tv = TreeMathTestVector::create(256);
  REQUIRE(tv.verify() == std::nullopt);
}

TEST_CASE("Encryption Keys")
{
  for (auto suite : supported_suites) {
    const auto tv = EncryptionTestVector::create(suite, 15, 10);
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Key Schedule")
{
  for (auto suite : supported_suites) {
    const auto tv = KeyScheduleTestVector::create(suite, 15);
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Transcript")
{
  for (auto suite : supported_suites) {
    const auto tv = TranscriptTestVector::create(suite);
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("TreeKEM")
{
  for (auto suite : supported_suites) {
    const auto tv = TreeKEMTestVector::create(suite, 10);
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Messages")
{
  auto tv = MessagesTestVector::create();
  REQUIRE(tv.verify() == std::nullopt);
}
