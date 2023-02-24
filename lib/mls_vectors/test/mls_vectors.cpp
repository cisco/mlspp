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
  const auto tv = TreeMathTestVector{ 15 };
  REQUIRE(tv.verify() == std::nullopt);
}

TEST_CASE("Crypto Basics")
{
  for (auto suite : supported_suites) {
    const auto tv = CryptoBasicsTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Secret Tree")
{
  for (auto suite : supported_suites) {
    const auto tv = SecretTreeTestVector{ suite, 15, { 10 } };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Key Schedule")
{
  for (auto suite : supported_suites) {
    const auto tv = KeyScheduleTestVector{ suite, 15 };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Message Protection")
{
  for (auto suite : supported_suites) {
    auto tv = MessageProtectionTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("PSK Secret")
{
  for (auto suite : supported_suites) {
    const auto tv = PSKSecretTestVector{ suite, 5 };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Transcript")
{
  for (auto suite : supported_suites) {
    const auto tv = TranscriptTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Welcome")
{
  for (auto suite : supported_suites) {
    const auto tv = WelcomeTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Tree Hashes")
{
  for (auto suite : supported_suites) {
    for (auto structure : all_tree_structures) {
      auto tv = TreeHashTestVector{ suite, structure };
      REQUIRE(tv.verify() == std::nullopt);
    }
  }
}

TEST_CASE("Tree Operations")
{
  auto suite = mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519;
  for (auto scenario : TreeOperationsTestVector::all_scenarios) {
    auto tv = TreeOperationsTestVector{ suite, scenario };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("TreeKEM")
{
  for (auto suite : supported_suites) {
    for (auto structure : treekem_test_tree_structures) {
      auto tv = TreeKEMTestVector{ suite, structure };
      REQUIRE(tv.verify() == std::nullopt);
    }
  }
}

TEST_CASE("Messages")
{
  auto tv = MessagesTestVector();
  REQUIRE(tv.verify() == std::nullopt);
}
