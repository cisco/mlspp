#include <doctest/doctest.h>
#include <mls_vectors/mls_vectors.h>

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
  auto tv = TreeMathTestVector::create(256);
  REQUIRE(!TreeMathTestVector::verify(tv));
}

TEST_CASE("Encryption Keys")
{
  for (auto suite : supported_suites) {
    auto tv = EncryptionKeyTestVector::create(suite, 15, 10);
    REQUIRE(!EncryptionKeyTestVector::verify(tv));
  }
}

TEST_CASE("Key Schedule")
{
  for (auto suite : supported_suites) {
    auto tv = KeyScheduleTestVector::create(suite, 15);
    REQUIRE(!KeyScheduleTestVector::verify(tv));
  }
}

TEST_CASE("Tree Hashing")
{
  for (auto suite : supported_suites) {
    auto tv = TreeHashingTestVector::create(suite, 10);
    REQUIRE(!TreeHashingTestVector::verify(tv));
  }
}

TEST_CASE("Messages")
{
  auto tv = MessagesTestVector::create();
  REQUIRE(!MessagesTestVector::verify(tv));
}
