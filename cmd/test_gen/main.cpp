#include <mls/crypto.h>

#include "test_vectors.h"

#include <hpke/random.h>

#include <fstream>
#include <iostream>

static CryptoTestVectors
generate_crypto()
{
  CryptoTestVectors tv;

  std::vector<CipherSuite> suites{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  };

  tv.kdf_extract_salt = { 0, 1, 2, 3 };
  tv.kdf_extract_ikm = { 4, 5, 6, 7 };

  tv.derive_key_pair_seed = { 0, 1, 2, 3 };

  tv.hpke_aad = bytes(128, 0xB1);
  tv.hpke_plaintext = bytes(128, 0xB2);

  // Construct a test case for each suite
  for (auto suite : suites) {
    // kdf-Extract
    auto kdf_extract_out =
      suite.hpke().kdf.extract(tv.kdf_extract_salt, tv.kdf_extract_ikm);

    // Derive-Key-Pair
    auto priv = HPKEPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto derive_key_pair_pub = priv.public_key;

    // HPKE
    auto hpke_out =
      derive_key_pair_pub.encrypt(suite, tv.hpke_aad, tv.hpke_plaintext);

    tv.cases.push_back(
      { suite, kdf_extract_out, derive_key_pair_pub, hpke_out });
  }

  return tv;
}

template<typename T>
void
write_test_vectors(const T& vectors)
{
  auto marshaled = tls::marshal(vectors);

  std::ofstream file(T::file_name, std::ios::out | std::ios::binary);
  if (!file) {
    throw std::invalid_argument("Could not create ofstream for: " +
                                T::file_name);
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const auto* data = reinterpret_cast<const char*>(marshaled.data());
  file.write(data, marshaled.size());
}

template<typename T>
void
verify_equal_marshaled(const T& lhs, const T& rhs)
{
  auto lhsb = tls::marshal(lhs);
  auto rhsb = tls::marshal(rhs);
  if (lhsb != rhsb) {
    throw std::runtime_error("difference in marshaled values");
  }
}

template<typename F>
void
verify_reproducible(const F& generator)
{
  auto v0 = generator();
  auto v1 = generator();
  verify_equal_marshaled(v0, v1);
}

int
main() // NOLINT(bugprone-exception-escape)
{
  auto crypto = generate_crypto();
  write_test_vectors(crypto);

  // Verify that the test vectors load
  try {
    TestLoader<CryptoTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
