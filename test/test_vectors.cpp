#include "test_vectors.h"

#include <fstream>
#include <iterator>

using namespace mls;

///
/// Ciphersuites
///

std::array<CipherSuite, 6> all_cipher_suites = { {
  { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
  { CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519 },
  { CipherSuite::ID::X448_AES256GCM_SHA512_Ed448 },
  { CipherSuite::ID::P521_AES256GCM_SHA512_P521 },
  { CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448 },
} };

///
/// File names
///

const std::string CryptoTestVectors::file_name = "./crypto.bin";
const std::string TreeKEMTestVectors::file_name = "./treekem.bin";
const std::string MessagesTestVectors::file_name = "./messages.bin";

///
/// Test for deterministic signatures
///

bool
deterministic_signature_scheme(const CipherSuite& suite)
{
  switch (suite.cipher_suite()) {
    case CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519:
    case CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519:
    case CipherSuite::ID::X448_AES256GCM_SHA512_Ed448:
    case CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448:
      return true;

    default:
      return false;
  }
}

///
/// File Handling
///

static bytes
read_file(const std::string& filename)
{
  std::ifstream file(filename, std::ios::binary);

  file.unsetf(std::ios::skipws);

  std::streampos fileSize;
  file.seekg(0, std::ios::end);
  fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  bytes vec;
  vec.reserve(fileSize);
  vec.insert(vec.begin(),
             std::istream_iterator<uint8_t>(file),
             std::istream_iterator<uint8_t>());

  return vec;
}

template<typename T>
void
load_test(T& val)
{
  auto ser = read_file(T::file_name);
  tls::unmarshal(ser, val);
}

///
/// TestLoader
///

template<typename T>
bool TestLoader<T>::_initialized = false;

template<typename T>
T TestLoader<T>::_vectors;

template<typename T>
const T&
TestLoader<T>::get()
{
  if (!_initialized) {
    load_test(_vectors);
    _initialized = true;
  }

  return _vectors;
}

template struct TestLoader<CryptoTestVectors>;
template struct TestLoader<TreeKEMTestVectors>;
template struct TestLoader<MessagesTestVectors>;
