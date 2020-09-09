#include "test_vectors.h"

#include <fstream>
#include <iterator>

using namespace mls;

///
/// File names
///

const std::string TreeMathTestVectors::file_name = "./tree_math.bin";
const std::string CryptoTestVectors::file_name = "./crypto.bin";
const std::string HashRatchetTestVectors::file_name = "./hash_ratchet.bin";
const std::string KeyScheduleTestVectors::file_name = "./key_schedule.bin";
const std::string TreeKEMTestVectors::file_name = "./treekem.bin";
const std::string MessagesTestVectors::file_name = "./messages.bin";

///
/// Test for deterministic signatures
///

bool
deterministic_signature_scheme(const CipherSuite& suite)
{
  switch (suite.id) {
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

bytes
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

template struct TestLoader<TreeMathTestVectors>;
template struct TestLoader<CryptoTestVectors>;
template struct TestLoader<HashRatchetTestVectors>;
template struct TestLoader<KeyScheduleTestVectors>;
template struct TestLoader<TreeKEMTestVectors>;
template struct TestLoader<MessagesTestVectors>;
