#include "test_vectors.h"

#include <fstream>

using namespace mls;

///
/// TreeMathTestVectors
///

const std::string TreeMathTestVectors::file_name = "./tree_math.bin";

tls::istream&
operator>>(tls::istream& str, TreeMathTestVectors& obj)
{
  return str >> obj.root >> obj.left >> obj.right >> obj.parent >> obj.sibling;
}

tls::ostream&
operator<<(tls::ostream& str, const TreeMathTestVectors& obj)
{
  return str << obj.root << obj.left << obj.right << obj.parent << obj.sibling;
}

///
/// CryptoTestVectors
///

const std::string CryptoTestVectors::file_name = "./crypto.bin";

tls::istream&
operator>>(tls::istream& str, CryptoTestVectors::TestCase& obj)
{
  return str >> obj.hkdf_extract_out >> obj.derive_secret_state >>
         obj.derive_secret_out >> obj.derive_key_pair_pub >> obj.ecies_out;
}

tls::ostream&
operator<<(tls::ostream& str, const CryptoTestVectors::TestCase& obj)
{
  return str << obj.hkdf_extract_out << obj.derive_secret_state
             << obj.derive_secret_out << obj.derive_key_pair_pub
             << obj.ecies_out;
}

tls::istream&
operator>>(tls::istream& str, CryptoTestVectors& obj)
{
  return str >> obj.hkdf_extract_salt >> obj.hkdf_extract_ikm >>
         obj.derive_secret_secret >> obj.derive_secret_label >>
         obj.derive_secret_length >> obj.derive_key_pair_seed >>
         obj.ecies_plaintext >> obj.case_p256 >> obj.case_x25519 >>
         obj.case_p521 >> obj.case_x448;
}

tls::ostream&
operator<<(tls::ostream& str, const CryptoTestVectors& obj)
{
  return str << obj.hkdf_extract_salt << obj.hkdf_extract_ikm
             << obj.derive_secret_secret << obj.derive_secret_label
             << obj.derive_secret_length << obj.derive_key_pair_seed
             << obj.ecies_plaintext << obj.case_p256 << obj.case_x25519
             << obj.case_p521 << obj.case_x448;
}

///
/// MessagesTestVectors
///

const std::string MessagesTestVectors::file_name = "./messages.bin";

tls::istream&
operator>>(tls::istream& str, MessagesTestVectors::TestCase& obj)
{
  return str >> obj.cipher_suite >> obj.user_init_key >> obj.welcome >>
         obj.add >> obj.update >> obj.remove;
}

tls::ostream&
operator<<(tls::ostream& str, const MessagesTestVectors::TestCase& obj)
{
  return str << obj.cipher_suite << obj.user_init_key << obj.welcome << obj.add
             << obj.update << obj.remove;
}

tls::istream&
operator>>(tls::istream& str, MessagesTestVectors& obj)
{
  return str >> obj.user_init_key_all >> obj.case_p256_p256 >>
         obj.case_x25519_ed25519 >> obj.case_p521_p521 >> obj.case_x448_ed448;
}

tls::ostream&
operator<<(tls::ostream& str, const MessagesTestVectors& obj)
{
  return str << obj.user_init_key_all << obj.case_p256_p256
             << obj.case_x25519_ed25519 << obj.case_p521_p521
             << obj.case_x448_ed448;
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

void
write_file(const std::string& filename, const bytes& vec)
{
  std::ofstream file(filename, std::ios::out | std::ios::binary);
  if (!file) {
    throw std::invalid_argument("Could not create ofstream for: " + filename);
  }

  file.write(reinterpret_cast<const char*>(vec.data()), vec.size());
}

template<typename T>
void
load_test(T& val)
{
  auto ser = read_file(T::file_name);
  tls::unmarshal(ser, val);
}

template<typename T>
void
dump_test(const T& val)
{
  auto ser = tls::marshal(val);
  write_file(T::file_name, ser);
}

///
/// TestVectors
///

bool TestVectors::_initialized = false;
TestVectors TestVectors::_vectors = TestVectors();

const TestVectors&
TestVectors::get()
{
  if (!_initialized) {
    load_test(_vectors.tree_math);
    load_test(_vectors.crypto);
    load_test(_vectors.messages);
  }

  return _vectors;
}

void
TestVectors::dump()
{
  dump_test(tree_math);
  dump_test(crypto);
  dump_test(messages);
}
