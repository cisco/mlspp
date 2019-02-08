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
/// ResolutionTestVectors
///

const std::string ResolutionTestVectors::file_name = "./resolution.bin";

tls::istream&
operator>>(tls::istream& str, ResolutionTestVectors& tv)
{
  return str >> tv.cases;
}

tls::ostream&
operator<<(tls::ostream& str, const ResolutionTestVectors& tv)
{
  return str << tv.cases;
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
  return str >> obj.cipher_suite >> obj.sig_scheme >> obj.user_init_key >>
         obj.welcome_info >> obj.welcome >> obj.add >> obj.update >> obj.remove;
}

tls::ostream&
operator<<(tls::ostream& str, const MessagesTestVectors::TestCase& obj)
{
  return str << obj.cipher_suite << obj.sig_scheme << obj.user_init_key
             << obj.welcome_info << obj.welcome << obj.add << obj.update
             << obj.remove;
}

tls::istream&
operator>>(tls::istream& str, MessagesTestVectors& obj)
{
  return str >> obj.epoch >> obj.signer_index >> obj.removed >> obj.user_id >>
         obj.group_id >> obj.uik_id >> obj.dh_seed >> obj.sig_seed >>
         obj.random >> obj.uik_all_scheme >> obj.user_init_key_all >>
         obj.case_p256_p256 >> obj.case_x25519_ed25519 >> obj.case_p521_p521 >>
         obj.case_x448_ed448;
}

tls::ostream&
operator<<(tls::ostream& str, const MessagesTestVectors& obj)
{
  return str << obj.epoch << obj.signer_index << obj.removed << obj.user_id
             << obj.group_id << obj.uik_id << obj.dh_seed << obj.sig_seed
             << obj.random << obj.uik_all_scheme << obj.user_init_key_all
             << obj.case_p256_p256 << obj.case_x25519_ed25519
             << obj.case_p521_p521 << obj.case_x448_ed448;
}

///
/// SessionTestVectors
///

tls::istream&
operator>>(tls::istream& str, SessionTestVectors::Epoch& obj)
{
  return str >> obj.welcome >> obj.handshake >> obj.epoch >> obj.epoch_secret >>
         obj.application_secret >> obj.confirmation_key >> obj.init_secret;
}

tls::ostream&
operator<<(tls::ostream& str, const SessionTestVectors::Epoch& obj)
{
  return str << obj.welcome << obj.handshake << obj.epoch << obj.epoch_secret
             << obj.application_secret << obj.confirmation_key
             << obj.init_secret;
}

tls::istream&
operator>>(tls::istream& str, SessionTestVectors::TestCase& obj)
{
  return str >> obj.cipher_suite >> obj.sig_scheme >> obj.user_init_keys >>
         obj.transcript;
}

tls::ostream&
operator<<(tls::ostream& str, const SessionTestVectors::TestCase& obj)
{
  return str << obj.cipher_suite << obj.sig_scheme << obj.user_init_keys
             << obj.transcript;
}

tls::istream&
operator>>(tls::istream& str, SessionTestVectors& obj)
{
  return str >> obj.group_size >> obj.group_id >> obj.case_p256_p256 >>
         obj.case_x25519_ed25519 >> obj.case_p521_p521 >> obj.case_x448_ed448;
}

tls::ostream&
operator<<(tls::ostream& str, const SessionTestVectors& obj)
{
  return str << obj.group_size << obj.group_id << obj.case_p256_p256
             << obj.case_x25519_ed25519 << obj.case_p521_p521
             << obj.case_x448_ed448;
}

const std::string BasicSessionTestVectors::file_name = "./basic_session.bin";

///
/// File Handling
///

const size_t max_file_size = 1 << 19; // 512KB

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

// TODO delete
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

template class TestLoader<TreeMathTestVectors>;
template class TestLoader<CryptoTestVectors>;
template class TestLoader<MessagesTestVectors>;
template class TestLoader<BasicSessionTestVectors>;
