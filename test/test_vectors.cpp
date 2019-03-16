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
  return str >> obj.n_leaves >> obj.root >> obj.left >> obj.right >>
         obj.parent >> obj.sibling;
}

tls::ostream&
operator<<(tls::ostream& str, const TreeMathTestVectors& obj)
{
  return str << obj.n_leaves << obj.root << obj.left << obj.right << obj.parent
             << obj.sibling;
}

///
/// ResolutionTestVectors
///

const std::string ResolutionTestVectors::file_name = "./resolution.bin";

std::vector<bool>
ResolutionTestVectors::make_tree(uint32_t t, uint32_t n)
{
  auto vec = std::vector<bool>(n);
  for (int i = 0; i < vec.size(); ++i) {
    vec[i] = t & 1;
    t >>= 1;
  }
  return vec;
}

std::vector<uint8_t>
ResolutionTestVectors::compact(const std::vector<uint32_t>& res)
{
  std::vector<uint8_t> out(res.size());
  std::transform(res.begin(),
                 res.end(),
                 out.begin(),
                 [](uint32_t c) -> uint8_t { return c; });
  return out;
}

tls::istream&
operator>>(tls::istream& str, ResolutionTestVectors& tv)
{
  return str >> tv.n_leaves >> tv.cases;
}

tls::ostream&
operator<<(tls::ostream& str, const ResolutionTestVectors& tv)
{
  return str << tv.n_leaves << tv.cases;
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
         obj.ecies_plaintext >> obj.case_p256 >> obj.case_x25519;
}

tls::ostream&
operator<<(tls::ostream& str, const CryptoTestVectors& obj)
{
  return str << obj.hkdf_extract_salt << obj.hkdf_extract_ikm
             << obj.derive_secret_secret << obj.derive_secret_label
             << obj.derive_secret_length << obj.derive_key_pair_seed
             << obj.ecies_plaintext << obj.case_p256 << obj.case_x25519;
}

///
/// KeyScheduleTestVectors
///

const std::string KeyScheduleTestVectors::file_name = "./key_schedule.bin";

tls::istream&
operator>>(tls::istream& str, KeyScheduleTestVectors::Epoch& obj)
{
  return str >> obj.update_secret >> obj.epoch_secret >>
         obj.application_secret >> obj.confirmation_key >> obj.init_secret;
}

tls::ostream&
operator<<(tls::ostream& str, const KeyScheduleTestVectors::Epoch& obj)
{
  return str << obj.update_secret << obj.epoch_secret << obj.application_secret
             << obj.confirmation_key << obj.init_secret;
}

tls::istream&
operator>>(tls::istream& str, KeyScheduleTestVectors::TestCase& obj)
{
  return str >> obj.suite >> obj.epochs;
}

tls::ostream&
operator<<(tls::ostream& str, const KeyScheduleTestVectors::TestCase& obj)
{
  return str << obj.suite << obj.epochs;
}

tls::istream&
operator>>(tls::istream& str, KeyScheduleTestVectors& obj)
{
  return str >> obj.n_epochs >> obj.base_group_state >> obj.case_p256 >>
         obj.case_x25519;
}

tls::ostream&
operator<<(tls::ostream& str, const KeyScheduleTestVectors& obj)
{
  return str << obj.n_epochs << obj.base_group_state << obj.case_p256
             << obj.case_x25519;
}

///
/// AppKeyScheduleTestVectors
///

const std::string AppKeyScheduleTestVectors::file_name =
  "./app_key_schedule.bin";

tls::istream&
operator>>(tls::istream& str, AppKeyScheduleTestVectors::Step& obj)
{
  return str >> obj.secret >> obj.key >> obj.iv;
}

tls::ostream&
operator<<(tls::ostream& str, const AppKeyScheduleTestVectors::Step& obj)
{
  return str << obj.secret << obj.key << obj.iv;
}

tls::istream&
operator>>(tls::istream& str, AppKeyScheduleTestVectors& obj)
{
  return str >> obj.n_participants >> obj.n_messages >> obj.case_p256 >>
         obj.case_x25519;
}

tls::ostream&
operator<<(tls::ostream& str, const AppKeyScheduleTestVectors& obj)
{
  return str << obj.n_participants << obj.n_messages << obj.case_p256
             << obj.case_x25519;
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
         obj.case_p256_p256 >> obj.case_x25519_ed25519;
}

tls::ostream&
operator<<(tls::ostream& str, const MessagesTestVectors& obj)
{
  return str << obj.epoch << obj.signer_index << obj.removed << obj.user_id
             << obj.group_id << obj.uik_id << obj.dh_seed << obj.sig_seed
             << obj.random << obj.uik_all_scheme << obj.user_init_key_all
             << obj.case_p256_p256 << obj.case_x25519_ed25519;
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
         obj.case_x25519_ed25519;
}

tls::ostream&
operator<<(tls::ostream& str, const SessionTestVectors& obj)
{
  return str << obj.group_size << obj.group_id << obj.case_p256_p256
             << obj.case_x25519_ed25519;
}

const std::string BasicSessionTestVectors::file_name = "./basic_session.bin";

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
template struct TestLoader<ResolutionTestVectors>;
template struct TestLoader<CryptoTestVectors>;
template struct TestLoader<KeyScheduleTestVectors>;
template struct TestLoader<AppKeyScheduleTestVectors>;
template struct TestLoader<MessagesTestVectors>;
template struct TestLoader<BasicSessionTestVectors>;
