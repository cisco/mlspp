#include "test_vectors.h"

#include <fstream>
#include <iterator>

using namespace mls;

///
/// File names
///

const std::string TreeMathTestVectors::file_name = "./tree_math.bin";
const std::string ResolutionTestVectors::file_name = "./resolution.bin";
const std::string CryptoTestVectors::file_name = "./crypto.bin";
const std::string KeyScheduleTestVectors::file_name = "./key_schedule.bin";
const std::string AppKeyScheduleTestVectors::file_name =
  "./app_key_schedule.bin";
const std::string TreeTestVectors::file_name = "./tree.bin";
const std::string MessagesTestVectors::file_name = "./messages.bin";
const std::string BasicSessionTestVectors::file_name = "./basic_session.bin";

///
/// ResolutionTestVectors
///

std::vector<bool>
ResolutionTestVectors::make_tree(uint32_t t, NodeCount w)
{
  auto vec = std::vector<bool>(w.val);
  for (size_t i = 0; i < vec.size(); ++i) {
    vec[i] = t & 1;
    t >>= 1;
  }
  return vec;
}

std::vector<uint8_t>
ResolutionTestVectors::compact(const std::vector<NodeIndex>& res)
{
  std::vector<uint8_t> out(res.size());
  std::transform(res.begin(),
                 res.end(),
                 out.begin(),
                 [](NodeIndex c) -> uint8_t { return c.val; });
  return out;
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
template struct TestLoader<ResolutionTestVectors>;
template struct TestLoader<CryptoTestVectors>;
template struct TestLoader<KeyScheduleTestVectors>;
template struct TestLoader<AppKeyScheduleTestVectors>;
template struct TestLoader<TreeTestVectors>;
template struct TestLoader<MessagesTestVectors>;
template struct TestLoader<BasicSessionTestVectors>;
