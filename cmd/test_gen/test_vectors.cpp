#include "test_vectors.h"

#include <fstream>

using namespace mls;

///
/// TreeMathTestVectors
///

const std::string TreeMathTestVectors::file_name = "./tree_math.bin";

tls::istream&
operator>>(tls::istream& str, TreeMathTestVectors& val)
{
  return str >> val.root >> val.left >> val.right >> val.parent >> val.sibling;
}

tls::ostream&
operator<<(tls::ostream& str, const TreeMathTestVectors& val)
{
  return str << val.root << val.left << val.right << val.parent << val.sibling;
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
    load_test(_vectors.tree);
  }

  return _vectors;
}

void
TestVectors::dump()
{
  dump_test(tree);
}

