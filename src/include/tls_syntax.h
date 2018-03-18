#pragma once

#include <algorithm>
#include <array>
#include <map>
#include <vector>

// Note: Different namespace because this is TLS-generic (might
// want to pull it out later).  Also, avoids confusables ending up
// in the global namespace, e.g., vector, istream, ostream.
namespace tls {

// For indicating no min or max in vector definitions
const size_t none = -1;

class WriteError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class ReadError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

// A vector type that knows the length of its header and optionally
// min and max lengths.  Otherwise identical to std::vector<T>.
//
// Tagging the type with head/min/max ensures symmetry in
// encode/decode, with a simple API.  The cost is that new code gets
// generated for every head/min/max combination.
template<typename T, size_t head, size_t min = none, size_t max = none>
class vector : public std::vector<T>
{
public:
  typedef std::vector<T> parent;

  // Explicitly import constructors
  using parent::parent;
  vector(const parent& other)
    : parent(other)
  {}
  vector(parent&& other)
    : parent(other)
  {}
  vector()
    : parent()
  {}
};

template<size_t head, size_t min = tls::none, size_t max = tls::none>
using opaque = vector<uint8_t, head, min, max>;

class ostream
{
public:
  static const size_t none = -1;

  void write_raw(const std::vector<uint8_t>& bytes);

  std::vector<uint8_t> bytes() const { return _buffer; }

private:
  std::vector<uint8_t> _buffer;
  ostream& write_uint(uint64_t value, int length);

  friend ostream& operator<<(ostream& out, uint8_t data);
  friend ostream& operator<<(ostream& out, uint16_t data);
  friend ostream& operator<<(ostream& out, uint32_t data);
  friend ostream& operator<<(ostream& out, uint64_t data);

  template<typename T, size_t N>
  friend ostream& operator<<(ostream& out, const std::array<T, N>& data);

  template<typename T, size_t head, size_t min, size_t max>
  friend ostream& operator<<(ostream& out,
                             const vector<T, head, min, max>& data);
};

// Primitive writers defined in .cpp file

// Array writer
template<typename T, size_t N>
ostream&
operator<<(ostream& out, const std::array<T, N>& data)
{
  for (const auto& item : data) {
    out << item;
  }
  return out;
}

// Vector writer
template<typename T, size_t head, size_t min, size_t max>
ostream&
operator<<(ostream& out, const vector<T, head, min, max>& data)
{
  uint64_t head_max = 0;
  switch (head) {
    case 1:
      head_max = 0xff;
      break;
    case 2:
      head_max = 0xffff;
      break;
    case 3:
      head_max = 0xffffff;
      break;
    case 4:
      head_max = 0xffffffff;
      break;
    default:
      throw WriteError("Invalid header size");
  }

  // Pre-encode contents
  ostream temp;
  for (const auto& item : data) {
    temp << item;
  }

  // Check that the encoded length is OK
  uint64_t size = temp._buffer.size();
  if (size > head_max) {
    throw WriteError("Data too large for header size");
  } else if ((max != none) && (size > max)) {
    throw WriteError("Data too large for declared max");
  } else if ((min != none) && (size < min)) {
    throw WriteError("Data too small for declared min");
  }

  // Write the encoded length, then the pre-encoded data
  out.write_uint(size, head);
  out._buffer.insert(
    out._buffer.end(), temp._buffer.begin(), temp._buffer.end());

  return out;
}

// Pair writer (same as two adjacent elements in a struct)
template<typename T1, typename T2>
ostream&
operator<<(ostream& out, const std::pair<T1, T2>& data)
{
  return out << data.first << data.second;
}

// Map writer
// XXX(rlb@ipv.sx) This is non-standard, and probably should be,
// because it's non-canonical.  But it's good enough for using TLS
// syntax to save and reconstitue objects.
template<typename Key, typename T>
ostream&
operator<<(ostream& out, const std::map<Key, T>& data)
{
  // XXX(rlb@ipv.sx) This causes an extra copy, but saves some
  // subtle messing around with constructors in tls::vector.
  std::vector<std::pair<Key, T>> vec(data.begin(), data.end());
  vector<std::pair<Key, T>, 3> tls_vec = vec;
  return out << tls_vec;
}

class istream
{
public:
  istream(const std::vector<uint8_t>& data)
    : _buffer(data)
  {
    // So that we can use the constant-time pop_back
    std::reverse(_buffer.begin(), _buffer.end());
  }

private:
  istream() {}
  std::vector<uint8_t> _buffer;
  uint8_t next();

  template<typename T>
  istream& read_uint(T& data, int length);

  friend istream& operator>>(istream& in, uint8_t& data);
  friend istream& operator>>(istream& in, uint16_t& data);
  friend istream& operator>>(istream& in, uint32_t& data);
  friend istream& operator>>(istream& in, uint64_t& data);

  template<typename T, size_t N>
  friend istream& operator>>(istream& in, std::array<T, N>& data);

  template<typename T, size_t head, size_t min, size_t max>
  friend istream& operator>>(istream& in, vector<T, head, min, max>& data);
};

// Primitive type readers defined in .cpp file

// Array reader
template<typename T, size_t N>
istream&
operator>>(istream& in, std::array<T, N>& data)
{
  for (auto& item : data) {
    in >> item;
  }
  return in;
}

// Vector reader
template<typename T, size_t head, size_t min, size_t max>
istream&
operator>>(istream& in, vector<T, head, min, max>& data)
{
  switch (head) {
    case 1: // fallthrough
    case 2: // fallthrough
    case 3: // fallthrough
    case 4:
      break;
    default:
      throw ReadError("Invalid header size");
  }

  // Read the size of the vector and check it against the
  // declared constraints
  uint64_t size = 0;
  in.read_uint(size, head);
  if (size > in._buffer.size()) {
    throw ReadError("Declared size exceeds available data size");
  } else if ((max != none) && (size > max)) {
    throw ReadError("Data too large for declared max");
  } else if ((min != none) && (size < min)) {
    throw ReadError("Data too small for declared min");
  }

  // Truncate the buffer to the declared length and wrap it in a
  // new reader, then read items from it
  // NB: Remember that we store the vector in reverse order
  // NB: This requires that T be default-constructible
  std::vector<uint8_t> trunc(in._buffer.end() - size, in._buffer.end());
  istream r;
  r._buffer = trunc;
  while (r._buffer.size() > 0) {
    T temp;
    r >> temp;
    data.push_back(temp);
  }

  // Truncate the primary buffer
  in._buffer.erase(in._buffer.end() - size, in._buffer.end());

  return in;
}

// Pair reader (same as two adjacent elements in a struct)
template<typename T1, typename T2>
istream&
operator>>(istream& in, std::pair<T1, T2>& data)
{
  return in >> data.first >> data.second;
}

// Map reader
// XXX(rlb@ipv.sx) This is non-standard, and probably should be,
// because it's non-canonical.  But it's good enough for using TLS
// syntax to save and reconstitute objects.
template<typename Key, typename T>
istream&
operator>>(istream& in, std::map<Key, T>& data)
{
  vector<std::pair<Key, T>, 3> vec;
  in >> vec;

  data.clear();
  data.insert(vec.begin(), vec.end());

  return in;
}

// Abbreviations
template<typename T>
std::vector<uint8_t>
marshal(const T& value)
{
  ostream w;
  w << value;
  return w.bytes();
}

template<typename T>
void
unmarshal(const std::vector<uint8_t>& data, T& value)
{
  istream r(data);
  r >> value;
}

} // namespace tls
