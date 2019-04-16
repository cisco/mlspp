#pragma once

#include <algorithm>
#include <array>
#include <map>
#include <optional>
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

template<typename T, size_t head, size_t min = none, size_t max = none>
class vector_base : public std::vector<T>
{
public:
  // Explicitly import constructors
  typedef std::vector<T> parent;
  using parent::parent;

  vector_base(const parent& other)
    : parent(other)
  {}
  vector_base(parent&& other)
    : parent(other)
  {}
  vector_base()
    : parent()
  {}

  virtual T new_element() const = 0;
};

// A vector type that knows the length of its header and optionally
// min and max lengths.  Otherwise identical to std::vector<T>.
//
// Tagging the type with head/min/max ensures symmetry in
// encode/decode, with a simple API.  The cost is that new code gets
// generated for every head/min/max combination.
template<typename T, size_t head, size_t min = none, size_t max = none>
class vector : public vector_base<T, head, min, max>
{
public:
  // Explicitly import constructors
  typedef vector_base<T, head, min, max> parent;
  using parent::parent;
  virtual ~vector() = default;

  virtual T new_element() const { return T{}; }
};

// An extension of the above vector type that can be used to handle
// types with runtime variants.  This works the same as `vector`
// except that it passes a single argument to the constructor for
// new elements.
template<typename T,
         typename C,
         size_t head,
         size_t min = none,
         size_t max = none>
class variant_vector : public vector_base<T, head, min, max>
{
public:
  // Explicitly import constructors
  typedef vector_base<T, head, min, max> parent;
  using parent::parent;

  variant_vector(C ctor_arg)
    : _ctor_arg(ctor_arg)
  {}

  virtual T new_element() const { return T{ _ctor_arg }; }

private:
  C _ctor_arg;
};

template<typename T>
class optional_base : public std::optional<T>
{
public:
  typedef std::optional<T> parent;
  using parent::parent;

  virtual T& emplace_new() = 0;

  bool equal(const optional_base<T>& other) const
  {
    auto both_blank = (!this->has_value() && !other.has_value());
    auto both_occupied = (this->has_value() && other.has_value());
    return (both_blank || (both_occupied && (this->value() == other.value())));
  }
};

template<typename T>
bool
operator==(const optional_base<T>& lhs, const optional_base<T>& rhs)
{}

template<typename T>
class optional : public optional_base<T>
{
public:
  typedef optional_base<T> parent;
  using parent::parent;

  virtual T& emplace_new() { return this->emplace(); }
};

template<typename T, typename C>
class variant_optional : public optional_base<T>
{
public:
  typedef optional_base<T> parent;
  using parent::parent;

  variant_optional(C ctor_arg)
    : _ctor_arg(ctor_arg)
  {}

  virtual T& emplace_new() { return this->emplace(_ctor_arg); }

private:
  C _ctor_arg;
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
                             const vector_base<T, head, min, max>& data);
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
operator<<(ostream& out, const vector_base<T, head, min, max>& data)
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
  size_t i = 0;
  for (const auto& item : data) {
    temp << item;
    i += 1;
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

// Optional writer
template<typename T>
tls::ostream&
operator<<(tls::ostream& out, const optional_base<T>& opt)
{
  if (!opt) {
    return out << uint8_t(0);
  }

  return out << uint8_t(1) << opt.value();
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
  friend istream& operator>>(istream& in, vector_base<T, head, min, max>& data);
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
operator>>(istream& in, vector_base<T, head, min, max>& data)
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

  // Truncate the data buffer
  data.clear();

  // Truncate the buffer to the declared length and wrap it in a
  // new reader, then read items from it
  // NB: Remember that we store the vector in reverse order
  // NB: This requires that T be default-constructible
  std::vector<uint8_t> trunc(in._buffer.end() - size, in._buffer.end());
  istream r;
  r._buffer = trunc;
  while (r._buffer.size() > 0) {
    auto temp = data.new_element();
    r >> temp;
    data.push_back(temp);
  }

  // Truncate the primary buffer
  in._buffer.erase(in._buffer.end() - size, in._buffer.end());

  return in;
}

// Optional reader
template<typename T>
tls::istream&
operator>>(tls::istream& in, optional_base<T>& opt)
{
  uint8_t present = 0;
  in >> present;

  switch (present) {
    case 0:
      opt.reset();
      return in;

    case 1:
      opt.emplace_new();
      return in >> opt.value();

    default:
      throw std::invalid_argument("Malformed optional");
  }
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
