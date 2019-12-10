#pragma once

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <variant>
#include <vector>

// Note: Different namespace because this is TLS-generic (might
// want to pull it out later).  Also, avoids confusables ending up
// in the global namespace, e.g., vector, istream, ostream.
namespace tls {

// Use this macro to define struct serialization with minimal boilerplate
#define TLS_SERIALIZABLE(...) \
  static const bool _tls_serializable = true; \
  auto _tls_fields_r() { return std::tie(__VA_ARGS__); } \
  auto _tls_fields_w() const { return std::make_tuple(__VA_ARGS__); }

// For indicating no min or max in vector definitions
const size_t none = -1;

class WriteError : public std::invalid_argument
{
public:
  using parent = std::invalid_argument;
  using parent::parent;
};

class ReadError : public std::invalid_argument
{
public:
  using parent = std::invalid_argument;
  using parent::parent;
};

// A variant class attached to a type enum
template<typename Te, typename... Tp>
class variant : public std::variant<Tp...>
{
  public:
  using parent = std::variant<Tp...>;
  using parent::parent;
  using type_enum = Te;

  template<size_t I = 0>
  inline typename std::enable_if_t<I < sizeof...(Tp), Te> inner_type() const {
    using curr_type = std::variant_alternative_t<I, parent>;
    if (std::holds_alternative<curr_type>(*this)) {
      return curr_type::type;
    }

    return inner_type<I+1>();
  }

  template<size_t I = 0>
  inline typename std::enable_if_t<I == sizeof...(Tp), Te> inner_type() const {
    throw std::bad_variant_access();
  }
};

template<typename Te, typename Tc, typename... Tp>
class variant_variant : public variant<Te, Tp...>
{
  public:
  using parent = variant<Te, Tp...>;
  using parent::parent;

  template<typename T>
  variant_variant(const Tc& context, const T& value)
    : parent(value)
    , _context(context)
  {}

  Tc _context;
};

template<typename T, size_t head, size_t min = none, size_t max = none>
class vector_base : public std::vector<T>
{
public:
  // Explicitly import constructors
  using parent = std::vector<T>;
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
  using parent = vector_base<T, head, min, max>;
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
  using parent = vector_base<T, head, min, max>;
  using parent::parent;

  variant_vector(C ctor_arg)
    : _ctor_arg(ctor_arg)
  {}

  void set_arg(C ctor_arg) { _ctor_arg = ctor_arg; }
  virtual T new_element() const { return T{ _ctor_arg }; }

private:
  C _ctor_arg;
};

template<typename T>
class optional_base : public std::optional<T>
{
public:
  using parent = std::optional<T>;
  using parent::parent;
  virtual ~optional_base() = default;

  virtual T& emplace_new() = 0;
};

template<typename T>
class optional : public optional_base<T>
{
public:
  using parent = optional_base<T>;
  using parent::parent;

  virtual T& emplace_new() { return this->emplace(); }
};

template<typename T>
bool
operator==(const optional<T>& lhs, const optional<T>& rhs)
{
  auto both_blank = (!lhs.has_value() && !rhs.has_value());
  auto both_occupied = (lhs.has_value() && rhs.has_value());
  return (both_blank || (both_occupied && (lhs.value() == rhs.value())));
}

template<typename T, typename C>
class variant_optional : public optional_base<T>
{
public:
  using parent = optional_base<T>;
  using parent::parent;

  variant_optional(C ctor_arg)
    : _ctor_arg(ctor_arg)
  {}

  virtual T& emplace_new() { return this->emplace(_ctor_arg); }

private:
  C _ctor_arg;
};

template<typename T, typename C>
bool
operator==(const variant_optional<T, C>& lhs, const variant_optional<T, C>& rhs)
{
  auto both_blank = (!lhs.has_value() && !rhs.has_value());
  auto both_occupied = (lhs.has_value() && rhs.has_value());
  return (both_blank || (both_occupied && (lhs.value() == rhs.value())));
}

template<size_t head, size_t min = tls::none, size_t max = tls::none>
using opaque = vector<uint8_t, head, min, max>;

///
/// ostream
///

class ostream
{
public:
  static const size_t none = -1;

  void write_raw(const std::vector<uint8_t>& bytes);

  std::vector<uint8_t> bytes() const { return _buffer; }

private:
  std::vector<uint8_t> _buffer;
  ostream& write_uint(uint64_t value, int length);

  friend ostream& operator<<(ostream& out, bool data);
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
  if (!opt.has_value()) {
    return out << uint8_t(0);
  }

  return out << uint8_t(1) << opt.value();
}

// Enum writer
template<typename T, std::enable_if_t<std::is_enum<T>::value, int> = 0>
tls::ostream&
operator<<(tls::ostream& str, const T& val) {
  auto u = static_cast<std::underlying_type_t<T>>(val);
  return str << u;
}

// Variant writer (requires ::type on underlying types)
template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
write_variant(tls::ostream& str, const std::variant<Tp...>& t)
{
  throw WriteError("Empty variant");
}

template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I < sizeof...(Tp), void>::type
write_variant(tls::ostream& str, const std::variant<Tp...>& v)
{
  using curr_type = std::variant_alternative_t<I, std::variant<Tp...>>;
  if (std::holds_alternative<curr_type>(v)) {
    str << curr_type::type << std::get<I>(v);
    return;
  }

  write_variant<I + 1, Tp...>(str, v);
}

template<typename Te, typename... Tp>
tls::ostream&
operator<<(tls::ostream& str, const variant<Te, Tp...>& v)
{
  write_variant(str, v);
  return str;
}

// Struct writer (enabled by macro)
template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
write_tuple(tls::ostream& str, const std::tuple<Tp...>& t)
{ }

template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I < sizeof...(Tp), void>::type
write_tuple(tls::ostream& str, const std::tuple<Tp...>& t)
{
  str << std::get<I>(t);
  write_tuple<I + 1, Tp...>(str, t);
}

template<typename T>
inline typename std::enable_if<T::_tls_serializable, tls::ostream&>::type
operator<<(tls::ostream& str, const T& obj) {
  write_tuple(str, obj._tls_fields_w());
  return str;
}

///
/// istream
///

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

  friend istream& operator>>(istream& in, bool& data);
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

// Enum reader
// XXX(rlb): It would be nice if this could enforce that the values are valid,
// but C++ doesn't seem to have that ability.  When used as a tag for variants,
// the variant reader will enforce, at least.
template<typename T, std::enable_if_t<std::is_enum<T>::value, int> = 0>
tls::istream&
operator>>(tls::istream& str, T& val) {
  std::underlying_type_t<T> u;
  str >> u;
  val = static_cast<T>(u);
  return str;
}

// Variant reader
template<size_t I = 0, typename Te, typename... Tp, typename... Tc>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
read_variant(tls::istream& str, Te target_type, std::variant<Tp...>& t, Tc... context)
{
  throw ReadError("Invalid variant type label");
}

template<size_t I = 0, typename Te, typename... Tp, typename... Tc>
inline typename std::enable_if<I < sizeof...(Tp), void>::type
read_variant(tls::istream& str, Te target_type, std::variant<Tp...>& v, Tc... context)
{
  using curr_type = std::variant_alternative_t<I, std::variant<Tp...>>;
  if (curr_type::type == target_type) {
    str >> v.template emplace<I>(context...);
    return;
  }

  read_variant<I + 1>(str, target_type, v, context...);
}

template<typename Te, typename... Tp>
tls::istream&
operator>>(tls::istream& str, variant<Te, Tp...>& v)
{
  using local_variant = variant<Te, Tp...>;
  typename local_variant::type_enum target_type;
  str >> target_type;
  read_variant(str, target_type, v);
  return str;
}

template<typename Te, typename Tc, typename... Tp>
tls::istream&
operator>>(tls::istream& str, variant_variant<Te, Tc, Tp...>& v)
{
  using local_variant = variant_variant<Te, Tc, Tp...>;
  typename local_variant::type_enum target_type;
  str >> target_type;
  read_variant(str, target_type, v, v._context);
  return str;
}

// Struct reader (enabled by macro)
template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
read_tuple(tls::istream& str, const std::tuple<Tp...>& t)
{ }

template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I < sizeof...(Tp), void>::type
read_tuple(tls::istream& str, const std::tuple<Tp...>& t)
{
  str >> std::get<I>(t);
  read_tuple<I + 1, Tp...>(str, t);
}

template<typename T>
inline typename std::enable_if<T::_tls_serializable, tls::istream&>::type
operator>>(tls::istream& str, T& obj) {
  read_tuple(str, obj._tls_fields_r());
  return str;
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

template<typename T, typename... Tp>
T
get(const std::vector<uint8_t>& data, Tp... args)
{
  T value(args...);
  tls::unmarshal(data, value);
  return value;
}

} // namespace tls
