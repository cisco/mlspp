#pragma once

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <variant>
#include <vector>
#include <stdexcept>

// Note: Different namespace because this is TLS-generic (might
// want to pull it out later).  Also, avoids confusables ending up
// in the global namespace, e.g., vector, istream, ostream.
namespace tls {

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

  template<size_t head, size_t min, size_t max>
  friend struct vector;
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

// Optional writer
template<typename T>
tls::ostream&
operator<<(tls::ostream& out, const std::optional<T>& opt)
{
  if (!opt.has_value()) {
    return out << uint8_t(0);
  }

  return out << uint8_t(1) << opt.value();
}

// Enum writer
template<typename T, std::enable_if_t<std::is_enum<T>::value, int> = 0>
tls::ostream&
operator<<(tls::ostream& str, const T& val)
{
  auto u = static_cast<std::underlying_type_t<T>>(val);
  return str << u;
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

  template<size_t head, size_t min, size_t max>
  friend struct vector;
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

// Optional reader
template<typename T>
tls::istream&
operator>>(tls::istream& in, std::optional<T>& opt)
{
  uint8_t present = 0;
  in >> present;

  switch (present) {
    case 0:
      opt.reset();
      return in;

    case 1:
      opt.emplace();
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
operator>>(tls::istream& str, T& val)
{
  std::underlying_type_t<T> u;
  str >> u;
  val = static_cast<T>(u);
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

// Use this macro to define struct serialization with minimal boilerplate
#define TLS_SERIALIZABLE(...)                                                  \
  static const bool _tls_serializable = true;                                  \
  auto _tls_fields_r() { return std::forward_as_tuple(__VA_ARGS__); }          \
  auto _tls_fields_w() const { return std::forward_as_tuple(__VA_ARGS__); }

// If your struct contains nontrivial members (e.g., vectors), use this to
// define traits for them.
#define TLS_TRAITS(...)                                                        \
  static const bool _tls_has_traits = true;                                    \
  using _tls_traits = std::tuple<__VA_ARGS__>;

template<typename T>
struct is_serializable
{
  template<typename U>
  static std::true_type test(decltype(U::_tls_serializable));

  template<typename U>
  static std::false_type test(...);

  static const bool value = decltype(test<T>(true))::value;
};

template<typename T>
struct has_traits
{
  template<typename U>
  static std::true_type test(decltype(U::_tls_has_traits));

  template<typename U>
  static std::false_type test(...);

  static const bool value = decltype(test<T>(true))::value;
};

// Traits must have static encode and decode methods, of the following form:
//
//     static ostream& encode(ostream& str, const T& val);
//     static istream& decode(istream& str, T& val);
//
// Trait types will never be constructed; only these static methods are used.
// The value arguments to encode and decode can be as strict or as loose as
// desired.
//
// Ultimately, all interesting encoding should be done through traits.
//
// * vectors
// * variants
// * varints

// Pass-through (normal encoding/decoding)
struct pass
{
  template<typename T>
  static ostream& encode(ostream& str, const T& val)
  {
    return str << val;
  }

  template<typename T>
  static istream& decode(istream& str, T& val)
  {
    return str >> val;
  }
};

// Vector encoding
template<size_t head, size_t min = none, size_t max = none>
struct vector
{
  template<typename T>
  static ostream& encode(ostream& str, const std::vector<T>& data)
  {
    // Vectors with no header are written directly
    if (head == 0) {
      for (const auto& item : data) {
        str << item;
      }
      return str;
    }

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
    str.write_uint(size, head);
    str.write_raw(temp.bytes());

    return str;
  }

  template<typename T>
  static istream& decode(istream& str, std::vector<T>& data)
  {
    switch (head) {
      case 0: // fallthrough
      case 1: // fallthrough
      case 2: // fallthrough
      case 3: // fallthrough
      case 4:
        break;
      default:
        throw ReadError("Invalid header size");
    }

    // Read the size of the vector, if provided; otherwise consume all remaining
    // data in the buffer
    uint64_t size = str._buffer.size();
    if (head > 0) {
      str.read_uint(size, head);
    }

    // Check the size against the declared constraints
    if (size > str._buffer.size()) {
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
    std::vector<uint8_t> trunc(str._buffer.end() - size, str._buffer.end());
    istream r;
    r._buffer = trunc;
    while (r._buffer.size() > 0) {
      data.emplace_back();
      r >> data.back();
    }

    // Truncate the primary buffer
    str._buffer.erase(str._buffer.end() - size, str._buffer.end());

    return str;
  }
};

// Variant encoding
template<typename Te, typename Tv>
Te variant_value;

template<typename Te>
struct variant
{
  template<typename Tv>
  static Te value_for();

  template<size_t I = 0, typename... Tp>
  static inline typename std::enable_if<I == sizeof...(Tp), void>::type
  write_variant(tls::ostream&, const std::variant<Tp...>&)
  {
    throw WriteError("Empty variant");
  }

  template<size_t I = 0, typename... Tp>
    static inline typename std::enable_if <
    I<sizeof...(Tp), void>::type write_variant(tls::ostream& str,
                                               const std::variant<Tp...>& v)
  {
    using Tc = std::variant_alternative_t<I, std::variant<Tp...>>;
    if (std::holds_alternative<Tc>(v)) {
      str << Tc::type << std::get<I>(v);
      return;
    }

    write_variant<I + 1, Tp...>(str, v);
  }

  template<typename... Tp>
  static ostream& encode(ostream& str, const std::variant<Tp...>& data)
  {
    write_variant(str, data);
    return str;
  }

  template<size_t I = 0, typename... Tp>
  static inline typename std::enable_if<I == sizeof...(Tp), void>::type
  read_variant(tls::istream&, Te, std::variant<Tp...>&)
  {
    throw ReadError("Invalid variant type label");
  }

  template<size_t I = 0, typename... Tp>
    static inline typename std::enable_if <
    I<sizeof...(Tp), void>::type read_variant(tls::istream& str,
                                              Te target_type,
                                              std::variant<Tp...>& v)
  {
    using Tc = std::variant_alternative_t<I, std::variant<Tp...>>;
    if (Tc::type == target_type) {
      str >> v.template emplace<I>();
      return;
    }

    read_variant<I + 1>(str, target_type, v);
  }

  template<typename... Tp>
  static istream& decode(istream& str, std::variant<Tp...>& data)
  {
    Te target_type;
    str >> target_type;
    read_variant(str, target_type, data);
    return str;
  }
};

// Struct writer without traits (enabled by macro)
template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
write_tuple(tls::ostream&, const std::tuple<Tp...>&)
{}

template<size_t I = 0, typename... Tp>
  inline typename std::enable_if <
  I<sizeof...(Tp), void>::type
  write_tuple(tls::ostream& str, const std::tuple<Tp...>& t)
{
  str << std::get<I>(t);
  write_tuple<I + 1, Tp...>(str, t);
}

template<typename T>
inline
  typename std::enable_if<is_serializable<T>::value && !has_traits<T>::value,
                          tls::ostream&>::type
  operator<<(tls::ostream& str, const T& obj)
{
  write_tuple(str, obj._tls_fields_w());
  return str;
}

// Struct writer with traits (enabled by macro)
template<typename Tr, size_t I = 0, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
write_tuple_traits(tls::ostream&, const std::tuple<Tp...>&)
{}

template<typename Tr, size_t I = 0, typename... Tp>
  inline typename std::enable_if <
  I<sizeof...(Tp), void>::type
  write_tuple_traits(tls::ostream& str, const std::tuple<Tp...>& t)
{
  std::tuple_element_t<I, Tr>::encode(str, std::get<I>(t));
  write_tuple_traits<Tr, I + 1, Tp...>(str, t);
}

template<typename T>
inline
  typename std::enable_if<is_serializable<T>::value && has_traits<T>::value,
                          tls::ostream&>::type
  operator<<(tls::ostream& str, const T& obj)
{
  write_tuple_traits<typename T::_tls_traits>(str, obj._tls_fields_w());
  return str;
}

// Struct reader without traits (enabled by macro)
template<size_t I = 0, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
read_tuple(tls::istream&, const std::tuple<Tp...>&)
{}

template<size_t I = 0, typename... Tp>
  inline typename std::enable_if <
  I<sizeof...(Tp), void>::type
  read_tuple(tls::istream& str, const std::tuple<Tp...>& t)
{
  str >> std::get<I>(t);
  read_tuple<I + 1, Tp...>(str, t);
}

template<typename T>
inline
  typename std::enable_if<is_serializable<T>::value && !has_traits<T>::value,
                          tls::istream&>::type
  operator>>(tls::istream& str, T& obj)
{
  read_tuple(str, obj._tls_fields_r());
  return str;
}

// Struct reader with traits (enabled by macro)
template<typename Tr, size_t I = 0, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type
read_tuple_traits(tls::istream&, const std::tuple<Tp...>&)
{}

template<typename Tr, size_t I = 0, typename... Tp>
  inline typename std::enable_if <
  I<sizeof...(Tp), void>::type
  read_tuple_traits(tls::istream& str, const std::tuple<Tp...>& t)
{
  std::tuple_element_t<I, Tr>::decode(str, std::get<I>(t));
  read_tuple_traits<Tr, I + 1, Tp...>(str, t);
}

template<typename T>
inline
  typename std::enable_if<is_serializable<T>::value && has_traits<T>::value,
                          tls::istream&>::type
  operator>>(tls::istream& str, T& obj)
{
  read_tuple_traits<typename T::_tls_traits>(str, obj._tls_fields_r());
  return str;
}

///
/// Abbreviation for opaque<N>
///

template<size_t N>
struct opaque
{
  std::vector<uint8_t> data;

  TLS_SERIALIZABLE(data)
  TLS_TRAITS(vector<N>)
};

template<size_t N>
bool
operator==(const opaque<N>& lhs, const opaque<N>& rhs)
{
  return lhs.data == rhs.data;
}

} // namespace tls
