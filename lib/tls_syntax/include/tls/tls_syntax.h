#pragma once

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <vector>
#include <string_view>

#include <tls/compat.h>

namespace tls {

// Abbreviations for owned and unowned buffers
using owned_bytes = std::vector<uint8_t>;
using output_bytes = std::basic_string_view<uint8_t>;
using input_bytes = std::basic_string_view<const uint8_t>;

// For indicating no min or max in vector definitions
const size_t none = std::numeric_limits<size_t>::max();

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
/// Struct-building tools
///

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

///
/// size_of
///

template<typename T>
struct is_serializable;

template<typename T>
inline typename std::enable_if<!is_serializable<T>::value && !std::is_enum<T>::value,
                          size_t>::type
size_of(const T& val);

template<typename T>
constexpr
  typename std::enable_if<is_serializable<T>::value && !has_traits<T>::value,
                          size_t>::type
  size_of(const T& obj);

template<typename T>
constexpr
  typename std::enable_if<is_serializable<T>::value && has_traits<T>::value,
                          size_t>::type
  size_of(const T& obj);

// Primitive sizes
template<>
constexpr size_t size_of(const bool&) { return 1; }

template<>
constexpr size_t size_of(const uint8_t&) { return 1; }

template<>
constexpr size_t size_of(const uint16_t&) { return 2; }

template<>
constexpr size_t size_of(const uint32_t&) { return 4; }

template<>
constexpr size_t size_of(const uint64_t&) { return 8; }

// Array size
template<typename T, size_t N>
constexpr size_t size_of(const std::array<T, N>& data)
{
  auto out = size_t(0);
  for (const auto& item : data) {
    out += size_of(item);
  }
  return out;
}

// Optional size
template<typename T>
constexpr size_t size_of(const std::optional<T>& opt)
{
  if (!opt) {
    return 1;
  }

  return 1 + size_of(opt::get(opt));
}

// Enum size
template<typename T, std::enable_if_t<std::is_enum<T>::value, bool> = true>
constexpr size_t size_of(const T& val)
{
  return size_of(static_cast<std::underlying_type_t<T>>(val));
}

// Struct sizer without traits (enabled by macro)
template<size_t I = 0, typename... Tp>
constexpr typename std::enable_if<I == sizeof...(Tp), size_t>::type
tuple_size_of(const std::tuple<Tp...>&)
{
  return 0;
}

template<size_t I = 0, typename... Tp>
  constexpr typename std::enable_if <
  I<sizeof...(Tp), size_t>::type
  tuple_size_of(const std::tuple<Tp...>& t)
{
  return size_of(std::get<I>(t)) + tuple_size_of<I+1, Tp...>(t);
}

template<typename T>
constexpr
  typename std::enable_if<is_serializable<T>::value && !has_traits<T>::value,
                          size_t>::type
  size_of(const T& obj)
{
  return tuple_size_of(obj._tls_fields_w());
}

// Struct sizer with traits (enabled by macro)
template<typename Tr, size_t I = 0, typename... Tp>
constexpr  typename std::enable_if<I == sizeof...(Tp), size_t>::type
tuple_traits_size_of(const std::tuple<Tp...>&)
{
  return 0;
}

template<typename Tr, size_t I = 0, typename... Tp>
  constexpr  typename std::enable_if <
  I<sizeof...(Tp), size_t>::type
  tuple_traits_size_of(const std::tuple<Tp...>& t)
{
  auto elem_size = std::tuple_element_t<I, Tr>::size_of(std::get<I>(t));
  return elem_size + tuple_traits_size_of<Tr, I+1, Tp...>(t);
}

template<typename T>
constexpr
  typename std::enable_if<is_serializable<T>::value && has_traits<T>::value,
                          size_t>::type
  size_of(const T& obj)
{
  return tuple_traits_size_of<typename T::_tls_traits>(obj._tls_fields_w());
}


///
/// ostream
///

class ostream
{
public:
  ostream(owned_bytes& buf)
    : _written(0)
    , _buffer(buf.data(), buf.size())
  {}

  static const size_t none = std::numeric_limits<size_t>::max();

  void write_raw(const owned_bytes& content);

  size_t written() const { return _written; }

private:
  size_t _written = 0;
  output_bytes _buffer;

  void check_remaining(size_t length);
  void write_uint(uint64_t value, size_t length);
  static void write_uint(uint64_t value, output_bytes span);

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
  if (!opt) {
    return out << uint8_t(0);
  }

  return out << uint8_t(1) << opt::get(opt);
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
  istream(const owned_bytes& data)
    : _buffer(data.data(), data.size())
  {}

  size_t size() const { return _buffer.size(); }
  bool empty() const { return _buffer.empty(); }

private:
  istream() {}
  input_bytes _buffer;
  uint8_t next();

  template<typename T>
  istream& read_uint(T& data, int length)
  {
    uint64_t value = 0;
    for (int i = 0; i < length; i += 1) {
      value = (value << unsigned(8)) + next();
    }
    data = static_cast<T>(value);
    return *this;
  }

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
      return in >> opt::get(opt);

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
template <class T, typename... Ts>
size_t total_size(const T& first, const Ts&... rest) {
  auto out = size_of(first);
  if constexpr (sizeof...(rest) > 0) {
      out += total_size(rest...);
  }
  return out;
}

template<typename... Ts>
owned_bytes
marshal(const Ts&... vals)
{
  auto size = total_size(vals...);
  auto buf = owned_bytes(size);
  auto w = ostream(buf);
  (w << ... << vals);
  return buf;
}

template<typename T>
void
unmarshal(const owned_bytes& data, T& value)
{
  istream r(data);
  r >> value;
}

template<typename T, typename... Tp>
T
get(const owned_bytes& data, Tp... args)
{
  T value(args...);
  tls::unmarshal(data, value);
  return value;
}

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
  static size_t size_of(const T& val) {
    return ::tls::size_of(val);
  }

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
  static size_t size_of(const std::vector<T>& data)
  {
    auto out = head;
    for (const auto& item : data) {
      out += ::tls::size_of(item);
    }
    return out;
  }

  template<typename T>
  static ostream& encode(ostream& str, const std::vector<T>& data)
  {
    // Vectors with no header are written directly
    if constexpr (head == 0) {
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

    // Write a zero header, followed by the data
    auto header = str._buffer.substr(0, head);
    auto base_size = str._written;
    str.write_uint(0, head);
    write_all(str, data);

    // Check that the encoded length is OK
    uint64_t size = str._written - base_size - head;
    if (size > head_max) {
      throw WriteError("Data too large for header size");
    } else if constexpr ((max != none) && (size > max)) {
      throw WriteError("Data too large for declared max");
    } else if constexpr ((min != none) && (size < min)) {
      throw WriteError("Data too small for declared min");
    }

    // Write the encoded length back to the header
    str.write_uint(size, header);

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
    if constexpr (head > 0) {
      str.read_uint(size, head);
    }

    // Check the size against the declared constraints
    if (size > str._buffer.size()) {
      throw ReadError("Declared size exceeds available data size");
    } else if constexpr ((max != none) && (size > max)) {
      throw ReadError("Data too large for declared max");
    } else if constexpr ((min != none) && (size < min)) {
      throw ReadError("Data too small for declared min");
    }

    // Truncate the data buffer
    data.clear();

    // Truncate the buffer to the declared length and wrap it in a
    // new reader, then read items from it
    // NB: This requires that T be default-constructible
    istream r;
    r._buffer = input_bytes(str._buffer.data(), size);
    read_all(r, data);

    // Truncate the primary buffer
    str._buffer.remove_prefix(size);

    return str;
  }

  private:
  template<typename T>
  static void write_all(ostream& str, const std::vector<T>& data)
  {
    for (const auto& item : data) {
      str << item;
    }
  }

  template<>
  static void write_all(ostream& str, const std::vector<uint8_t>& data)
  {
    str.write_raw(data);
  }

  template<typename T>
  static void read_all(istream& str, std::vector<T>& data)
  {
    while (!str._buffer.empty()) {
      data.emplace_back();
      str >> data.back();
    }
  }

  template<>
  static void read_all(istream& str, std::vector<uint8_t>& data)
  {
    data.insert(data.end(), str._buffer.begin(), str._buffer.end());
  }

};

// Variant encoding
template<typename Ts, typename Tv>
constexpr Ts
variant_map();

#define TLS_VARIANT_MAP(EnumType, MappedType, enum_value)                      \
  template<>                                                                   \
  constexpr EnumType variant_map<EnumType, MappedType>()                       \
  {                                                                            \
    return EnumType::enum_value;                                               \
  }

template<typename Ts>
struct variant
{
  template<typename... Tp>
  static size_t size_of(const var::variant<Tp...>& data)
  {
    static const auto get_size = [](const auto& v) {
      return ::tls::size_of(v);
    };

    auto type_size = ::tls::size_of(type(data));
    auto item_size = var::visit(get_size, data);
    return type_size + item_size;
  }


  template<typename... Tp>
  static inline Ts type(const var::variant<Tp...>& data)
  {
    static const auto get_type = [](const auto& v) {
      return variant_map<Ts, std::decay_t<decltype(v)>>();
    };
    return var::visit(get_type, data);
  }

  template<typename... Tp>
  static ostream& encode(ostream& str, const var::variant<Tp...>& data)
  {
    const auto write_variant = [&str](auto&& v) {
      using Tv = std::decay_t<decltype(v)>;
      str << variant_map<Ts, Tv>() << v;
    };
    var::visit(write_variant, data);
    return str;
  }

  template<size_t I = 0, typename Te, typename... Tp>
  static inline typename std::enable_if<I == sizeof...(Tp), void>::type
  read_variant(tls::istream&, Te, var::variant<Tp...>&)
  {
    throw ReadError("Invalid variant type label");
  }

  template<size_t I = 0, typename Te, typename... Tp>
    static inline typename std::enable_if <
    I<sizeof...(Tp), void>::type read_variant(tls::istream& str,
                                              Te target_type,
                                              var::variant<Tp...>& v)
  {
    using Tc = var::variant_alternative_t<I, var::variant<Tp...>>;
    if (variant_map<Ts, Tc>() == target_type) {
      str >> v.template emplace<I>();
      return;
    }

    read_variant<I + 1>(str, target_type, v);
  }

  template<typename... Tp>
  static istream& decode(istream& str, var::variant<Tp...>& data)
  {
    Ts target_type;
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

} // namespace tls
