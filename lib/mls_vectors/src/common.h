#pragma once
#include <mls_vectors/mls_vectors.h>

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY(label, test)                                                    \
  if (auto err = verify_bool(label, test)) {                                   \
    return err;                                                                \
  }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY_EQUAL(label, actual, expected)                                  \
  if (auto err = verify_equal(label, actual, expected)) {                      \
    return err;                                                                \
  }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY_TLS_RTT(label, Type, expected)                                  \
  if (auto err = verify_round_trip<Type>(label, expected)) {                   \
    return err;                                                                \
  }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY_TLS_RTT_VAL(label, Type, expected, val)                         \
  if (auto err = verify_round_trip<Type>(label, expected, val)) {              \
    return err;                                                                \
  }

namespace mls_vectors {

std::ostream&
operator<<(std::ostream& str, const mls::NodeIndex& obj);

std::ostream&
operator<<(std::ostream& str, const mls::NodeCount& obj);

std::ostream&
operator<<(std::ostream& str, const std::vector<uint8_t>& obj);

std::ostream&
operator<<(std::ostream& str, const mls::GroupContent::RawContent& obj);

template<typename T, std::enable_if_t<std::is_enum<T>::value, int> = 0>
std::ostream&
operator<<(std::ostream& str, const T& obj)
{
  auto u = static_cast<std::underlying_type_t<T>>(obj);
  return str << u;
}

template<typename T>
std::ostream&
operator<<(std::ostream& str, const std::optional<T>& obj)
{
  if (!obj) {
    return str << "(nullopt)";
  }

  return str << opt::get(obj);
}

template<typename T>
std::ostream&
operator<<(std::ostream& str, const std::vector<T>& obj)
{
  for (const auto& val : obj) {
    str << val << " ";
  }
  return str;
}

template<typename T>
inline typename std::enable_if<T::_tls_serializable, std::ostream&>::type
operator<<(std::ostream& str, const T& obj)
{
  return str << to_hex(tls::marshal(obj));
}

template<typename T>
std::optional<std::string>
verify_bool(const std::string& label, const T& test)
{
  if (test) {
    return std::nullopt;
  }

  return label;
}

template<typename T, typename U>
std::optional<std::string>
verify_equal(const std::string& label, const T& actual, const U& expected)
{
  if (actual == expected) {
    return std::nullopt;
  }

  auto ss = std::stringstream();
  ss << "Error: " << label << "  " << actual << " != " << expected;
  return ss.str();
}

template<typename T>
std::optional<std::string>
verify_round_trip(const std::string& label, const bytes& expected)
{
  auto noop = [](const auto& /* unused */) { return true; };
  return verify_round_trip<T>(label, expected, noop);
}

template<typename T, typename F>
std::optional<std::string>
verify_round_trip(const std::string& label, const bytes& expected, const F& val)
{
  auto obj = T{};
  try {
    obj = tls::get<T>(expected);
  } catch (const std::exception& e) {
    auto ss = std::stringstream();
    ss << "Decode error: " << label << " " << e.what();
    return ss.str();
  }

  if (!val(obj)) {
    auto ss = std::stringstream();
    ss << "Validation error: " << label;
    return ss.str();
  }

  auto actual = tls::marshal(obj);
  VERIFY_EQUAL(label, actual, expected);
  return std::nullopt;
}

} // namespace mls_vectors
