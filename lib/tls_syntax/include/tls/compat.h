#pragma once

#include <optional>

#include <mpark/variant.hpp>

namespace tls {

// To balance backward-compatibility with macOS 10.11 with forward-compatibility
// with future versions of C++, we use `mpark::variant`, but import it into
// `namespace std`.
namespace var = mpark;

// In a similar vein, we provide our own safe accessors for std::optional, since
// std::optional::value() is not available on macOS 10.11.
namespace opt {

template<typename T>
T&
get(std::optional<T>& opt)
{
  if (!opt) {
    throw std::runtime_error("bad_optional_access");
  }
  return *opt;
}

template<typename T>
const T&
get(const std::optional<T>& opt)
{
  if (!opt) {
    throw std::runtime_error("bad_optional_access");
  }
  return *opt;
}

} // namespace opt
} // namespace tls
