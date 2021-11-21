#pragma once

#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::literals::string_literals;

// Expose the bytes library globally
#include <bytes/bytes.h>
using namespace bytes_ns;

// Expose the compatibility library globally
#include <tls/compat.h>
namespace var = tls::var;
namespace opt = tls::opt;

namespace mls {

// Expose bytes operators for code within this namespace
using namespace bytes_ns::operators;

// Make variant equality work in the same way as optional equality, with
// automatic unwrapping.  In other words
//
//     v == T(x) <=> hold_alternative<T>(v) && get<T>(v) == x
//
// For consistency, we also define symmetric and negated version.  In this
// house, we obey the symmetric law of equivalence relations!
template<typename T, typename... Ts>
bool
operator==(const var::variant<Ts...>& v, const T& t)
{
  return var::visit(
    [&](const auto& arg) {
      using U = std::decay_t<decltype(arg)>;
      if constexpr (std::is_same_v<U, T>) {
        return arg == t;
      } else {
        return false;
      }
    },
    v);
}

template<typename T, typename... Ts>
bool
operator==(const T& t, const var::variant<Ts...>& v)
{
  return v == t;
}

template<typename T, typename... Ts>
bool
operator!=(const var::variant<Ts...>& v, const T& t)
{
  return !(v == t);
}

template<typename T, typename... Ts>
bool
operator!=(const T& t, const var::variant<Ts...>& v)
{
  return !(v == t);
}

using epoch_t = uint64_t;

///
/// Get the current system clock time in the format MLS expects
///

uint64_t
seconds_since_epoch();

///
/// Easy construction of overloaded lambdas
///

template<class... Ts>
struct overloaded : Ts...
{
  using Ts::operator()...;
};

// clang-format off
// XXX(RLB): For some reason, different versions of clang-format disagree on how
// this should be formatted.  Probably because it's new syntax with C++17?
// Exempting it from clang-format for now.
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
// clang-format on

///
/// Auto-generate equality and inequality operators for TLS-serializable things
///

template<typename T>
inline typename std::enable_if<T::_tls_serializable, bool>::type
operator==(const T& lhs, const T& rhs)
{
  return lhs._tls_fields_w() == rhs._tls_fields_w();
}

template<typename T>
inline typename std::enable_if<T::_tls_serializable, bool>::type
operator!=(const T& lhs, const T& rhs)
{
  return lhs._tls_fields_w() != rhs._tls_fields_w();
}

///
/// Error types
///

// The `using parent = X` / `using parent::parent` construction here
// imports the constructors of the parent.

class NotImplementedError : public std::exception
{
public:
  using parent = std::exception;
  using parent::parent;
};

class ProtocolError : public std::runtime_error
{
public:
  using parent = std::runtime_error;
  using parent::parent;
};

class IncompatibleNodesError : public std::invalid_argument
{
public:
  using parent = std::invalid_argument;
  using parent::parent;
};

class InvalidParameterError : public std::invalid_argument
{
public:
  using parent = std::invalid_argument;
  using parent::parent;
};

class InvalidPathError : public std::invalid_argument
{
public:
  using parent = std::invalid_argument;
  using parent::parent;
};

class InvalidIndexError : public std::invalid_argument
{
public:
  using parent = std::invalid_argument;
  using parent::parent;
};

class InvalidMessageTypeError : public std::invalid_argument
{
public:
  using parent = std::invalid_argument;
  using parent::parent;
};

class MissingNodeError : public std::out_of_range
{
public:
  using parent = std::out_of_range;
  using parent::parent;
};

class MissingStateError : public std::out_of_range
{
public:
  using parent = std::out_of_range;
  using parent::parent;
};

// A slightly more elegant way to silence -Werror=unused-variable
template<typename T>
void
silence_unused(const T& val)
{
  (void)val;
}

} // namespace mls
