#pragma once

#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace mls {

///
/// Byte strings and serialization
///

using bytes = std::vector<uint8_t>;

bytes
to_bytes(const std::string& ascii);

std::string
to_hex(const bytes& data);

bytes
from_hex(const std::string& hex);

bytes&
operator+=(bytes& lhs, const bytes& rhs);

bytes
operator+(const bytes& lhs, const bytes& rhs);

bytes
operator^(const bytes& lhs, const bytes& rhs);

std::ostream&
operator<<(std::ostream& out, const bytes& data);

using epoch_t = uint32_t;

///
/// Auto-generate equality and inequality operators for TLS-serializable things
///

template<typename T>
inline typename std::enable_if<T::_tls_serializable, bool>::type
operator==(const T& lhs, const T& rhs) {
  return lhs._tls_fields_w() == rhs._tls_fields_w();
}

template<typename T>
inline typename std::enable_if<T::_tls_serializable, bool>::type
operator!=(const T& lhs, const T& rhs) {
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
void silence_unused(const T& val) {
  (void)val;
}

} // namespace mls
