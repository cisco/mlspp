#pragma once

#include <array>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

// Forward declarations to enable optional serialization below
namespace tls {
class ostream;
class istream;

ostream&
operator<<(ostream& out, uint8_t data);
istream&
operator>>(istream& in, uint8_t& data);
}

namespace mls {

///
/// Protocol versions
///

typedef uint16_t ProtocolVersion;

static const ProtocolVersion mls10Version = 0xABCD;

///
/// Serialization of optional values
///

template<typename T>
std::ostream&
operator<<(std::ostream& out, const std::optional<T>& opt)
{
  if (!opt) {
    return out << "_";
  }

  return out << *opt;
}

///
/// Byte strings and serialization
///

typedef std::vector<uint8_t> bytes;

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

std::ostream&
operator<<(std::ostream& out, const bytes& data);

typedef uint32_t epoch_t;

///
/// Error types
///

// The `typedef X parent` / `using parent::parent` construction here
// imports the constructors of the parent.

class NotImplementedError : public std::exception
{
public:
  typedef std::exception parent;
  using parent::parent;
};

class ProtocolError : public std::runtime_error
{
public:
  typedef std::runtime_error parent;
  using parent::parent;
};

class InvalidTLSSyntax : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class IncompatibleNodesError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class InvalidParameterError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class InvalidPathError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class InvalidIndexError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class InvalidMessageTypeError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class MissingNodeError : public std::out_of_range
{
public:
  typedef std::out_of_range parent;
  using parent::parent;
};

class MissingStateError : public std::out_of_range
{
public:
  typedef std::out_of_range parent;
  using parent::parent;
};

} // namespace mls
