#pragma once

#include <array>
#include <experimental/optional>
#include <iomanip>
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
/// Optional and its serialization
///

template<typename T>
using optional = std::experimental::optional<T>;

template<typename T>
std::ostream&
operator<<(std::ostream& out, const optional<T>& opt)
{
  if (!opt) {
    return out << "_";
  }

  return out << *opt;
}

template<typename T>
tls::ostream&
operator<<(tls::ostream& out, const optional<T>& opt)
{
  if (!opt) {
    return out << uint8_t(0);
  }

  return out << uint8_t(1) << *opt;
}

template<typename T>
tls::istream&
operator>>(tls::istream& in, optional<T>& opt)
{
  uint8_t present = 0;
  in >> present;

  switch (present) {
    case 0:
      opt = std::experimental::nullopt;
      return in;

    case 1:
      return in >> *opt;

    default:
      throw std::invalid_argument("Malformed optional");
  }
}

///
/// Byte strings and serialization
///

typedef std::vector<uint8_t> bytes;

static std::string
to_hex(const bytes& data)
{
  std::stringstream hex;
  hex.flags(std::ios::hex);
  for (const auto& byte : data) {
    hex << std::setw(2) << std::setfill('0') << int(byte);
  }
  return hex.str();
}

static bytes
from_hex(const std::string& hex)
{
  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  int len = hex.length() / 2;
  bytes out(len);
  for (int i = 0; i < len; i += 1) {
    std::string byte = hex.substr(2 * i, 2);
    out[i] = strtol(byte.c_str(), nullptr, 16);
  }

  return out;
}

static std::ostream&
operator<<(std::ostream& out, const bytes& data)
{
  return out << to_hex(data);
}

typedef uint32_t epoch_t;

///
/// Hash prefixes
///

static const uint8_t leaf_hash_prefix = 0x01;
static const uint8_t pair_hash_prefix = 0x02;
static const uint8_t dh_hash_prefix = 0x03;

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
