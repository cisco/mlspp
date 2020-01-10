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

using epoch_t = uint64_t;

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
/// CipherSuite and Signature identifiers
///

enum struct CipherSuite : uint16_t
{
  P256_SHA256_AES128GCM = 0x0000,
  P521_SHA512_AES256GCM = 0x0010,
  X25519_SHA256_AES128GCM = 0x0001,
  X448_SHA512_AES256GCM = 0x0011,
  unknown = 0xffff,
};

size_t suite_nonce_size(CipherSuite suite);
size_t suite_key_size(CipherSuite suite);

enum struct SignatureScheme : uint16_t
{
  P256_SHA256 = 0x0403,
  P521_SHA512 = 0x0603,
  Ed25519 = 0x0807,
  Ed448 = 0x0808,
  unknown = 0xffff,
};

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
