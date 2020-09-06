#pragma once

#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <bytes/bytes.h>
using namespace bytes_ns;

#include <hpke/digest.h>
#include <hpke/hpke.h>
#include <hpke/signature.h>

#include <tls/tls_syntax.h>

namespace mls {

using epoch_t = uint64_t;

///
/// Get the current system clock time in the format MLS expects
///

uint64_t
seconds_since_epoch();

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
/// Cipher suites
///
struct CipherSuite
{
  enum struct ID : uint16_t
  {
    unknown = 0x0000,
    X25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    P256_AES128GCM_SHA256_P256 = 0x0002,
    X25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    X448_AES256GCM_SHA512_Ed448 = 0x0004,
    P521_AES256GCM_SHA512_P521 = 0x0005,
    X448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
  };

  CipherSuite();
  CipherSuite(ID id_in);
  CipherSuite(const CipherSuite& other);
  CipherSuite(CipherSuite&& other);
  CipherSuite& operator=(const CipherSuite& other);

  ID id;
  std::unique_ptr<hpke::HPKE> hpke;
  std::unique_ptr<hpke::Digest> digest;
  std::unique_ptr<hpke::Signature> sig;

  bytes expand_with_label(const bytes& secret,
                          const std::string& label,
                          const bytes& context,
                          size_t size) const;

private:
  void reset(ID id_in);
};

tls::istream&
operator>>(tls::istream& str, CipherSuite& suite);
tls::ostream&
operator<<(tls::ostream& str, const CipherSuite& suite);
bool
operator==(const CipherSuite& lhs, const CipherSuite& rhs);
bool
operator!=(const CipherSuite& lhs, const CipherSuite& rhs);

enum struct SignatureScheme : uint16_t
{
  unknown = 0x0000,
  P256_SHA256 = 0x0403,
  P521_SHA512 = 0x0603,
  Ed25519 = 0x0807,
  Ed448 = 0x0808,
};

SignatureScheme
scheme_for_suite(CipherSuite::ID id);

extern const std::array<CipherSuite::ID, 6> all_supported_suites;

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
