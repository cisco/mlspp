#pragma once

#include "common.h"
#include "crypto.h"
#include "tls_syntax.h"
#include <iosfwd>

namespace mls {

class RawKeyCredential
{
public:
  RawKeyCredential() {}

  RawKeyCredential(const SignaturePublicKey& key)
    : _key(key)
  {}

  bytes identity() const { return _key.to_bytes(); }

  SignaturePublicKey public_key() const { return _key; }

private:
  SignaturePublicKey _key;

  friend bool operator==(const RawKeyCredential& lhs,
                         const RawKeyCredential& rhs);
  friend tls::ostream& operator<<(tls::ostream& out,
                                  const RawKeyCredential& roster);
  friend tls::istream& operator>>(tls::istream& in, RawKeyCredential& roster);
};

// TODO(rlb@ipv.sx): Figure out how to generalize to more types of
// credential
class Roster
{
public:
  void put(uint32_t index, const RawKeyCredential& public_key);
  void add(const RawKeyCredential& public_key);
  RawKeyCredential get(uint32_t index) const;

private:
  tls::vector<RawKeyCredential, 4> _credentials;

  friend bool operator==(const Roster& lhs, const Roster& rhs);
  friend tls::ostream& operator<<(tls::ostream& out, const Roster& roster);
  friend tls::istream& operator>>(tls::istream& in, Roster& roster);
};

} // namespace mls
