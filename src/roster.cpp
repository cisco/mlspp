#include "roster.h"

namespace mls {

bool
operator==(const RawKeyCredential& lhs, const RawKeyCredential& rhs)
{
  return lhs._key == rhs._key;
}

tls::ostream&
operator<<(tls::ostream& out, const RawKeyCredential& obj)
{
  return out << obj._key.signature_scheme() << obj._key;
}

tls::istream&
operator>>(tls::istream& in, RawKeyCredential& obj)
{
  SignatureScheme scheme;
  in >> scheme;

  SignaturePublicKey key(scheme);
  in >> key;

  obj._key = key;
  return in;
}

void
Roster::add(const RawKeyCredential& cred)
{
  _credentials.push_back(cred);
}

void
Roster::put(uint32_t index, const RawKeyCredential& cred)
{
  if (index > _credentials.size() - 1) {
    _credentials.resize(index + 1);
  }

  _credentials.emplace(_credentials.begin() + index, cred);
}

void
Roster::copy(uint32_t dst, uint32_t src)
{
  if (dst > _credentials.size() - 1) {
    _credentials.resize(dst + 1);
  }

  _credentials.emplace(_credentials.begin() + dst, _credentials[src]);
}

RawKeyCredential
Roster::get(uint32_t index) const
{
  return _credentials[index];
}

size_t
Roster::size() const
{
  return _credentials.size();
}

bool
operator==(const Roster& lhs, const Roster& rhs)
{
  return lhs._credentials == rhs._credentials;
}

tls::ostream&
operator<<(tls::ostream& out, const Roster& obj)
{
  return out << obj._credentials;
}

tls::istream&
operator>>(tls::istream& in, Roster& obj)
{
  return in >> obj._credentials;
}

} // namespace mls
