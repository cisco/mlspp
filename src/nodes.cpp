#include "nodes.h"
#include "common.h"
#include "openssl/sha.h"
#include <iomanip>
#include <iostream>

namespace mls {

///
/// MerkleNode
///

MerkleNode
MerkleNode::leaf(const bytes& data)
{
  MerkleNode out;
  out._value = SHA256Digest(leaf_hash_prefix).write(data).digest();
  return out;
}

bool
MerkleNode::public_equal(const MerkleNode& other) const
{
  return *this == other;
}

const bytes&
MerkleNode::value() const
{
  return _value;
}

MerkleNode
operator+(const MerkleNode& lhs, const MerkleNode& rhs)
{
  SHA256Digest digest(pair_hash_prefix);
  digest.write(lhs._value).write(rhs._value);

  MerkleNode out;
  out._value = digest.digest();
  return out;
}

bool
operator==(const MerkleNode& lhs, const MerkleNode& rhs)
{
  return lhs._value == rhs._value;
}

bool
operator!=(const MerkleNode& lhs, const MerkleNode& rhs)
{
  return !(lhs == rhs);
}

std::ostream&
operator<<(std::ostream& out, const MerkleNode& node)
{
  return out << node._value;
}

tls::ostream&
operator<<(tls::ostream& out, const MerkleNode& obj)
{
  tls::vector<uint8_t, 1> data = obj._value;
  return out << data;
}

tls::istream&
operator>>(tls::istream& in, MerkleNode& obj)
{
  tls::vector<uint8_t, 1> data;
  in >> data;
  obj._value = data;
  return in;
}

///
/// RatchetNode
///

RatchetNode::RatchetNode(const RatchetNode& other)
  : _secret(other._secret)
  , _priv(other._priv)
  , _pub(other._pub)
{}

RatchetNode&
RatchetNode::operator=(const RatchetNode& other)
{
  _secret = other._secret;
  _priv = other._priv;
  _pub = other._pub;
  return *this;
}

RatchetNode::RatchetNode(const bytes& secret)
  : _secret(secret)
  , _priv(DHPrivateKey::derive(secret))
{
  _pub = _priv->public_key();
}

RatchetNode::RatchetNode(const DHPrivateKey& priv)
  : _secret(std::experimental::nullopt)
  , _priv(priv)
  , _pub(priv.public_key())
{}

RatchetNode::RatchetNode(const DHPublicKey& pub)
  : _secret(std::experimental::nullopt)
  , _priv(std::experimental::nullopt)
  , _pub(pub)
{}

bool
RatchetNode::public_equal(const RatchetNode& other) const
{
  return _pub == other._pub;
}

const optional<bytes>&
RatchetNode::secret() const
{
  return _secret;
}

const optional<DHPrivateKey>&
RatchetNode::private_key() const
{
  return _priv;
}

const DHPublicKey&
RatchetNode::public_key() const
{
  return _pub;
}

RatchetNode
operator+(const RatchetNode& lhs, const RatchetNode& rhs)
{
  if (lhs._priv) {
    return RatchetNode(lhs._priv->derive(rhs._pub));
  } else if (rhs._priv) {
    return RatchetNode(rhs._priv->derive(lhs._pub));
  }

  throw IncompatibleNodesError("Neither ratchet node has a private key");
}

bool
operator==(const RatchetNode& lhs, const RatchetNode& rhs)
{
  return (lhs._secret == rhs._secret) && (lhs._priv == rhs._priv) &&
         (lhs._pub == rhs._pub);
}

bool
operator!=(const RatchetNode& lhs, const RatchetNode& rhs)
{
  return !(lhs == rhs);
}

std::ostream&
operator<<(std::ostream& out, const RatchetNode& node)
{
  return out << node._pub.to_bytes();
}

tls::ostream&
operator<<(tls::ostream& out, const RatchetNode& obj)
{
  return out << obj._pub;
}

tls::istream&
operator>>(tls::istream& in, RatchetNode& obj)
{
  return in >> obj._pub;
}

} // namespace mls
