#include "ratchet_tree.h"
#include "common.h"
#include "tree_math.h"
#include <iostream> // XXX
#include <queue>

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

void
RatchetNode::merge(const RatchetNode& other)
{
  if (other._pub != _pub) {
    *this = other;
  }

  if (other._priv && !_priv) {
    *_priv = *other._priv;
  }

  if (other._secret && !_secret) {
    *_secret = *other._secret;
  }
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

///
/// RatchetPath
///

std::ostream&
operator<<(std::ostream& out, const RatchetPath& obj)
{
  out << "nodes:" << std::endl;
  for (auto& node : obj.nodes) {
    out << "  " << node << std::endl;
  }

  return out;
}

tls::ostream&
operator<<(tls::ostream& out, const RatchetPath& obj)
{
  return out << obj.nodes << obj.node_secrets;
}

tls::istream&
operator>>(tls::istream& in, RatchetPath& obj)
{
  return in >> obj.nodes >> obj.node_secrets;
}

///
/// RatchetTree
///

RatchetTree::RatchetTree()
  : nodes()
{}

RatchetTree::RatchetTree(const bytes& secret)
  : nodes(1)
{
  nodes[0] = RatchetNode(secret);
}

RatchetTree::RatchetTree(const std::vector<bytes>& secrets)
  : nodes(tree_math::node_width(secrets.size()))
{
  uint32_t size = secrets.size();
  std::queue<uint32_t> to_update;
  for (uint32_t i = 0; i < secrets.size(); i += 1) {
    auto curr = 2 * i;
    auto parent = tree_math::parent(curr, size);
    if (curr != parent && curr == tree_math::right(parent, size)) {
      to_update.push(parent);
    }

    nodes[curr] = RatchetNode(secrets[i]);
  }

  while (to_update.size() > 0) {
    auto curr = to_update.front();
    to_update.pop();
    auto parent = tree_math::parent(curr, size);
    if (curr != parent && curr == tree_math::right(parent, size)) {
      to_update.push(parent);
    }

    auto right = tree_math::right(curr, size);
    auto child_secret = *(nodes[right].secret());
    auto secret = SHA256Digest(child_secret).digest();
    nodes[curr] = RatchetNode(secret);
  }
}

uint32_t
RatchetTree::working_size(uint32_t from) const
{
  uint32_t size = tree_math::size_from_width(nodes.size());
  if (2 * from > size) {
    size = from + 1;
  }
  return size;
}

RatchetPath
RatchetTree::encrypt(uint32_t from, const bytes& leaf_secret) const
{
  RatchetPath path;

  const auto size = working_size(from);
  const auto root = tree_math::root(size);

  path.nodes.push_back(RatchetNode{ leaf_secret });

  auto curr = 2 * from;
  auto sibling = tree_math::sibling(curr, size);
  auto secret = leaf_secret;
  while (curr != root) {
    secret = SHA256Digest(secret).digest();

    RatchetNode temp(secret);
    path.nodes.push_back(temp);

    auto ciphertext = nodes[sibling].public_key().encrypt(secret);
    path.node_secrets.push_back(ciphertext);

    curr = tree_math::parent(curr, size);
    sibling = tree_math::sibling(curr, size);
  }

  return path;
}

bytes
RatchetTree::decrypt(uint32_t from, RatchetPath& path) const
{
  if (path.nodes.size() != path.node_secrets.size() + 1) {
    throw InvalidParameterError("Malformed RatchetPath");
  }

  const auto size = working_size(from);
  const auto root = tree_math::root(size);

  auto curr = 2 * from;
  auto sibling = tree_math::sibling(curr, size);
  bool have_secret = false;
  bytes secret;
  for (int i = 1; i < path.nodes.size(); i += 1) {
    auto priv = nodes[sibling].private_key();
    if (priv && !have_secret) {
      secret = priv->decrypt(path.node_secrets[i - 1]);
      have_secret = true;
    } else if (have_secret) {
      secret = SHA256Digest(secret).digest();
    }

    if (have_secret) {
      RatchetNode temp(secret);
      if (temp.public_key() != path.nodes[i].public_key()) {
        throw InvalidParameterError("Incorrect node public key");
      }

      path.nodes[i] = RatchetNode(secret);
    }

    curr = tree_math::parent(curr, size);
    sibling = tree_math::sibling(curr, size);
  }

  if (curr != root) {
    throw InvalidParameterError("Update path failed to reach the root");
  }

  return secret;
}

void
RatchetTree::merge(uint32_t from, const RatchetPath& path)
{
  const auto size = working_size(from);

  auto curr = 2 * from;
  for (auto& node : path.nodes) {
    if (curr > nodes.size() - 1) {
      nodes.resize(curr + 1);
    }

    nodes[curr].merge(node);
    curr = tree_math::parent(curr, size);
  }
}

uint32_t
RatchetTree::size() const
{
  return working_size(0);
}

bytes
RatchetTree::root_secret() const
{
  auto root = tree_math::root(size());
  auto val = nodes[root].secret();
  return *val;
}

bool
operator==(const RatchetTree& lhs, const RatchetTree& rhs)
{
  if (lhs.nodes.size() != rhs.nodes.size()) {
    return false;
  }

  for (int i = 0; i < lhs.nodes.size(); i += 1) {
    if (lhs.nodes[i].public_key() != rhs.nodes[i].public_key()) {
      return false;
    }
  }

  return true;
}

tls::ostream&
operator<<(tls::ostream& out, const RatchetTree& obj)
{
  return out << obj.nodes;
}

tls::istream&
operator>>(tls::istream& in, RatchetTree& obj)
{
  return in >> obj.nodes;
}

} // namespace mls
