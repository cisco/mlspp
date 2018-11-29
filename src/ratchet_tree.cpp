#include "ratchet_tree.h"
#include "common.h"
#include "tree_math.h"
#include <queue>

namespace mls {

///
/// RatchetNode
///

RatchetNode::RatchetNode(CipherSuite suite)
  : CipherAware(suite)
  , _secret(std::experimental::nullopt)
  , _priv(std::experimental::nullopt)
  , _pub(suite)
{}

RatchetNode::RatchetNode(const RatchetNode& other)
  : CipherAware(other)
  , _secret(other._secret)
  , _priv(other._priv)
  , _pub(other._pub)
{}

RatchetNode&
RatchetNode::operator=(const RatchetNode& other)
{
  _suite = other._suite;
  _secret = other._secret;
  _priv = other._priv;
  _pub = other._pub;
  return *this;
}

RatchetNode::RatchetNode(CipherSuite suite, const bytes& secret)
  : CipherAware(suite)
  , _secret(secret)
  , _priv(DHPrivateKey::derive(suite, secret))
  , _pub(suite)
{
  _pub = _priv->public_key();
}

RatchetNode::RatchetNode(const DHPrivateKey& priv)
  : CipherAware(priv.cipher_suite())
  , _secret(std::experimental::nullopt)
  , _priv(priv)
  , _pub(priv.public_key())
{}

RatchetNode::RatchetNode(const DHPublicKey& pub)
  : CipherAware(pub.cipher_suite())
  , _secret(std::experimental::nullopt)
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

bool
operator==(const RatchetPath& lhs, const RatchetPath& rhs)
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

RatchetTree::RatchetTree(CipherSuite suite)
  : CipherAware(suite)
  , _nodes(suite)
{}

RatchetTree::RatchetTree(CipherSuite suite, const bytes& secret)
  : CipherAware(suite)
  , _nodes(suite)
{
  _nodes.emplace_back(_suite, secret);
}

RatchetTree::RatchetTree(CipherSuite suite, const std::vector<bytes>& secrets)
  : CipherAware(suite)
  , _nodes(suite)
{
  uint32_t size = secrets.size();
  std::queue<uint32_t> to_update;
  for (uint32_t i = 0; i < secrets.size(); i += 1) {
    auto curr = 2 * i;
    auto parent = tree_math::parent(curr, size);
    if (curr != parent && curr == tree_math::right(parent, size)) {
      to_update.push(parent);
    }

    _nodes.emplace_back(_suite, secrets[i]);
    if (i < secrets.size() - 1) {
      _nodes.emplace_back(_suite);
    }
  }

  while (to_update.size() > 0) {
    auto curr = to_update.front();
    to_update.pop();
    auto parent = tree_math::parent(curr, size);
    if (curr != parent && curr == tree_math::right(parent, size)) {
      to_update.push(parent);
    }

    auto right = tree_math::right(curr, size);
    auto child_secret = *(_nodes[right].secret());
    auto secret = SHA256Digest(child_secret).digest();
    _nodes[curr] = new_node(secret);
  }
}

RatchetNode
RatchetTree::new_node(const bytes& data) const
{
  return RatchetNode(_suite, data);
}

uint32_t
RatchetTree::working_size(uint32_t from) const
{
  uint32_t size = tree_math::size_from_width(_nodes.size());
  if (2 * from > size) {
    size = from + 1;
  }
  return size;
}

RatchetPath
RatchetTree::encrypt(uint32_t from, const bytes& leaf_secret) const
{
  RatchetPath path(_suite);

  const auto size = working_size(from);
  const auto root = tree_math::root(size);

  path.nodes.push_back(new_node(leaf_secret));

  auto curr = 2 * from;
  auto sibling = tree_math::sibling(curr, size);
  auto secret = leaf_secret;
  while (curr != root) {
    secret = SHA256Digest(secret).digest();

    auto temp = new_node(secret);
    path.nodes.push_back(temp);

    auto ciphertext = _nodes[sibling].public_key().encrypt(secret);
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
    auto priv = _nodes[sibling].private_key();
    if (priv && !have_secret) {
      secret = priv->decrypt(path.node_secrets[i - 1]);
      have_secret = true;
    } else if (have_secret) {
      secret = SHA256Digest(secret).digest();
    }

    if (have_secret) {
      auto temp = new_node(secret);
      if (temp.public_key() != path.nodes[i].public_key()) {
        throw InvalidParameterError("Incorrect node public key");
      }

      path.nodes[i] = new_node(secret);
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
    while (curr > _nodes.size() - 1) {
      _nodes.emplace_back(_suite);
    }

    _nodes[curr].merge(node);
    curr = tree_math::parent(curr, size);
  }
}

void
RatchetTree::set_leaf(uint32_t index, const bytes& leaf)
{
  const auto size = working_size(index);
  const auto root = tree_math::root(size);

  auto curr = 2 * index;
  auto secret = leaf;
  while (curr != root) {
    while (curr > _nodes.size() - 1) {
      _nodes.emplace_back(_suite);
    }

    _nodes[curr] = new_node(secret);
    secret = SHA256Digest(secret).digest();

    curr = tree_math::parent(curr, size);
  }

  _nodes[root] = new_node(secret);
}

uint32_t
RatchetTree::size() const
{
  return working_size(0);
}

RatchetNode
RatchetTree::root() const
{
  auto root = tree_math::root(size());
  return _nodes[root];
}

bytes
RatchetTree::root_secret() const
{
  auto root = tree_math::root(size());
  auto val = _nodes[root].secret();
  return *val;
}

bool
operator==(const RatchetTree& lhs, const RatchetTree& rhs)
{
  if (lhs._nodes.size() != rhs._nodes.size()) {
    return false;
  }

  for (int i = 0; i < lhs._nodes.size(); i += 1) {
    if (lhs._nodes[i].public_key() != rhs._nodes[i].public_key()) {
      return false;
    }
  }

  return true;
}

std::ostream&
operator<<(std::ostream& out, const RatchetTree& obj)
{
  for (int i = 0; i < obj._nodes.size(); i += 1) {
    out << obj._nodes[i].public_key() << " ";
  }
  return out;
}

tls::ostream&
operator<<(tls::ostream& out, const RatchetTree& obj)
{
  return out << obj._nodes;
}

tls::istream&
operator>>(tls::istream& in, RatchetTree& obj)
{
  return in >> obj._nodes;
}

} // namespace mls
