#include "ratchet_tree.h"
#include "common.h"
#include "messages.h"
#include "tree_math.h"

#include <iostream>

namespace mls {

///
/// RatchetTreeNode
///

RatchetTreeNode::RatchetTreeNode(CipherSuite suite)
  : CipherAware(suite)
  , _secret(nullopt)
  , _priv(nullopt)
  , _pub(suite)
{}

RatchetTreeNode::RatchetTreeNode(const RatchetTreeNode& other)
  : CipherAware(other)
  , _secret(other._secret)
  , _priv(other._priv)
  , _pub(other._pub)
{}

RatchetTreeNode&
RatchetTreeNode::operator=(const RatchetTreeNode& other)
{
  _suite = other._suite;
  _secret = other._secret;
  _priv = other._priv;
  _pub = other._pub;
  return *this;
}

RatchetTreeNode::RatchetTreeNode(CipherSuite suite, const bytes& secret)
  : CipherAware(suite)
  , _secret(secret)
  , _priv(DHPrivateKey::derive(suite, secret))
  , _pub(suite)
{
  _pub = _priv->public_key();
}

RatchetTreeNode::RatchetTreeNode(const DHPrivateKey& priv)
  : CipherAware(priv.cipher_suite())
  , _secret(nullopt)
  , _priv(priv)
  , _pub(priv.public_key())
{}

RatchetTreeNode::RatchetTreeNode(const DHPublicKey& pub)
  : CipherAware(pub.cipher_suite())
  , _secret(nullopt)
  , _priv(nullopt)
  , _pub(pub)
{}

bool
RatchetTreeNode::public_equal(const RatchetTreeNode& other) const
{
  return _pub == other._pub;
}

const optional<bytes>&
RatchetTreeNode::secret() const
{
  return _secret;
}

const optional<DHPrivateKey>&
RatchetTreeNode::private_key() const
{
  return _priv;
}

const DHPublicKey&
RatchetTreeNode::public_key() const
{
  return _pub;
}

void
RatchetTreeNode::merge(const RatchetTreeNode& other)
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
operator==(const RatchetTreeNode& lhs, const RatchetTreeNode& rhs)
{
  return (lhs._secret == rhs._secret) && (lhs._priv == rhs._priv) &&
         (lhs._pub == rhs._pub);
}

bool
operator!=(const RatchetTreeNode& lhs, const RatchetTreeNode& rhs)
{
  return !(lhs == rhs);
}

std::ostream&
operator<<(std::ostream& out, const RatchetTreeNode& node)
{
  return out << node._pub.to_bytes();
}

tls::ostream&
operator<<(tls::ostream& out, const RatchetTreeNode& obj)
{
  return out << obj._pub;
}

tls::istream&
operator>>(tls::istream& in, RatchetTreeNode& obj)
{
  obj._priv = nullopt;
  obj._secret = nullopt;
  return in >> obj._pub;
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
  for (uint32_t i = 0; i < secrets.size(); i += 1) {
    add_leaf(secrets[i]);
    set_path(i, secrets[i]);
  }
}

DirectPath
RatchetTree::encrypt(uint32_t from, const bytes& leaf_secret) const
{
  DirectPath path{ _suite };

  auto leaf_node = new_node(leaf_secret);
  path.nodes.push_back({ leaf_node.public_key(), {} });

  auto secret = leaf_secret;
  auto copath = tree_math::copath(2 * from, size());
  for (const auto& node : copath) {
    secret = Digest(_suite).write(secret).digest();

    RatchetNode path_node{ _suite };
    path_node.public_key = new_node(secret).public_key();

    for (const auto& node : resolve(node)) {
      auto ciphertext = _nodes[node]->public_key().encrypt(secret);
      path_node.node_secrets.push_back(ciphertext);
    }

    path.nodes.push_back(path_node);
  }

  return path;
}

RatchetTree::MergeInfo
RatchetTree::decrypt(uint32_t from, const DirectPath& path) const
{
  MergeInfo info;

  auto copath = tree_math::copath(2 * from, size());
  if (path.nodes.size() != copath.size() + 1) {
    throw ProtocolError("Malformed DirectPath");
  }

  // Handle the leaf node
  if (path.nodes[0].node_secrets.size() != 0) {
    throw ProtocolError("Malformed initial node");
  }
  info.public_keys.push_back(path.nodes[0].public_key);

  // Handle the remainder of the path
  bytes secret;
  bool have_secret = false;
  for (int i = 0; i < copath.size(); ++i) {
    const auto curr = copath[i];
    const auto& path_node = path.nodes[i + 1];

    if (!have_secret) {
      auto res = resolve(curr);
      if (path_node.node_secrets.size() != res.size()) {
        throw ProtocolError("Malformed RatchetNode");
      }

      for (int j = 0; j < res.size(); ++j) {
        auto tree_node = _nodes[res[j]];
        if (!tree_node || !tree_node->private_key()) {
          continue;
        }

        auto encrypted_secret = path_node.node_secrets[j];
        secret = tree_node->private_key()->decrypt(encrypted_secret);
        have_secret = true;
      }
    } else {
      secret = Digest(_suite).write(secret).digest();
    }

    if (have_secret) {
      auto temp = new_node(secret);
      if (temp.public_key() != path_node.public_key) {
        throw InvalidParameterError("Incorrect node public key");
      }

      info.secrets.push_back(secret);
    } else {
      info.public_keys.push_back(path_node.public_key);
    }
  }

  return info;
}

void
RatchetTree::merge_path(uint32_t from, const RatchetTree::MergeInfo& info)
{
  const auto dirpath = tree_math::dirpath(2 * from, size());
  if (dirpath.size() + 1 != info.public_keys.size() + info.secrets.size()) {
    throw InvalidParameterError("Malformed MergeInfo");
  }

  auto key_list_size = info.public_keys.size();
  for (int i = 0; i < dirpath.size(); ++i) {
    auto curr = dirpath[i];
    while (curr > _nodes.size() - 1) {
      _nodes.emplace_back(_suite);
    }

    if (i < info.public_keys.size()) {
      auto node = RatchetTreeNode(info.public_keys[i]);
      _nodes[curr].merge(node);
    } else {
      auto node = new_node(info.secrets[i - key_list_size]);
      _nodes[curr].merge(node);
    }
  }

  auto root = tree_math::root(size());
  auto node = new_node(info.secrets.back());
  _nodes[root].merge(node);
}

void
RatchetTree::add_leaf(const DHPublicKey& pub)
{
  if (_suite != pub.cipher_suite()) {
    throw InvalidParameterError("Incorrect ciphersuite");
  }

  if (_nodes.size() > 0) {
    _nodes.emplace_back(nullopt);
  }
  _nodes.emplace_back(RatchetTreeNode(pub));
}

void
RatchetTree::add_leaf(const bytes& leaf_secret)
{
  if (_nodes.size() > 0) {
    _nodes.emplace_back(nullopt);
  }
  _nodes.emplace_back(new_node(leaf_secret));
}

void
RatchetTree::blank_path(uint32_t index)
{
  const auto size_ = size();
  const auto root = tree_math::root(size_);

  auto curr = 2 * index;
  while (curr != root) {
    _nodes[curr] = nullopt;
    curr = tree_math::parent(curr, size_);
  }
}

void
RatchetTree::set_path(uint32_t index, const bytes& leaf)
{
  const auto size_ = size();
  const auto root = tree_math::root(size_);

  auto curr = 2 * index;
  auto secret = leaf;
  while (curr != root) {
    while (curr > _nodes.size() - 1) {
      _nodes.emplace_back(_suite);
    }

    _nodes[curr] = new_node(secret);
    secret = Digest(_suite).write(secret).digest();

    curr = tree_math::parent(curr, size_);
  }

  _nodes[root] = new_node(secret);
}

uint32_t
RatchetTree::size() const
{
  return tree_math::size_from_width(_nodes.size());
}

bytes
RatchetTree::root_secret() const
{
  auto root = tree_math::root(size());
  auto val = _nodes[root]->secret();
  return *val;
}

bool
RatchetTree::check_invariant(size_t from) const
{
  std::vector<bool> in_dirpath(_nodes.size(), false);

  // Ensure that we have private keys for everything in the direct
  // path...
  auto dirpath = tree_math::dirpath(2 * from, size());
  dirpath.push_back(tree_math::root(size()));
  for (const auto& node : dirpath) {
    in_dirpath[node] = true;
    if (_nodes[node] && !_nodes[node]->private_key()) {
      std::cout << "Missing privkey: " << node << std::endl;
      return false;
    }
  }

  // ... and nothing else
  for (int i = 0; i < _nodes.size(); ++i) {
    if (in_dirpath[i]) {
      continue;
    }

    if (_nodes[i] && _nodes[i]->private_key()) {
      std::cout << "Inappropriate privkey: " << i << std::endl;
      return false;
    }
  }

  return true;
}

RatchetTreeNode
RatchetTree::new_node(const bytes& data) const
{
  return RatchetTreeNode(_suite, data);
}

std::vector<uint32_t>
RatchetTree::resolve(uint32_t node) const
{
  if (_nodes[node]) {
    return { node };
  }

  if (tree_math::level(node) == 0) {
    return {};
  }

  auto left = resolve(tree_math::left(node));
  auto right = resolve(tree_math::right(node, size()));
  left.insert(left.end(), right.begin(), right.end());
  return left;
}

bool
operator==(const RatchetTree& lhs, const RatchetTree& rhs)
{
  if (lhs._nodes.size() != rhs._nodes.size()) {
    return false;
  }

  for (int i = 0; i < lhs._nodes.size(); i += 1) {
    // Presence state needs to be the same
    if (bool(lhs._nodes[i]) != bool(rhs._nodes[i])) {
      return false;
    }

    // If they're both present, they need to be equal
    if (lhs._nodes[i] && rhs._nodes[i] &&
        lhs._nodes[i]->public_key() != rhs._nodes[i]->public_key()) {
      return false;
    }
  }

  return true;
}

std::ostream&
operator<<(std::ostream& out, const RatchetTree& obj)
{
  for (const auto& node : obj._nodes) {
    out << node << " ";
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
