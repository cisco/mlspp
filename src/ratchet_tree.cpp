#include "ratchet_tree.h"
#include "common.h"
#include "messages.h"
#include "tree_math.h"

namespace mls {

///
/// RatchetTreeNode
///

RatchetTreeNode::RatchetTreeNode(CipherSuite suite)
  : CipherAware(suite)
  , _secret(std::nullopt)
  , _priv(std::nullopt)
  , _pub(suite)
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
  , _secret(std::nullopt)
  , _priv(priv)
  , _pub(priv.public_key())
{}

RatchetTreeNode::RatchetTreeNode(const DHPublicKey& pub)
  : CipherAware(pub.cipher_suite())
  , _secret(std::nullopt)
  , _priv(std::nullopt)
  , _pub(pub)
{}

bool
RatchetTreeNode::public_equal(const RatchetTreeNode& other) const
{
  return _pub == other._pub;
}

const std::optional<bytes>&
RatchetTreeNode::secret() const
{
  return _secret;
}

const std::optional<DHPrivateKey>&
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
  obj._priv = std::nullopt;
  obj._secret = std::nullopt;
  return in >> obj._pub;
}

///
/// RatchetTreeNodeVector
///

OptionalRatchetTreeNode& RatchetTreeNodeVector::operator[](
  const NodeIndex index)
{
  auto vec = static_cast<parent*>(this);
  return (*vec)[index.val];
}

const OptionalRatchetTreeNode& RatchetTreeNodeVector::operator[](
  const NodeIndex index) const
{
  auto vec = static_cast<const parent*>(this);
  return (*vec)[index.val];
}

///
/// RatchetTree
///

RatchetTree::RatchetTree(CipherSuite suite)
  : CipherAware(suite)
  , _nodes(suite)
  , _secret_size(Digest(suite).output_size())
{}

RatchetTree::RatchetTree(CipherSuite suite, const bytes& secret)
  : CipherAware(suite)
  , _nodes(suite)
  , _secret_size(Digest(suite).output_size())
{
  add_leaf(LeafIndex{ 0 }, secret);
}

RatchetTree::RatchetTree(CipherSuite suite, const std::vector<bytes>& secrets)
  : CipherAware(suite)
  , _nodes(suite)
  , _secret_size(Digest(suite).output_size())
{
  for (uint32_t i = 0; i < secrets.size(); i += 1) {
    add_leaf(LeafIndex{ i }, secrets[i]);
    set_path(LeafIndex{ i }, secrets[i]);
  }
}

DirectPath
RatchetTree::encrypt(LeafIndex from, const bytes& leaf_secret) const
{
  DirectPath path{ _suite };

  auto leaf_node = new_node(leaf_secret);
  path.nodes.push_back({ leaf_node.public_key(), {} });

  auto path_secret = leaf_secret;
  auto copath = tree_math::copath(NodeIndex{ from }, node_size());
  for (const auto& node : copath) {
    path_secret = path_step(path_secret);

    RatchetNode path_node{ _suite };
    path_node.public_key = new_node(path_secret).public_key();

    for (const auto& res_node : tree_math::resolve(_nodes, node)) {
      auto ciphertext = _nodes[res_node]->public_key().encrypt(path_secret);
      path_node.node_secrets.push_back(ciphertext);
    }

    path.nodes.push_back(path_node);
  }

  return path;
}

RatchetTree::MergeInfo
RatchetTree::decrypt(LeafIndex from, const DirectPath& path) const
{
  MergeInfo info;

  auto copath = tree_math::copath(NodeIndex{ from }, node_size());
  if (path.nodes.size() != copath.size() + 1) {
    throw ProtocolError("Malformed DirectPath");
  }

  // Handle the leaf node
  if (!path.nodes[0].node_secrets.empty()) {
    throw ProtocolError("Malformed initial node");
  }
  info.public_keys.push_back(path.nodes[0].public_key);

  // Handle the remainder of the path
  bytes path_secret;
  bool have_secret = false;
  for (size_t i = 0; i < copath.size(); ++i) {
    const auto curr = copath[i];
    const auto& path_node = path.nodes[i + 1];

    if (!have_secret) {
      auto res = tree_math::resolve(_nodes, curr);
      if (path_node.node_secrets.size() != res.size()) {
        throw ProtocolError("Malformed RatchetNode");
      }

      for (size_t j = 0; j < res.size(); ++j) {
        auto tree_node = _nodes[res[j]];
        if (!tree_node || !tree_node->private_key()) {
          continue;
        }

        auto encrypted_secret = path_node.node_secrets[j];
        path_secret = tree_node->private_key()->decrypt(encrypted_secret);
        have_secret = true;
      }
    } else {
      path_secret = path_step(path_secret);
    }

    if (have_secret) {
      auto temp = new_node(path_secret);
      if (temp.public_key() != path_node.public_key) {
        throw InvalidParameterError("Incorrect node public key");
      }

      info.secrets.push_back(path_secret);
    } else {
      info.public_keys.push_back(path_node.public_key);
    }
  }

  return info;
}

void
RatchetTree::merge_path(LeafIndex from, const RatchetTree::MergeInfo& info)
{
  const auto dirpath = tree_math::dirpath(NodeIndex{ from }, node_size());
  if (dirpath.size() + 1 != info.public_keys.size() + info.secrets.size()) {
    throw InvalidParameterError("Malformed MergeInfo");
  }

  auto key_list_size = info.public_keys.size();
  for (size_t i = 0; i < dirpath.size(); ++i) {
    auto curr = dirpath[i];
    while (curr.val > _nodes.size() - 1) {
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

  auto root = tree_math::root(node_size());
  auto node = new_node(info.secrets.back());
  _nodes[root].merge(node);
}

void
RatchetTree::add_leaf(LeafIndex index, const DHPublicKey& pub)
{
  if (_suite != pub.cipher_suite()) {
    throw InvalidParameterError("Incorrect ciphersuite");
  }

  if (index.val == size()) {
    if (!_nodes.empty()) {
      _nodes.emplace_back(std::nullopt);
    }

    _nodes.emplace_back(RatchetTreeNode(pub));
  } else {
    auto node = NodeIndex{ index };
    _nodes[node] = RatchetTreeNode(pub);
  }
}

void
RatchetTree::add_leaf(LeafIndex index, const bytes& leaf_secret)
{
  if (index.val == size()) {
    if (!_nodes.empty()) {
      _nodes.emplace_back(std::nullopt);
    }

    _nodes.emplace_back(new_node(leaf_secret));
  } else {
    auto node = NodeIndex{ index };
    _nodes[node] = new_node(leaf_secret);
  }
}

void
RatchetTree::blank_path(LeafIndex index)
{
  const auto node_count = node_size();
  const auto root = tree_math::root(node_count);

  auto curr = NodeIndex{ index };
  while (curr != root) {
    _nodes[curr] = std::nullopt;
    curr = tree_math::parent(curr, node_count);
  }
}

void
RatchetTree::set_path(LeafIndex index, const bytes& leaf)
{
  const auto node_count = node_size();
  const auto root = tree_math::root(node_count);

  auto curr = NodeIndex{ index };
  auto path_secret = leaf;
  while (curr != root) {
    while (curr.val > _nodes.size() - 1) {
      _nodes.emplace_back(_suite);
    }

    _nodes[curr] = new_node(path_secret);
    path_secret = path_step(path_secret);

    curr = tree_math::parent(curr, node_count);
  }

  _nodes[root] = new_node(path_secret);
}

LeafCount
RatchetTree::leaf_span() const
{
  uint32_t max = size() - 1;
  while (max != 0 && !_nodes[2 * max]) {
    max -= 1;
  }
  return LeafCount{ max + 1 };
}

void
RatchetTree::truncate(LeafCount leaves)
{
  auto w = NodeCount{ leaves };
  _nodes.resize(w.val);
}

uint32_t
RatchetTree::size() const
{
  return LeafCount{ node_size() }.val;
}

bool
RatchetTree::occupied(LeafIndex index) const
{
  NodeIndex node_index{ index };
  return bool(_nodes[node_index]);
}

bytes
RatchetTree::root_secret() const
{
  auto root = tree_math::root(node_size());
  auto val = _nodes[root]->secret();
  return *val;
}

bool
RatchetTree::check_invariant(LeafIndex from) const
{
  std::vector<bool> in_dirpath(_nodes.size(), false);

  // Ensure that we have private keys for everything in the direct
  // path...
  auto dirpath = tree_math::dirpath(NodeIndex{ from }, node_size());
  dirpath.push_back(tree_math::root(node_size()));
  for (const auto& node : dirpath) {
    in_dirpath[node.val] = true;
    if (_nodes[node] && !_nodes[node]->private_key()) {
      return false;
    }
  }

  // ... and nothing else
  for (size_t i = 0; i < _nodes.size(); ++i) {
    if (in_dirpath[i]) {
      continue;
    }

    if (_nodes[i] && _nodes[i]->private_key()) {
      return false;
    }
  }

  return true;
}

NodeCount
RatchetTree::node_size() const
{
  return NodeCount{ uint32_t(_nodes.size()) };
}

RatchetTreeNode
RatchetTree::new_node(const bytes& path_secret) const
{
  auto node_secret = node_step(path_secret);
  return RatchetTreeNode(_suite, node_secret);
}

bytes
RatchetTree::path_step(const bytes& path_secret) const
{
  return hkdf_expand_label(_suite, path_secret, "path", {}, _secret_size);
}

bytes
RatchetTree::node_step(const bytes& path_secret) const
{
  return hkdf_expand_label(_suite, path_secret, "node", {}, _secret_size);
}

bool
operator==(const RatchetTree& lhs, const RatchetTree& rhs)
{
  if (lhs._nodes.size() != rhs._nodes.size()) {
    return false;
  }

  for (size_t i = 0; i < lhs._nodes.size(); i += 1) {
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
