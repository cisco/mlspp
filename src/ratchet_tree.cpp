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
  , _priv(std::nullopt)
  , _pub(suite)
{}

RatchetTreeNode&
RatchetTreeNode::operator=(const RatchetTreeNode& other)
{
  _suite = other._suite;
  _priv = other._priv;
  _pub = other._pub;
  _cred = other._cred;
  return *this;
}

RatchetTreeNode::RatchetTreeNode(CipherSuite suite, const bytes& secret)
  : CipherAware(suite)
  , _priv(DHPrivateKey::derive(suite, secret))
  , _pub(suite)
{
  _pub = _priv.value().public_key();
}

RatchetTreeNode::RatchetTreeNode(const DHPrivateKey& priv)
  : CipherAware(priv.cipher_suite())
  , _priv(priv)
  , _pub(priv.public_key())
{}

RatchetTreeNode::RatchetTreeNode(const DHPublicKey& pub)
  : CipherAware(pub.cipher_suite())
  , _priv(std::nullopt)
  , _pub(pub)
{}

bool
RatchetTreeNode::public_equal(const RatchetTreeNode& other) const
{
  return _pub == other._pub;
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

const std::optional<Credential>&
RatchetTreeNode::credential() const
{
  return _cred;
}

void
RatchetTreeNode::set_credential(const Credential& cred)
{
  _cred = cred;
}

void
RatchetTreeNode::merge(const RatchetTreeNode& other)
{
  if (other._pub != _pub) {
    _pub = other._pub;
    _priv = std::nullopt;
  }

  if (other._priv.has_value()) {
    _priv = other._priv.value();
  }

  // Credential is immutable
}

bool
operator==(const RatchetTreeNode& lhs, const RatchetTreeNode& rhs)
{
  // Equality is based on public attributes only
  return (lhs._pub == rhs._pub) && (lhs._cred == rhs._cred);
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
  return out << obj._pub << obj._cred;
}

tls::istream&
operator>>(tls::istream& in, RatchetTreeNode& obj)
{
  obj._priv = std::nullopt;
  return in >> obj._pub >> obj._cred;
}

///
/// OptionalRatchetTreeNode
///

bool
OptionalRatchetTreeNode::has_private() const
{
  return has_value() && value().private_key().has_value();
}

const bytes&
OptionalRatchetTreeNode::hash() const
{
  return _hash;
}

void
OptionalRatchetTreeNode::merge(const RatchetTreeNode& other)
{
  if (!has_value()) {
    *this = other;
  } else {
    value().merge(other);
  }
}

struct LeafNodeInfo
{
  DHPublicKey public_key;
  Credential credential;
};

tls::ostream&
operator<<(tls::ostream& out, const LeafNodeInfo& obj)
{
  return out << obj.public_key << obj.credential;
}

struct LeafNodeHashInput
{
  const uint8_t hash_type = 0;
  tls::optional<LeafNodeInfo> info;
};

tls::ostream&
operator<<(tls::ostream& out, const LeafNodeHashInput& obj)
{
  return out << obj.hash_type << obj.info;
}

void
OptionalRatchetTreeNode::set_leaf_hash(CipherSuite suite)
{
  auto hash_input_str = LeafNodeHashInput{};
  if (has_value()) {
    auto& pub = value().public_key();
    auto& cred = value().credential();
    if (!cred.has_value()) {
      throw InvalidParameterError(
        "Leaf node not provisioned with a credential");
    }

    hash_input_str.info = LeafNodeInfo{ pub, cred.value() };
  }

  auto hash_input = tls::marshal(hash_input_str);
  _hash = Digest(suite).write(hash_input).digest();
}

struct ParentNodeHashInput
{
  const uint8_t hash_type = 1;
  tls::optional<DHPublicKey> public_key;
  tls::opaque<1> left_hash;
  tls::opaque<1> right_hash;
};

tls::ostream&
operator<<(tls::ostream& out, const ParentNodeHashInput& obj)
{
  return out << obj.hash_type << obj.public_key << obj.left_hash
             << obj.right_hash;
}

void
OptionalRatchetTreeNode::set_hash(CipherSuite suite,
                                  const OptionalRatchetTreeNode& left,
                                  const OptionalRatchetTreeNode& right)
{
  auto hash_input_str = ParentNodeHashInput{};
  if (has_value()) {
    hash_input_str.public_key = value().public_key();
  }
  hash_input_str.left_hash = left._hash;
  hash_input_str.right_hash = right._hash;

  auto hash_input = tls::marshal(hash_input_str);
  _hash = Digest(suite).write(hash_input).digest();
}

std::ostream&
operator<<(std::ostream& out, const OptionalRatchetTreeNode& opt)
{
  if (!opt.has_value()) {
    return out << "_";
  }

  return out << opt.value();
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

RatchetTree::RatchetTree(CipherSuite suite,
                         const bytes& secret,
                         const Credential& cred)
  : CipherAware(suite)
  , _nodes(suite)
  , _secret_size(Digest(suite).output_size())
{
  add_leaf(LeafIndex{ 0 }, secret, cred);
}

RatchetTree::RatchetTree(CipherSuite suite,
                         const std::vector<bytes>& secrets,
                         const std::vector<Credential>& creds)
  : CipherAware(suite)
  , _nodes(suite)
  , _secret_size(Digest(suite).output_size())
{
  if (secrets.size() != creds.size()) {
    throw InvalidParameterError("Incorrect tree initialization data");
  }

  for (uint32_t i = 0; i < secrets.size(); i += 1) {
    add_leaf(LeafIndex{ i }, secrets[i], creds[i]);
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
      auto& pub = _nodes[res_node].value().public_key();
      auto ciphertext = pub.encrypt(path_secret);
      path_node.node_secrets.push_back(ciphertext);
    }

    path.nodes.push_back(path_node);
  }

  return path;
}

RatchetTree::MergePath
RatchetTree::decrypt(LeafIndex from, const DirectPath& path) const
{
  MergePath merge_path;

  auto copath = tree_math::copath(NodeIndex{ from }, node_size());
  if (path.nodes.size() != copath.size() + 1) {
    throw ProtocolError("Malformed DirectPath");
  }

  // Handle the leaf node
  if (!path.nodes[0].node_secrets.empty()) {
    throw ProtocolError("Malformed initial node");
  }
  merge_path.nodes.emplace_back(path.nodes[0].public_key);

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
        auto& tree_node = _nodes[res[j]];
        if (!tree_node.has_private()) {
          continue;
        }

        auto encrypted_secret = path_node.node_secrets[j];
        auto& priv = tree_node.value().private_key().value();
        path_secret = priv.decrypt(encrypted_secret);
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

      merge_path.nodes.push_back(temp);
    } else {
      merge_path.nodes.emplace_back(path_node.public_key);
    }
  }

  merge_path.root_path_secret = path_secret;
  return merge_path;
}

void
RatchetTree::merge_path(LeafIndex from, const RatchetTree::MergePath& path)
{
  auto dirpath = tree_math::dirpath(NodeIndex{ from }, node_size());
  dirpath.push_back(root_index());
  if (dirpath.size() != path.nodes.size()) {
    throw InvalidParameterError("Malformed MergePath");
  }

  for (size_t i = 0; i < dirpath.size(); ++i) {
    auto curr = dirpath[i];
    _nodes[curr].merge(path.nodes[i]);
  }

  set_hash_path(from);
}

void
RatchetTree::add_leaf(LeafIndex index,
                      const DHPublicKey& pub,
                      const Credential& cred)
{
  if (_suite != pub.cipher_suite()) {
    throw InvalidParameterError("Incorrect ciphersuite");
  }

  auto node = RatchetTreeNode(pub);
  node.set_credential(cred);

  add_leaf_inner(index, node);
}

void
RatchetTree::add_leaf(LeafIndex index,
                      const bytes& leaf_secret,
                      const Credential& cred)
{
  auto node = new_node(leaf_secret);
  node.set_credential(cred);

  add_leaf_inner(index, node);
}

void
RatchetTree::add_leaf_inner(LeafIndex index, const RatchetTreeNode& node_val)
{
  if (index.val == size()) {
    if (!_nodes.empty()) {
      _nodes.emplace_back(std::nullopt);
    }
    _nodes.emplace_back(std::nullopt);
  }

  blank_path(index);

  auto node = NodeIndex{ index };
  _nodes[node] = node_val;

  set_hash_path(index);
}

void
RatchetTree::blank_path(LeafIndex index)
{
  if (_nodes.empty()) {
    return;
  }

  const auto node_count = node_size();
  const auto root = root_index();

  auto curr = NodeIndex{ index };
  while (curr != root) {
    _nodes[curr] = std::nullopt;
    curr = tree_math::parent(curr, node_count);
  }

  _nodes[root] = std::nullopt;
  set_hash_path(index);
}

bytes
RatchetTree::set_path(LeafIndex index, const bytes& leaf)
{
  const auto node_count = node_size();
  const auto root = root_index();

  auto curr = NodeIndex{ index };
  if (!_nodes[curr].has_value()) {
    throw InvalidParameterError("Cannot update a blank leaf");
  }
  _nodes[curr].value().merge(new_node(leaf));

  auto path_secret = path_step(leaf);
  curr = tree_math::parent(curr, node_count);
  while (curr != root) {
    _nodes[curr] = new_node(path_secret);

    path_secret = path_step(path_secret);
    curr = tree_math::parent(curr, node_count);
  }

  // If there is only one member, then leaf == root == 0
  // and some special considerations apply
  if (root != NodeIndex{ index }) {
    _nodes[root] = new_node(path_secret);
  } else {
    path_secret = leaf;
  }

  set_hash_path(index);
  return path_secret;
}

const Credential&
RatchetTree::get_credential(LeafIndex index) const
{
  auto node = NodeIndex{ index };

  if (!_nodes[node].has_value()) {
    throw InvalidParameterError("Requested credential for a blank leaf");
  }

  auto& cred = _nodes[node].value().credential();
  if (!cred.has_value()) {
    throw InvalidParameterError(
      "Leaf node was not populated with a credential");
  }

  return cred.value();
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
  auto node = NodeIndex{ index };
  if (node.val >= _nodes.size()) {
    return false;
  }

  return _nodes[node].has_value();
}

bytes
RatchetTree::root_hash() const
{
  return _nodes[root_index()].hash();
}

bool
RatchetTree::check_credentials() const
{
  for (LeafIndex i{ 0 }; i.val < size(); i.val += 1) {
    auto& node = _nodes[NodeIndex{ i }];
    if (node.has_value() && !node.value().credential().has_value()) {
      return false;
    }
  }
  return true;
}

bool
RatchetTree::check_invariant(LeafIndex from) const
{
  std::vector<bool> in_dirpath(_nodes.size(), false);

  // Ensure that we have private keys for everything in the direct
  // path...
  auto dirpath = tree_math::dirpath(NodeIndex{ from }, node_size());
  dirpath.push_back(root_index());
  for (const auto& node : dirpath) {
    in_dirpath[node.val] = true;
    if (_nodes[node].has_value() && !_nodes[node].has_private()) {
      return false;
    }
  }

  // ... and nothing else
  for (size_t i = 0; i < _nodes.size(); ++i) {
    if (in_dirpath[i]) {
      continue;
    }

    if (_nodes[i].has_private()) {
      throw std::runtime_error("unexpected private key");
      return false;
    }
  }

  return true;
}

NodeIndex
RatchetTree::root_index() const
{
  return tree_math::root(node_size());
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
  auto out = hkdf_expand_label(_suite, path_secret, "path", {}, _secret_size);
  return out;
}

bytes
RatchetTree::node_step(const bytes& path_secret) const
{
  auto out = hkdf_expand_label(_suite, path_secret, "node", {}, _secret_size);
  return out;
}

void
RatchetTree::set_hash(NodeIndex index)
{
  if (tree_math::level(index) == 0) {
    _nodes[index].set_leaf_hash(_suite);
    return;
  }

  auto left = tree_math::left(index);
  auto right = tree_math::right(index, node_size());
  _nodes[index].set_hash(_suite, _nodes[left], _nodes[right]);
}

void
RatchetTree::set_hash_path(LeafIndex index)
{
  auto curr = NodeIndex{ index };
  set_hash(curr);

  auto node_count = node_size();
  auto root = root_index();
  do {
    curr = tree_math::parent(curr, node_count);
    set_hash(curr);
  } while (curr != root);
}

void
RatchetTree::set_hash_all(NodeIndex index)
{
  if (_nodes.empty()) {
    return;
  }

  if (tree_math::level(index) == 0) {
    set_hash(index);
    return;
  }

  auto left = tree_math::left(index);
  auto right = tree_math::right(index, node_size());
  set_hash_all(left);
  set_hash_all(right);
  set_hash(index);
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
    if (lhs._nodes[i].has_value() && rhs._nodes[i].has_value() &&
        (lhs._nodes[i].value() != rhs._nodes[i].value())) {
      return false;
    }

    // Hashes need to be the same
    if (lhs._nodes[i].hash() != rhs._nodes[i].hash()) {
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
  in >> obj._nodes;
  obj.set_hash_all(obj.root_index());
  return in;
}

namespace test {

const RatchetTreeNodeVector&
TestRatchetTree::nodes() const
{
  return _nodes;
}

} // namespace test

} // namespace mls
