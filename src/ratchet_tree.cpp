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

RatchetTreeNode::RatchetTreeNode(CipherSuite suite, const bytes& secret)
  : CipherAware(suite)
  , _priv(HPKEPrivateKey::derive(suite, secret))
  , _pub(suite)
{
  _pub = _priv.value().public_key();
}

RatchetTreeNode::RatchetTreeNode(const HPKEPrivateKey& priv)
  : CipherAware(priv.cipher_suite())
  , _priv(priv)
  , _pub(priv.public_key())
{}

RatchetTreeNode::RatchetTreeNode(const HPKEPublicKey& pub)
  : CipherAware(pub.cipher_suite())
  , _priv(std::nullopt)
  , _pub(pub)
{}

bool
RatchetTreeNode::public_equal(const RatchetTreeNode& other) const
{
  return _pub == other._pub;
}

const std::optional<HPKEPrivateKey>&
RatchetTreeNode::private_key() const
{
  return _priv;
}

const HPKEPublicKey&
RatchetTreeNode::public_key() const
{
  return _pub;
}

const std::vector<LeafIndex>&
RatchetTreeNode::unmerged_leaves() const
{
  return _unmerged_leaves;
}

const std::optional<Credential>&
RatchetTreeNode::credential() const
{
  return _cred;
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

  // List of unmerged leaves is cleared on update
  _unmerged_leaves.clear();
}

void
RatchetTreeNode::set_credential(const Credential& cred)
{
  _cred = cred;
}

void
RatchetTreeNode::add_unmerged(LeafIndex index)
{
  _unmerged_leaves.push_back(index);
}

///
/// OptionalRatchetTreeNode
///

OptionalRatchetTreeNode::OptionalRatchetTreeNode(CipherSuite suite,
                                                 const bytes& secret)
  : parent(RatchetTreeNode(suite, secret))
{}

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
  HPKEPublicKey public_key;
  Credential credential;

  TLS_SERIALIZABLE(public_key, credential);
};

struct LeafNodeHashInput
{
  const uint8_t hash_type = 0;
  tls::optional<LeafNodeInfo> info;

  TLS_SERIALIZABLE(hash_type, info);
};

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

struct ParentNodeInfo
{
  HPKEPublicKey public_key;
  tls::vector<LeafIndex, 4> unmerged_leaves;

  TLS_SERIALIZABLE(public_key, unmerged_leaves);
};

struct ParentNodeHashInput
{
  const uint8_t hash_type = 1;
  tls::optional<ParentNodeInfo> info;
  tls::opaque<1> left_hash;
  tls::opaque<1> right_hash;

  TLS_SERIALIZABLE(hash_type, info, left_hash, right_hash);
};

void
OptionalRatchetTreeNode::set_hash(CipherSuite suite,
                                  const OptionalRatchetTreeNode& left,
                                  const OptionalRatchetTreeNode& right)
{
  auto hash_input_str = ParentNodeHashInput{};
  if (has_value()) {
    hash_input_str.info =
      ParentNodeInfo{ value().public_key(), value().unmerged_leaves() };
  }
  hash_input_str.left_hash = left._hash;
  hash_input_str.right_hash = right._hash;

  auto hash_input = tls::marshal(hash_input_str);
  _hash = Digest(suite).write(hash_input).digest();
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

RatchetTree::RatchetTree(const HPKEPrivateKey& priv, const Credential& cred)
  : CipherAware(priv.cipher_suite())
  , _nodes(priv.cipher_suite())
  , _secret_size(Digest(priv.cipher_suite()).output_size())
{
  _nodes.emplace_back(priv);
  _nodes[0].value().set_credential(cred);
  set_hash(NodeIndex{ 0 });
}

std::tuple<DirectPath, bytes>
RatchetTree::encap(LeafIndex from,
                   const bytes& context,
                   const bytes& leaf_secret)
{
  DirectPath path{ _suite };

  auto leaf_node = NodeIndex{ from };
  _nodes[leaf_node].merge(new_node(leaf_secret));
  path.nodes.push_back({ _nodes[leaf_node].value().public_key(), {} });

  auto path_secret = leaf_secret;
  auto copath = tree_math::copath(NodeIndex{ from }, node_size());
  for (const auto& node : copath) {
    path_secret = path_step(path_secret);

    auto parent = tree_math::parent(node, node_size());
    _nodes[parent] = new_node(path_secret);

    RatchetNode path_node{ _suite };
    path_node.public_key = _nodes[parent].value().public_key();

    for (const auto& res_node : resolve(node)) {
      auto& pub = _nodes[res_node].value().public_key();
      auto ciphertext = pub.encrypt(context, path_secret);
      path_node.node_secrets.push_back(ciphertext);
    }

    path.nodes.push_back(path_node);
  }

  set_hash_path(from);

  return std::make_tuple(path, path_secret);
}

bytes
RatchetTree::decap(LeafIndex from, const bytes& context, const DirectPath& path)
{
  auto copath = tree_math::copath(NodeIndex{ from }, node_size());
  if (path.nodes.size() != copath.size() + 1) {
    throw ProtocolError("Malformed DirectPath");
  }

  auto dirpath = tree_math::dirpath(NodeIndex{ from }, node_size());
  dirpath.push_back(root_index());

  // Handle the leaf node
  if (!path.nodes[0].node_secrets.empty()) {
    throw ProtocolError("Malformed initial node");
  }
  _nodes[NodeIndex{ from }].merge(path.nodes[0].public_key);

  // Handle the remainder of the path
  bytes path_secret;
  bool have_secret = false;
  for (size_t i = 0; i < copath.size(); ++i) {
    const auto curr = copath[i];
    const auto& path_node = path.nodes[i + 1];

    // Decrypt or update the path secret
    if (!have_secret) {
      auto res = resolve(curr);
      if (path_node.node_secrets.size() != res.size()) {
        throw ProtocolError("Malformed RatchetNode");
      }

      auto ri = res.begin();
      auto si = path_node.node_secrets.begin();
      for (; ri != res.end(); ++ri, ++si) {
        auto& tree_node = _nodes[*ri];
        if (!tree_node.has_private()) {
          continue;
        }

        auto& encrypted_secret = *si;
        auto& priv = tree_node.value().private_key().value();
        path_secret = priv.decrypt(context, encrypted_secret);
        have_secret = true;
      }
    } else {
      path_secret = path_step(path_secret);
    }

    // Update the current direct path node as appropriate
    if (have_secret) {
      auto temp = new_node(path_secret);
      if (temp.public_key() != path_node.public_key) {
        throw InvalidParameterError("Incorrect node public key");
      }

      _nodes[dirpath[i + 1]].merge(temp);
    } else {
      _nodes[dirpath[i + 1]].merge(path_node.public_key);
    }
  }

  set_hash_path(from);
  return path_secret;
}

void
RatchetTree::blank_path(LeafIndex index, bool include_leaf)
{
  if (_nodes.empty()) {
    return;
  }

  const auto node_count = node_size();
  const auto root = root_index();

  auto first = true;
  auto curr = NodeIndex{ index };
  while (curr != root) {
    auto skip = first && !include_leaf;
    first = false;

    if (!skip) {
      _nodes[curr] = std::nullopt;
    }

    curr = tree_math::parent(curr, node_count);
  }

  _nodes[root] = std::nullopt;
  set_hash_path(index);
}

void
RatchetTree::add_leaf(LeafIndex index,
                      const HPKEPublicKey& leaf_key,
                      const Credential& credential)
{
  if (index.val == size()) {
    if (!_nodes.empty()) {
      _nodes.emplace_back(std::nullopt);
    }
    _nodes.emplace_back(std::nullopt);
  }

  // Set the leaf node
  auto node = NodeIndex{ index };
  if (_nodes[node].has_value()) {
    throw InvalidParameterError("Add target already occupied");
  }

  auto node_val = RatchetTreeNode(leaf_key);
  node_val.set_credential(credential);
  _nodes[node] = node_val;

  // Add to unmerged_leaves
  auto dirpath = tree_math::dirpath(node, node_size());
  for (const auto& i : dirpath) {
    if (i == NodeIndex{ index } || !_nodes[i].has_value()) {
      continue;
    }

    _nodes[i].value().add_unmerged(index);
  }

  set_hash_path(index);
}

void
RatchetTree::merge(LeafIndex index, const HPKEPublicKey& leaf_key)
{
  auto curr = NodeIndex{ index };
  if (!_nodes[curr].has_value()) {
    throw InvalidParameterError("Cannot update a blank leaf");
  }
  _nodes[curr].value().merge(leaf_key);
  set_hash_path(index);
}

void
RatchetTree::merge(LeafIndex index, const HPKEPrivateKey& leaf_priv)
{
  auto curr = NodeIndex{ index };
  if (!_nodes[curr].has_value()) {
    throw InvalidParameterError("Cannot update a blank leaf");
  }
  _nodes[curr].value().merge(leaf_priv);
  set_hash_path(index);
}

void
RatchetTree::merge(LeafIndex index, const bytes& leaf_secret)
{
  auto curr = NodeIndex{ index };
  if (!_nodes[curr].has_value()) {
    throw InvalidParameterError("Cannot update a blank leaf");
  }

  _nodes[curr].value().merge({ _suite, leaf_secret });
  set_hash_path(index);
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

LeafIndex
RatchetTree::leftmost_free() const
{
  auto curr = LeafIndex{ 0 };
  while (occupied(curr) && curr.val < size()) {
    curr.val += 1;
  }

  return curr;
}

std::optional<LeafIndex>
RatchetTree::find(const ClientInitKey& cik) const
{
  for (LeafIndex i{ 0 }; i.val < size(); i.val += 1) {
    auto& node = _nodes[NodeIndex(i)];

    if (!node.has_value() || !node.value().credential().has_value()) {
      continue;
    }

    auto hpke_match = (cik.init_key == node.value().public_key());
    auto sig_match = (cik.credential == node.value().credential().value());
    if (hpke_match && sig_match) {
      return i;
    }
  }

  return std::nullopt;
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

bytes
RatchetTree::root_hash() const
{
  return _nodes[root_index()].hash();
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

std::list<NodeIndex>
RatchetTree::resolve(NodeIndex index)
{
  if (_nodes[index].has_value()) {
    std::list<NodeIndex> out{ index };
    for (auto i : _nodes[index].value().unmerged_leaves()) {
      out.emplace_back(i);
    }
    return out;
  }

  if (tree_math::level(index) == 0) {
    return {};
  }

  auto l = resolve(tree_math::left(index));
  auto r = resolve(tree_math::right(index, node_size()));
  l.insert(l.end(), r.begin(), r.end());
  return l;
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
operator<<(std::ostream& out, const RatchetTree obj)
{
  out << "=== tree ===" << std::endl;
  for (uint32_t i = 0; i < obj._nodes.size(); ++i) {
    out << "    " << i << " ";
    if (!obj._nodes[i].has_value()) {
      out << "_";
    } else {
      const auto& node = obj._nodes[i].value();

      out << node.public_key().to_bytes() << " (";
      for (auto j : node.unmerged_leaves()) {
        out << j.val << " ";
      }
      out << ")";
    }
    out << " " << obj._nodes[i].hash() << std::endl;
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

} // namespace mls
