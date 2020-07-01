#include "treekem.h"

namespace mls {

///
/// ParentNode
///

const NodeType ParentNode::type = NodeType::parent;

///
/// Node
///

const HPKEPublicKey&
Node::public_key() const
{
  if (std::holds_alternative<KeyPackage>(node)) {
    return std::get<KeyPackage>(node).init_key;
  }
  return std::get<ParentNode>(node).public_key;
}

///
/// OptionalNode
///

void
OptionalNode::set_leaf_hash(CipherSuite suite, NodeIndex index)
{
  auto leaf = std::optional<KeyPackage>{};
  if (node.has_value()) {
    leaf = std::get<KeyPackage>(node.value().node);
  }

  tls::ostream w;
  w << index << leaf;
  hash = Digest(suite).write(w.bytes()).digest();
}

void
OptionalNode::set_parent_hash(CipherSuite suite,
                              NodeIndex index,
                              const bytes& left,
                              const bytes& right)
{
  auto parent = std::optional<ParentNode>{};
  if (node.has_value()) {
    parent = std::get<ParentNode>(node.value().node);
  }

  tls::ostream w;
  w << index << parent;
  tls::vector<1>::encode(w, left);
  tls::vector<1>::encode(w, right);
  hash = Digest(suite).write(w.bytes()).digest();
}

///
/// TreeKEMPrivateKey
///

TreeKEMPrivateKey
TreeKEMPrivateKey::create(CipherSuite suite,
                          LeafCount size,
                          LeafIndex index,
                          const bytes& leaf_secret)
{
  auto priv = TreeKEMPrivateKey{ suite, index, {}, {}, {} };
  priv.implant(NodeIndex(index), size, leaf_secret);
  return priv;
}

TreeKEMPrivateKey
TreeKEMPrivateKey::joiner(CipherSuite suite,
                          LeafCount size,
                          LeafIndex index,
                          const bytes& leaf_secret,
                          NodeIndex intersect,
                          const bytes& path_secret)
{
  auto priv = TreeKEMPrivateKey{ suite, index, {}, {}, {} };
  priv.implant(intersect, size, path_secret);
  priv.path_secrets[NodeIndex(index)] = leaf_secret;
  return priv;
}

bytes
TreeKEMPrivateKey::path_step(const bytes& path_secret) const
{
  auto secret_size = Digest(suite).output_size();
  return hkdf_expand_label(suite, path_secret, "path", {}, secret_size);
}

void
TreeKEMPrivateKey::implant(NodeIndex start,
                           LeafCount size,
                           const bytes& path_secret)
{
  auto n = start;
  auto r = tree_math::root(NodeCount(size));
  auto secret = path_secret;

  while (n != r) {
    path_secrets[n] = secret;
    n = tree_math::parent(n, NodeCount(size));
    secret = path_step(secret);
  }

  path_secrets[r] = secret;
}

std::optional<HPKEPrivateKey>
TreeKEMPrivateKey::private_key(NodeIndex n)
{
  auto pki = private_key_cache.find(n);
  if (pki != private_key_cache.end()) {
    return pki->second;
  }

  auto i = path_secrets.find(n);
  if (i == path_secrets.end()) {
    return std::nullopt;
  }

  auto priv = HPKEPrivateKey::derive(suite, i->second);
  private_key_cache.insert({ n, priv });
  return private_key_cache.at(n);
}

void
TreeKEMPrivateKey::set_leaf_secret(const bytes& secret)
{
  path_secrets[NodeIndex(index)] = secret;
}

std::tuple<NodeIndex, bytes, bool>
TreeKEMPrivateKey::shared_path_secret(LeafIndex to) const
{
  auto n = tree_math::ancestor(index, to);
  auto i = path_secrets.find(n);
  if (i == path_secrets.end()) {
    return std::make_tuple(n, bytes{}, false);
  }

  return std::make_tuple(n, i->second, true);
}

void
TreeKEMPrivateKey::decap(LeafIndex from,
                         const TreeKEMPublicKey& pub,
                         const bytes& context,
                         const DirectPath& path)
{
  // Identify which node in the path secret we will be decrypting
  auto ni = NodeIndex(index);
  auto size = NodeCount(pub.size());
  auto dp = tree_math::dirpath(NodeIndex(from), size);
  if (dp.size() != path.nodes.size()) {
    throw ProtocolError("Malformed direct path");
  }

  int dpi = 0;
  auto last = NodeIndex(from);
  NodeIndex overlap_node, copath_node;
  for (dpi = 0; dpi < dp.size(); dpi++) {
    if (tree_math::in_path(ni, dp[dpi])) {
      overlap_node = dp[dpi];
      copath_node = tree_math::sibling(last, size);
    }

    last = dp[dpi];
  }

  if (dpi == dp.size()) {
    throw ProtocolError("No overlap in path");
  }

  // Identify which node in the resolution of the copath we will use to decrypt
  auto res = pub.resolve(copath_node);
  if (res.size() != path.nodes[dpi].node_secrets.size()) {
    throw ProtocolError("Malformed direct path node");
  }

  int resi = 0;
  NodeIndex res_overlap_node;
  for (resi = 0; resi < res.size(); resi++) {
    if (path_secrets.find(res[resi]) != path_secrets.end()) {
      break;
    }
  }

  if (resi == res.size()) {
    throw ProtocolError("No private key to decrypt path secret");
  }

  // Decrypt and implant
  auto priv = private_key(res[resi]).value();
  auto path_secret =
    priv.decrypt(suite, context, path.nodes[dpi].node_secrets[resi]);
  implant(overlap_node, LeafCount(size), path_secret);
}

///
/// TreeKEMPublicKey
///

TreeKEMPublicKey::TreeKEMPublicKey(CipherSuite suite_in)
  : suite(suite_in)
{}

LeafIndex
TreeKEMPublicKey::add_leaf(const KeyPackage& kp)
{
  // Find the leftmost free leaf
  auto index = LeafIndex(0);
  while (index.val < size().val &&
         nodes.at(NodeIndex(index).val).node.has_value()) {
    index.val++;
  }

  // Extend the tree if necessary
  auto ni = NodeIndex(index);
  if (index.val >= size().val) {
    nodes.resize(ni.val + 1);
  }

  // Set the leaf
  nodes.at(ni.val).node = Node{ kp };

  // Update the unmerged list
  for (auto& n : tree_math::dirpath(ni, NodeCount(size()))) {
    if (!nodes.at(n.val).node.has_value()) {
      continue;
    }

    auto& parent = std::get<ParentNode>(nodes.at(n.val).node.value().node);
    parent.unmerged_leaves.push_back(index);
  }

  return index;
}

void
TreeKEMPublicKey::update_leaf(LeafIndex index, const KeyPackage& kp)
{
  blank_path(index);
  nodes.at(index.val).node = Node{ kp };
  clear_hash_path(index);
}

void
TreeKEMPublicKey::blank_path(LeafIndex index)
{
  if (nodes.empty()) {
    return;
  }

  auto ni = NodeIndex(index);
  nodes.at(ni.val).node.reset();
  for (auto n : tree_math::dirpath(ni, NodeCount(size()))) {
    nodes.at(n.val).node.reset();
  }
}

void
TreeKEMPublicKey::merge(LeafIndex from, const DirectPath& path)
{
  auto ni = NodeIndex(from);
  nodes.at(ni.val).node = Node{ path.leaf_key_package };

  auto dp = tree_math::dirpath(ni, NodeCount(size()));
  if (dp.size() != path.nodes.size()) {
    throw ProtocolError("Malformed direct path");
  }

  for (int i = 0; i < dp.size(); i++) {
    auto n = dp[i];
    auto parent = ParentNode{ path.nodes[i].public_key, {}, {} };
  }

  // XXX(RLB): Should be possible to make a more targeted change, e.g., just
  // resetting the path
  clear_hash_all();
  set_hash_all();
}

void
TreeKEMPublicKey::set_hash_all()
{
  root_hash();
}

bytes
TreeKEMPublicKey::root_hash()
{
  auto r = tree_math::root(NodeCount(size()));
  return get_hash(r);
}

LeafCount
TreeKEMPublicKey::size() const
{
  return LeafCount(NodeCount(nodes.size()));
}

std::vector<NodeIndex>
TreeKEMPublicKey::resolve(NodeIndex index) const
{
  if (nodes[index.val].node.has_value()) {
    auto& node = nodes[index.val].node.value();
    auto out = std::vector<NodeIndex>{ index };
    if (std::holds_alternative<KeyPackage>(node.node)) {
      return out;
    }

    auto& parent = std::get<ParentNode>(node.node);
    auto& unmerged = parent.unmerged_leaves;
    std::transform(unmerged.begin(),
                   unmerged.end(),
                   std::back_inserter(out),
                   [](LeafIndex x) -> NodeIndex { return NodeIndex(x); });

    return out;
  }

  if (tree_math::level(index) == 0) {
    return {};
  }

  auto l = resolve(tree_math::left(index));
  auto r = resolve(tree_math::right(index, NodeCount(size())));
  l.insert(l.end(), r.begin(), r.end());
  return l;
}

std::optional<LeafIndex>
TreeKEMPublicKey::find(const KeyPackage& kp) const
{
  for (LeafIndex i{ 0 }; i < size(); i.val++) {
    const auto& node = nodes.at(NodeIndex(i).val).node;
    if (!node.has_value()) {
      continue;
    }

    const auto& node_kp = std::get<KeyPackage>(node.value().node);
    if (kp == node_kp) {
      return i;
    }
  }

  return std::nullopt;
}

std::optional<KeyPackage>
TreeKEMPublicKey::key_package(LeafIndex index) const
{
  const auto& node = nodes.at(NodeIndex(index).val).node;
  if (!node.has_value()) {
    return std::nullopt;
  }

  return std::get<KeyPackage>(node.value().node);
}

std::tuple<TreeKEMPrivateKey, DirectPath>
TreeKEMPublicKey::encap(LeafIndex from,
                        const bytes& context,
                        const bytes& leaf_secret,
                        const SignaturePrivateKey& sig_priv,
                        std::optional<KeyPackageOpts> opts)
{
  // Generate path secrets
  auto priv = TreeKEMPrivateKey::create(suite, size(), from, leaf_secret);

  // Package into a DirectPath
  auto path = DirectPath{};
  auto last = NodeIndex(from);
  for (auto n : tree_math::dirpath(NodeIndex(from), NodeCount(size()))) {
    auto path_secret = priv.path_secrets.at(n);
    auto node_priv = priv.private_key(n).value();
    auto node = RatchetNode{ node_priv.public_key(), {} };

    auto copath = tree_math::sibling(last, NodeCount(size()));
    auto res = resolve(copath);
    for (auto nr : res) {
      auto& node_pub = nodes.at(nr.val).node.value().public_key();
      auto ct = node_pub.encrypt(suite, context, path_secret);
      node.node_secrets.push_back(ct);
    }

    path.nodes.push_back(node);
    last = n;
  }

  // Sign the DirectPath
  auto leaf_priv = priv.private_key(NodeIndex(from)).value();
  path.sign(suite, leaf_priv.public_key(), sig_priv, opts);

  // Update the pubic key itself
  merge(from, path);
  clear_hash_all();
  set_hash_all();
  return std::make_tuple(priv, path);
}

void
TreeKEMPublicKey::clear_hash_all()
{
  for (auto& node : nodes) {
    node.hash.resize(0);
  }
}

void
TreeKEMPublicKey::clear_hash_path(LeafIndex index)
{
  auto dp = tree_math::dirpath(NodeIndex(index), NodeCount(size()));
  nodes.at(NodeIndex(index).val).hash.resize(0);
  for (auto n : dp) {
    nodes.at(n.val).hash.resize(0);
  }
}

bytes
TreeKEMPublicKey::get_hash(NodeIndex index)
{
  if (!nodes.at(index.val).hash.empty()) {
    return nodes.at(index.val).hash;
  }

  if (tree_math::level(index) == 0) {
    nodes.at(index.val).set_leaf_hash(suite, index);
    return nodes.at(index.val).hash;
  }

  auto lh = get_hash(tree_math::left(index));
  auto rh = get_hash(tree_math::right(index, NodeCount(size())));
  nodes.at(index.val).set_parent_hash(suite, index, lh, rh);
  return nodes.at(index.val).hash;
}

std::ostream&
operator<<(std::ostream& str, const TreeKEMPublicKey& obj)
{
  auto suite = obj.suite;
  auto size = obj.nodes.size();

  str << "=== TreeKEMPublicKey ===" << std::endl;
  str << "suite=" << 0 << " nodes=" << size << std::endl;
  for (size_t i = 0; i < size; i++) {
    str << "  " << i << " ";
    if (!obj.nodes[i].node.has_value()) {
      str << "-" << std::endl;
      continue;
    }

    str << obj.nodes[i].node.value().public_key().data << std::endl;
  }

  return str;
}

} // namespace mls
