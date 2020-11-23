#include <mls/treekem.h>

namespace mls {

///
/// Node
///

const HPKEPublicKey&
Node::public_key() const
{
  static const auto get_key = overloaded{
    [](const KeyPackage& kp) -> const HPKEPublicKey& { return kp.init_key; },
    [](const ParentNode& node) -> const HPKEPublicKey& {
      return node.public_key;
    },
  };
  return var::visit(get_key, node);
}

bytes
Node::parent_hash() const
{
  static const auto get_key = overloaded{
    [](const KeyPackage& kp) {
      auto maybe_phe = kp.extensions.find<ParentHashExtension>();
      if (!maybe_phe) {
        return bytes{};
      }

      return opt::get(maybe_phe).parent_hash;
    },
    [](const ParentNode& node) { return node.parent_hash; },
  };
  return var::visit(get_key, node);
}

///
/// OptionalNode
///

void
OptionalNode::set_leaf_hash(CipherSuite suite, NodeIndex index)
{
  auto leaf = std::optional<KeyPackage>{};
  if (node) {
    leaf = var::get<KeyPackage>(opt::get(node).node);
  }

  tls::ostream w;
  w << index << leaf;
  hash = suite.get().digest.hash(w.bytes());
}

void
OptionalNode::set_parent_hash(CipherSuite suite,
                              NodeIndex index,
                              const bytes& left,
                              const bytes& right)
{
  auto parent = std::optional<ParentNode>{};
  if (node) {
    parent = var::get<ParentNode>(opt::get(node).node);
  }

  tls::ostream w;
  w << index << parent;
  tls::vector<1>::encode(w, left);
  tls::vector<1>::encode(w, right);
  hash = suite.get().digest.hash(w.bytes());
}

///
/// TreeKEMPrivateKey
///

TreeKEMPrivateKey
TreeKEMPrivateKey::solo(CipherSuite suite,
                        LeafIndex index,
                        const HPKEPrivateKey& leaf_priv)
{
  auto priv = TreeKEMPrivateKey{ suite, index, {}, {}, {} };
  priv.private_key_cache.insert({ NodeIndex(index), leaf_priv });
  return priv;
}

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
                          const HPKEPrivateKey& leaf_priv,
                          NodeIndex intersect,
                          const std::optional<bytes>& path_secret)
{
  auto priv = TreeKEMPrivateKey{ suite, index, {}, {}, {} };
  priv.private_key_cache.insert({ NodeIndex(index), leaf_priv });
  if (path_secret) {
    priv.implant(intersect, size, opt::get(path_secret));
  }
  return priv;
}

bytes
TreeKEMPrivateKey::path_step(const bytes& path_secret) const
{
  return suite.expand_with_label(path_secret, "path", {}, suite.secret_size());
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
    private_key_cache.erase(n);

    n = tree_math::parent(n, NodeCount(size));
    secret = path_step(secret);
  }

  path_secrets[r] = secret;
  private_key_cache.erase(n);
}

std::optional<HPKEPrivateKey>
TreeKEMPrivateKey::private_key(NodeIndex n) const
{
  auto pki = private_key_cache.find(n);
  if (pki != private_key_cache.end()) {
    return pki->second;
  }

  auto i = path_secrets.find(n);
  if (i == path_secrets.end()) {
    return std::nullopt;
  }

  return HPKEPrivateKey::derive(suite, i->second);
}

bool
TreeKEMPrivateKey::have_private_key(NodeIndex n) const
{
  auto path_secret = path_secrets.find(n) != path_secrets.end();
  auto cached_priv = private_key_cache.find(n) != private_key_cache.end();
  return path_secret || cached_priv;
}

std::optional<HPKEPrivateKey>
TreeKEMPrivateKey::private_key(NodeIndex n)
{
  auto priv = static_cast<const TreeKEMPrivateKey&>(*this).private_key(n);
  if (priv) {
    private_key_cache.insert({ n, opt::get(priv) });
  }
  return priv;
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
                         const UpdatePath& path)
{
  // Identify which node in the path secret we will be decrypting
  auto ni = NodeIndex(index);
  auto size = NodeCount(pub.size());
  auto dp = tree_math::dirpath(NodeIndex(from), size);
  if (dp.size() != path.nodes.size()) {
    throw ProtocolError("Malformed direct path");
  }

  size_t dpi = 0;
  auto last = NodeIndex(from);
  NodeIndex overlap_node;
  NodeIndex copath_node;
  for (dpi = 0; dpi < dp.size(); dpi++) {
    if (tree_math::in_path(ni, dp[dpi])) {
      overlap_node = dp[dpi];
      copath_node = tree_math::sibling(last, size);
      break;
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

  size_t resi = 0;
  NodeIndex res_overlap_node;
  for (resi = 0; resi < res.size(); resi++) {
    if (have_private_key(res[resi])) {
      break;
    }
  }

  if (resi == res.size()) {
    throw ProtocolError("No private key to decrypt path secret");
  }

  // Decrypt and implant
  auto priv = opt::get(private_key(res[resi]));
  auto path_secret =
    priv.decrypt(suite, context, path.nodes[dpi].node_secrets[resi]);
  implant(overlap_node, LeafCount(size), path_secret);
}

void
TreeKEMPrivateKey::truncate(LeafCount size)
{
  auto ni = NodeIndex(LeafIndex{ size.val - 1 });
  auto to_remove = std::vector<NodeIndex>{};
  for (const auto& entry : path_secrets) {
    if (entry.first.val > ni.val) {
      to_remove.push_back(entry.first);
    }
  }

  for (auto n : to_remove) {
    path_secrets.erase(n);
    private_key_cache.erase(n);
  }
}

bool
TreeKEMPrivateKey::consistent(const TreeKEMPrivateKey& other) const
{
  if (suite != other.suite) {
    return false;
  }

  if (update_secret != other.update_secret) {
    return false;
  }

  const auto match_if_present = [&](const auto& entry) {
    auto other_entry = other.path_secrets.find(entry.first);
    if (other_entry == other.path_secrets.end()) {
      return true;
    }

    return entry.second == other_entry->second;
  };
  return std::all_of(
    path_secrets.begin(), path_secrets.end(), match_if_present);
}

bool
TreeKEMPrivateKey::consistent(const TreeKEMPublicKey& other) const
{
  if (suite != other.suite) {
    return false;
  }

  const auto public_match = [&](const auto& entry) {
    auto n = entry.first;
    auto priv = opt::get(private_key(n));

    const auto& opt_node = other.node_at(n).node;
    if (!opt_node) {
      return false;
    }

    const auto& pub = opt::get(opt_node).public_key();
    return priv.public_key == pub;
  };
  return std::all_of(path_secrets.begin(), path_secrets.end(), public_match);
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
  while (index.val < size().val && node_at(NodeIndex(index)).node) {
    index.val++;
  }

  // Extend the tree if necessary
  auto ni = NodeIndex(index);
  if (index.val >= size().val) {
    nodes.resize(ni.val + 1);
  }

  // Set the leaf
  node_at(ni).node = Node{ kp };

  // Update the unmerged list
  for (auto& n : tree_math::dirpath(ni, NodeCount(size()))) {
    if (!node_at(n).node) {
      continue;
    }

    auto& parent = var::get<ParentNode>(opt::get(node_at(n).node).node);
    parent.unmerged_leaves.push_back(index);
  }

  clear_hash_path(index);
  return index;
}

void
TreeKEMPublicKey::update_leaf(LeafIndex index, const KeyPackage& kp)
{
  blank_path(index);
  node_at(NodeIndex(index)).node = Node{ kp };
  clear_hash_path(index);
}

void
TreeKEMPublicKey::blank_path(LeafIndex index)
{
  if (nodes.empty()) {
    return;
  }

  auto ni = NodeIndex(index);
  node_at(ni).node.reset();
  for (auto n : tree_math::dirpath(ni, NodeCount(size()))) {
    node_at(n).node.reset();
  }

  clear_hash_path(index);
}

void
TreeKEMPublicKey::merge(LeafIndex from, const UpdatePath& path)
{
  auto ni = NodeIndex(from);
  node_at(ni).node = Node{ path.leaf_key_package };

  auto dp = tree_math::dirpath(ni, NodeCount(size()));
  if (dp.size() != path.nodes.size()) {
    throw ProtocolError("Malformed direct path");
  }

  auto ph = path.parent_hashes(suite);
  for (size_t i = 0; i < dp.size(); i++) {
    auto n = dp[i];

    auto parent_hash = bytes{};
    if (i < dp.size() - 1) {
      parent_hash = ph[i + 1];
    }

    node_at(n).node = { ParentNode{
      path.nodes[i].public_key, {}, parent_hash } };
  }

  clear_hash_path(from);
  set_hash_all();
}

void
TreeKEMPublicKey::set_hash_all()
{
  auto r = tree_math::root(NodeCount(size()));
  get_hash(r);
}

bytes
TreeKEMPublicKey::root_hash() const
{
  auto r = tree_math::root(NodeCount(size()));
  auto hash = node_at(r).hash;
  if (hash.empty()) {
    throw InvalidParameterError("Root hash not set");
  }

  return hash;
}

LeafCount
TreeKEMPublicKey::size() const
{
  return LeafCount(NodeCount(nodes.size()));
}

bool
TreeKEMPublicKey::parent_hash_valid() const
{
  for (auto i = NodeIndex{ 1 }; i.val < nodes.size(); i.val += 2) {
    if (nodes[i.val].blank()) {
      continue;
    }

    auto self_hash = nodes[i.val].parent_node().hash(suite);

    auto l = tree_math::left(i);
    auto ln = nodes[l.val].node;
    auto l_match = (ln && opt::get(ln).parent_hash() == self_hash);

    auto r = tree_math::right(i, NodeCount(size()));
    auto rn = nodes[r.val].node;
    auto r_match = (rn && opt::get(rn).parent_hash() == self_hash);

    if (!l_match && !r_match) {
      return false;
    }
  }
  return true;
}

std::vector<NodeIndex>
TreeKEMPublicKey::resolve(NodeIndex index) const // NOLINT(misc-no-recursion)
{
  auto at_leaf = (tree_math::level(index) == 0);
  if (nodes[index.val].node) {
    const auto& node = opt::get(nodes[index.val].node);
    auto out = std::vector<NodeIndex>{ index };
    if (at_leaf) {
      return out;
    }

    const auto& parent = var::get<ParentNode>(node.node);
    const auto& unmerged = parent.unmerged_leaves;
    std::transform(unmerged.begin(),
                   unmerged.end(),
                   std::back_inserter(out),
                   [](LeafIndex x) -> NodeIndex { return NodeIndex(x); });

    return out;
  }

  if (at_leaf) {
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
    const auto& node = node_at(NodeIndex(i)).node;
    if (!node) {
      continue;
    }

    const auto& node_kp = var::get<KeyPackage>(opt::get(node).node);
    if (kp == node_kp) {
      return i;
    }
  }

  return std::nullopt;
}

std::optional<KeyPackage>
TreeKEMPublicKey::key_package(LeafIndex index) const
{
  const auto& node = node_at(NodeIndex(index)).node;
  if (!node) {
    return std::nullopt;
  }

  return var::get<KeyPackage>(opt::get(node).node);
}

std::tuple<TreeKEMPrivateKey, UpdatePath>
TreeKEMPublicKey::encap(LeafIndex from,
                        const bytes& context,
                        const bytes& leaf_secret,
                        const SignaturePrivateKey& sig_priv,
                        const std::optional<KeyPackageOpts>& opts)
{
  // Grab information about the sender
  auto& maybe_node = node_at(NodeIndex(from)).node;
  if (!maybe_node) {
    throw InvalidParameterError("Cannot encap from blank node");
  }

  auto path = UpdatePath{};
  path.leaf_key_package = var::get<KeyPackage>(opt::get(maybe_node).node);

  // Generate path secrets
  auto priv = TreeKEMPrivateKey::create(suite, size(), from, leaf_secret);

  // Package into a UpdatePath
  auto last = NodeIndex(from);
  for (auto n : tree_math::dirpath(NodeIndex(from), NodeCount(size()))) {
    auto path_secret = priv.path_secrets.at(n);
    auto node_priv = opt::get(priv.private_key(n));
    auto node = RatchetNode{ node_priv.public_key, {} };

    auto copath = tree_math::sibling(last, NodeCount(size()));
    auto res = resolve(copath);
    for (auto nr : res) {
      const auto& node_pub = opt::get(node_at(nr).node).public_key();
      auto ct = node_pub.encrypt(suite, context, path_secret);
      node.node_secrets.push_back(ct);
    }

    path.nodes.push_back(node);
    last = n;
  }

  // Sign the UpdatePath
  auto leaf_priv = opt::get(priv.private_key(NodeIndex(from)));
  path.sign(suite, leaf_priv.public_key, sig_priv, opts);

  // Update the pubic key itself
  merge(from, path);
  return std::make_tuple(priv, path);
}

void
TreeKEMPublicKey::truncate()
{
  while (!nodes.empty() && !nodes.back().node) {
    nodes.pop_back();
  }
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
  node_at(NodeIndex(index)).hash.resize(0);
  for (auto n : dp) {
    node_at(n).hash.resize(0);
  }
}

bytes
TreeKEMPublicKey::get_hash(NodeIndex index) // NOLINT(misc-no-recursion)
{
  if (!node_at(index).hash.empty()) {
    return node_at(index).hash;
  }

  if (tree_math::level(index) == 0) {
    node_at(index).set_leaf_hash(suite, index);
    return node_at(index).hash;
  }

  auto lh = get_hash(tree_math::left(index));
  auto rh = get_hash(tree_math::right(index, NodeCount(size())));
  node_at(index).set_parent_hash(suite, index, lh, rh);
  return node_at(index).hash;
}

} // namespace mls
