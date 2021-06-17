#include <mls/treekem.h>

namespace mls {

// Utility method used for removing leaves from a resolution
static void
remove_leaves(std::vector<NodeIndex>& res, const std::vector<LeafIndex>& except)
{
  for (const auto& leaf : except) {
    auto it = std::find(res.begin(), res.end(), NodeIndex(leaf));
    if (it == res.end()) {
      continue;
    }

    res.erase(it);
  }
}

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
OptionalNode::set_tree_hash(CipherSuite suite, NodeIndex index)
{
  auto leaf = std::optional<KeyPackage>{};
  if (node) {
    leaf = var::get<KeyPackage>(opt::get(node).node);
  }

  tls::ostream w;
  w << index << leaf;
  hash = suite.digest().hash(w.bytes());
}

void
OptionalNode::set_tree_hash(CipherSuite suite,
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
  hash = suite.digest().hash(w.bytes());
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

void
TreeKEMPrivateKey::implant(NodeIndex start,
                           LeafCount size,
                           const bytes& path_secret)
{
  auto n = start;
  auto r = tree_math::root(size);
  auto secret = path_secret;

  while (n != r) {
    path_secrets[n] = secret;
    private_key_cache.erase(n);

    n = tree_math::parent(n, size);
    secret = suite.derive_secret(secret, "path");
  }

  path_secrets[r] = secret;
  private_key_cache.erase(n);
  update_secret = secret;
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

  auto node_secret = suite.derive_secret(i->second, "node");
  return HPKEPrivateKey::derive(suite, node_secret);
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
                         const UpdatePath& path,
                         const std::vector<LeafIndex>& except)
{
  // Identify which node in the path secret we will be decrypting
  auto ni = NodeIndex(index);
  auto size = pub.size();
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
  remove_leaves(res, except);
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
  for (auto& n : tree_math::dirpath(ni, size())) {
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
  for (auto n : tree_math::dirpath(ni, size())) {
    node_at(n).node.reset();
  }

  clear_hash_path(index);
}

void
TreeKEMPublicKey::merge(LeafIndex from, const UpdatePath& path)
{
  auto ni = NodeIndex(from);
  node_at(ni).node = Node{ path.leaf_key_package };

  auto dp = tree_math::dirpath(ni, size());
  if (dp.size() != path.nodes.size()) {
    throw ProtocolError("Malformed direct path");
  }

  auto ph = parent_hashes(from, path);
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
  auto r = tree_math::root(size());
  get_hash(r);
}

bytes
TreeKEMPublicKey::root_hash() const
{
  auto r = tree_math::root(size());
  auto hash = node_at(r).hash;
  if (hash.empty()) {
    throw InvalidParameterError("Root hash not set");
  }

  return hash;
}

LeafCount
TreeKEMPublicKey::size() const
{
  return LeafCount(NodeCount(static_cast<uint32_t>(nodes.size())));
}

bool
TreeKEMPublicKey::parent_hash_valid() const
{
  for (auto i = NodeIndex{ 1 }; i.val < nodes.size(); i.val += 2) {
    if (nodes[i.val].blank()) {
      continue;
    }

    const auto& parent = nodes[i.val].parent_node();
    auto l = tree_math::left(i);
    auto r = tree_math::right(i, size());

    auto lh = parent_hash(parent, r);
    auto rh = parent_hash(parent, l);

    // If left child matches, good to go
    auto ln = node_at(l).node;
    if (ln && opt::get(ln).parent_hash() == lh) {
      continue;
    }

    // Otherwise, the right child must be present and match
    while (node_at(r).blank() && tree_math::level(r) > 0) {
      r = tree_math::left(r);
    }

    auto rn = node_at(r).node;
    if (!rn || opt::get(rn).parent_hash() != rh) {
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
  auto r = resolve(tree_math::right(index, size()));
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
                        const std::vector<LeafIndex>& except,
                        const std::optional<KeyPackageOpts>& maybe_opts)
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
  for (auto n : tree_math::dirpath(NodeIndex(from), size())) {
    auto path_secret = priv.path_secrets.at(n);
    auto node_priv = opt::get(priv.private_key(n));
    auto node = RatchetNode{ node_priv.public_key, {} };

    auto copath = tree_math::sibling(last, size());
    auto res = resolve(copath);
    remove_leaves(res, except);
    for (auto nr : res) {
      const auto& node_pub = opt::get(node_at(nr).node).public_key();
      auto ct = node_pub.encrypt(suite, context, path_secret);
      node.node_secrets.push_back(ct);
    }

    path.nodes.push_back(node);
    last = n;
  }

  // Sign the UpdatePath
  auto opts = KeyPackageOpts{};
  if (maybe_opts) {
    opts = opt::get(maybe_opts);
  }

  auto ph = parent_hashes(from, path);
  if (!ph.empty()) {
    opts.extensions.add(ParentHashExtension{ ph[0] });
  }

  auto leaf_node = opt::get(priv.private_key(NodeIndex(from)));
  path.leaf_key_package.init_key = leaf_node.public_key;
  path.leaf_key_package.sign(sig_priv, opts);

  // Update the pubic key itself
  merge(from, path);
  return std::make_tuple(priv, path);
}

void
TreeKEMPublicKey::truncate()
{
  auto leaf = false;
  // Find the first rightmost non blank leaf node index
  auto it = std::find_if(nodes.rbegin(), nodes.rend(), [&](const auto& node) {
    leaf = !leaf;
    return (leaf && !node.blank());
  });

  if (it == nodes.rbegin()) {
    return;
  }

  nodes.erase(it.base(), nodes.end());
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
  auto dp = tree_math::dirpath(NodeIndex(index), size());
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
    node_at(index).set_tree_hash(suite, index);
    return node_at(index).hash;
  }

  auto lh = get_hash(tree_math::left(index));
  auto rh = get_hash(tree_math::right(index, size()));
  node_at(index).set_tree_hash(suite, index, lh, rh);
  return node_at(index).hash;
}

// struct {
//     HPKEPublicKey public_key;
//     opaque parent_hash<0..255>;
//     HPKEPublicKey original_child_resolution<0..2^32-1>;
// } ParentHashInput;
struct ParentHashInput
{
  const HPKEPublicKey& public_key;
  const bytes& parent_hash;
  std::vector<HPKEPublicKey> original_child_resolution;

  TLS_SERIALIZABLE(public_key, parent_hash, original_child_resolution)
  TLS_TRAITS(tls::pass, tls::vector<1>, tls::vector<4>)
};

bytes
TreeKEMPublicKey::parent_hash(const ParentNode& parent,
                              NodeIndex copath_child) const
{
  auto res = resolve(copath_child);
  remove_leaves(res, parent.unmerged_leaves);

  auto hash_input = ParentHashInput{
    parent.public_key,
    parent.parent_hash,
    std::vector<HPKEPublicKey>(res.size()),
  };
  for (size_t i = 0; i < res.size(); i++) {
    const auto& node = opt::get(node_at(res[i]).node);
    hash_input.original_child_resolution[i] = node.public_key();
  }

  return suite.digest().hash(tls::marshal(hash_input));
}

std::vector<bytes>
TreeKEMPublicKey::parent_hashes(LeafIndex from, const UpdatePath& path) const
{
  // The list of nodes for whom parent hashes are computed, namely: Direct path
  // excluding root, including leaf
  auto from_node = NodeIndex(from);
  auto dp = tree_math::dirpath(from_node, size());
  if (!dp.empty()) {
    // pop_back() on an empty list is undefined behavior
    dp.pop_back();
  }

  if (from_node != tree_math::root(size())) {
    // Handle the special case of a one-leaf tree
    dp.insert(dp.begin(), from_node);
  }

  if (dp.size() != path.nodes.size()) {
    throw ProtocolError("Malformed UpdatePath");
  }

  // Parent hash for all the parents, starting from the root
  auto last_hash = bytes{};
  auto ph = std::vector<bytes>(dp.size());
  for (int i = static_cast<int>(dp.size()) - 1; i >= 0; i--) {
    auto n = dp[i];
    auto s = tree_math::sibling(n, size());

    auto parent_node = ParentNode{ path.nodes[i].public_key, {}, last_hash };
    last_hash = parent_hash(parent_node, s);
    ph[i] = last_hash;
  }

  return ph;
}

bool
TreeKEMPublicKey::parent_hash_valid(LeafIndex from,
                                    const UpdatePath& path) const
{
  auto ph = parent_hashes(from, path);
  auto phe = path.leaf_key_package.extensions.find<ParentHashExtension>();

  // If there are no nodes to hash, then ParentHash MUST be omitted
  if (ph.empty()) {
    return !phe;
  }

  return phe && opt::get(phe).parent_hash == ph[0];
}

} // namespace mls
