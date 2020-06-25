#include "treekem.h"

namespace mls {

///
/// ParentNode
///

const NodeType ParentNode::type = NodeType::parent;

bool
operator==(const ParentNode& lhs, const ParentNode& rhs)
{
  return lhs.public_key == rhs.public_key &&
         lhs.unmerged_leaves == rhs.unmerged_leaves &&
         lhs.parent_hash == rhs.parent_hash;
}

///
/// Node
///

const HPKEPublicKey&
Node::public_key() const
{
  switch (inner_type()) {
    case NodeType::leaf:
      return std::get<KeyPackage>(*this).init_key;

    case NodeType::parent:
      return std::get<ParentNode>(*this).public_key;
  }
}

///
/// OptionalNode
///

struct LeafNodeHashInput
{
  LeafIndex leaf_index;
  tls::optional<KeyPackage> key_package;

  TLS_SERIALIZABLE(leaf_index, key_package);
};

void
OptionalNode::set_leaf_hash(CipherSuite suite, LeafIndex index)
{
  auto hash_input_str = LeafNodeHashInput{};
  hash_input_str.leaf_index = index;
  if (has_value()) {
    hash_input_str.key_package = std::get<KeyPackage>(value());
  }

  auto hash_input = tls::marshal(hash_input_str);
  hash = Digest(suite).write(hash_input).digest();
}

struct ParentNodeHashInput
{
  NodeIndex node_index;
  tls::optional<ParentNode> parent_node;
  tls::opaque<1> left_hash;
  tls::opaque<1> right_hash;

  TLS_SERIALIZABLE(node_index, parent_node, left_hash, right_hash);
};

void
OptionalNode::set_parent_hash(CipherSuite suite,
                              NodeIndex index,
                              const bytes& left,
                              const bytes& right)
{
  auto hash_input_str = ParentNodeHashInput{};
  hash_input_str.node_index = index;
  hash_input_str.left_hash = left;
  hash_input_str.right_hash = right;
  if (has_value()) {
    hash_input_str.parent_node = std::get<ParentNode>(value());
  }

  auto hash_input = tls::marshal(hash_input_str);
  hash = Digest(suite).write(hash_input).digest();
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

LeafCount
TreeKEMPublicKey::size() const
{
  return LeafCount(NodeCount(nodes.size()));
}

std::vector<NodeIndex>
TreeKEMPublicKey::resolve(NodeIndex index) const
{
  // TODO
  return {};
}

} // namespace mls
