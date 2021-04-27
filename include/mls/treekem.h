#pragma once

#include "mls/common.h"
#include "mls/core_types.h"
#include "mls/crypto.h"
#include "mls/tree_math.h"
#include <tls/tls_syntax.h>

namespace mls {

enum struct NodeType : uint8_t
{
  reserved = 0x00,
  leaf = 0x01,
  parent = 0x02,
};

struct Node
{
  var::variant<KeyPackage, ParentNode> node;

  const HPKEPublicKey& public_key() const;
  bytes parent_hash() const;

  TLS_SERIALIZABLE(node)
  TLS_TRAITS(tls::variant<NodeType>)
};

struct OptionalNode
{
  std::optional<Node> node;
  bytes hash;

  bool blank() const { return !node.has_value(); }

  KeyPackage& key_package()
  {
    return var::get<KeyPackage>(opt::get(node).node);
  }

  const KeyPackage& key_package() const
  {
    return var::get<KeyPackage>(opt::get(node).node);
  }

  ParentNode& parent_node()
  {
    return var::get<ParentNode>(opt::get(node).node);
  }

  const ParentNode& parent_node() const
  {
    return var::get<ParentNode>(opt::get(node).node);
  }

  // For leaf nodes
  void set_tree_hash(CipherSuite suite, NodeIndex index);

  // For parent nodes
  void set_tree_hash(CipherSuite suite,
                     NodeIndex index,
                     const bytes& left,
                     const bytes& right);

  TLS_SERIALIZABLE(node)
};

struct TreeKEMPublicKey;

struct TreeKEMPrivateKey
{
  CipherSuite suite;
  LeafIndex index;
  bytes update_secret;
  std::map<NodeIndex, bytes> path_secrets;
  std::map<NodeIndex, HPKEPrivateKey> private_key_cache;

  static TreeKEMPrivateKey solo(CipherSuite suite,
                                LeafIndex index,
                                const HPKEPrivateKey& leaf_priv);
  static TreeKEMPrivateKey create(CipherSuite suite,
                                  LeafCount size,
                                  LeafIndex index,
                                  const bytes& leaf_secret);
  static TreeKEMPrivateKey joiner(CipherSuite suite,
                                  LeafCount size,
                                  LeafIndex index,
                                  const HPKEPrivateKey& leaf_priv,
                                  NodeIndex intersect,
                                  const std::optional<bytes>& path_secret);

  void set_leaf_secret(const bytes& secret);
  std::tuple<NodeIndex, bytes, bool> shared_path_secret(LeafIndex to) const;

  bool have_private_key(NodeIndex n) const;
  std::optional<HPKEPrivateKey> private_key(NodeIndex n);
  std::optional<HPKEPrivateKey> private_key(NodeIndex n) const;

  void decap(LeafIndex from,
             const TreeKEMPublicKey& pub,
             const bytes& context,
             const UpdatePath& path,
             const std::vector<LeafIndex>& except);

  void truncate(LeafCount size);

  bool consistent(const TreeKEMPrivateKey& other) const;
  bool consistent(const TreeKEMPublicKey& other) const;

private:
  void implant(NodeIndex start, LeafCount size, const bytes& path_secret);
  bytes path_step(const bytes& path_secret) const;
};

struct TreeKEMPublicKey
{
  CipherSuite suite;
  std::vector<OptionalNode> nodes;

  explicit TreeKEMPublicKey(CipherSuite suite);

  TreeKEMPublicKey() = default;
  TreeKEMPublicKey(const TreeKEMPublicKey& other) = default;
  TreeKEMPublicKey(TreeKEMPublicKey&& other) = default;
  TreeKEMPublicKey& operator=(const TreeKEMPublicKey& other) = default;
  TreeKEMPublicKey& operator=(TreeKEMPublicKey&& other) = default;

  LeafIndex add_leaf(const KeyPackage& kp);
  void update_leaf(LeafIndex index, const KeyPackage& kp);
  void blank_path(LeafIndex index);

  void merge(LeafIndex from, const UpdatePath& path);
  void set_hash_all();
  bytes root_hash() const;
  LeafCount size() const;

  bool parent_hash_valid(LeafIndex from, const UpdatePath& path) const;
  bool parent_hash_valid() const;

  std::optional<LeafIndex> find(const KeyPackage& kp) const;
  std::optional<KeyPackage> key_package(LeafIndex index) const;
  std::vector<NodeIndex> resolve(NodeIndex index) const;

  std::tuple<TreeKEMPrivateKey, UpdatePath> encap(
    LeafIndex from,
    const bytes& context,
    const bytes& leaf_secret,
    const SignaturePrivateKey& sig_priv,
    const std::vector<LeafIndex>& except,
    const std::optional<KeyPackageOpts>& opts);

  void truncate();

  OptionalNode& node_at(NodeIndex n) { return nodes.at(n.val); }
  const OptionalNode& node_at(NodeIndex n) const { return nodes.at(n.val); }
  OptionalNode& node_at(LeafIndex n) { return nodes.at(NodeIndex(n).val); }
  const OptionalNode& node_at(LeafIndex n) const
  {
    return nodes.at(NodeIndex(n).val);
  }

  TLS_SERIALIZABLE(nodes)
  TLS_TRAITS(tls::vector<4>)

private:
  void clear_hash_all();
  void clear_hash_path(LeafIndex index);
  bytes get_hash(NodeIndex index);

  bytes parent_hash(const ParentNode& parent, NodeIndex copath_child) const;
  std::vector<bytes> parent_hashes(LeafIndex from,
                                   const UpdatePath& path) const;

  friend struct TreeKEMPrivateKey;
};

} // namespace mls

namespace tls {

TLS_VARIANT_MAP(mls::NodeType, mls::KeyPackage, leaf)
TLS_VARIANT_MAP(mls::NodeType, mls::ParentNode, parent)

} // namespace tls
