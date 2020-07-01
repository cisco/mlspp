#pragma once

#include "common.h"
#include "crypto.h"
#include "messages.h"
#include "tls_syntax.h"
#include "tree_math.h"

namespace mls {

struct KeyPackage;
struct DirectPath;

enum class NodeType : uint8_t {
  leaf = 0x00,
  parent = 0x01,
};

struct ParentNode {
  HPKEPublicKey public_key;
  std::vector<LeafIndex> unmerged_leaves;
  bytes parent_hash;

  static const NodeType type;
  TLS_SERIALIZABLE(public_key, unmerged_leaves, parent_hash);
  TLS_TRAITS(tls::pass, tls::vector<4>, tls::vector<1>);
};

struct Node {
  std::variant<KeyPackage, ParentNode> node;

  const HPKEPublicKey& public_key() const;

  TLS_SERIALIZABLE(node)
  TLS_TRAITS(tls::variant<NodeType>)
};

struct OptionalNode {
  std::optional<Node> node;
  bytes hash;

  void set_leaf_hash(CipherSuite suite, NodeIndex index);
  void set_parent_hash(CipherSuite suite, NodeIndex index, const bytes& left, const bytes& right);

  TLS_SERIALIZABLE(node);
};

struct TreeKEMPublicKey;

struct TreeKEMPrivateKey {
  CipherSuite suite;
  LeafIndex index;
  bytes update_secret;
  std::map<NodeIndex, bytes> path_secrets;
  std::map<NodeIndex, HPKEPrivateKey> private_key_cache;

  static TreeKEMPrivateKey create(CipherSuite suite,
                                  LeafCount size,
                                  LeafIndex index,
                                  const bytes& leaf_secret);
  static TreeKEMPrivateKey joiner(CipherSuite suite,
                                  LeafCount size,
                                  LeafIndex index,
                                  const bytes& leaf_secret,
                                  NodeIndex intersect,
                                  const bytes& path_secret);

  void set_leaf_secret(const bytes& secret);
  std::tuple<NodeIndex, bytes, bool> shared_path_secret(LeafIndex to) const;
  std::optional<HPKEPrivateKey> private_key(NodeIndex n);
  std::optional<HPKEPrivateKey> private_key(NodeIndex n) const;

  void decap(LeafIndex from, const TreeKEMPublicKey& pub, const bytes& context, const DirectPath& path);

  bool consistent(const TreeKEMPrivateKey& other) const;
  bool consistent(const TreeKEMPublicKey& other) const;

  private:
  void implant(NodeIndex start, LeafCount size, const bytes& path_secret);
  bytes path_step(const bytes& path_secret) const;

  friend std::ostream& operator<<(std::ostream& str, const TreeKEMPrivateKey& obj);
};

struct TreeKEMPublicKey {
  CipherSuite suite;
  std::vector<OptionalNode> nodes;

  explicit TreeKEMPublicKey(CipherSuite suite);

  LeafIndex add_leaf(const KeyPackage& kp);
  void update_leaf(LeafIndex index, const KeyPackage& kp);
  void blank_path(LeafIndex index);

  void merge(LeafIndex from, const DirectPath& path);
  void set_hash_all();
  bytes root_hash();
  LeafCount size() const;
  std::vector<NodeIndex> resolve(NodeIndex index) const;

  std::optional<LeafIndex> find(const KeyPackage& kp) const;
  std::optional<KeyPackage> key_package(LeafIndex index) const;

  std::tuple<TreeKEMPrivateKey, DirectPath> encap(LeafIndex from,
                                                  const bytes& context,
                                                  const bytes& leaf_secret,
                                                  const SignaturePrivateKey& sig_priv,
                                                  std::optional<KeyPackageOpts> opts);

  TLS_SERIALIZABLE(nodes);
  TLS_TRAITS(tls::vector<4>);

  private:
  void clear_hash_all();
  void clear_hash_path(LeafIndex index);
  bytes get_hash(NodeIndex index);
};

std::ostream& operator<<(std::ostream& str, const TreeKEMPublicKey& obj);

} // namespace mls
