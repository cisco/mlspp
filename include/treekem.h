#pragma once

#include "common.h"
#include "crypto.h"
#include "messages.h"
#include "tls_syntax.h"
#include "tree_math.h"

namespace mls {

struct KeyPackage;
struct KeyPackageOpts;
struct DirectPath;

enum class NodeType : uint8_t {
  leaf = 0x00,
  parent = 0x01,
};

struct ParentNode {
  HPKEPublicKey public_key;
  tls::vector<LeafIndex, 4> unmerged_leaves;
  tls::opaque<1> parent_hash;

  static const NodeType type;
  TLS_SERIALIZABLE(public_key, unmerged_leaves, parent_hash);
};

bool operator==(const ParentNode& lhs, const ParentNode& rhs);

struct Node : public tls::variant<NodeType, KeyPackage, ParentNode> {
  using parent = tls::variant<NodeType, KeyPackage, ParentNode>;
  using parent::parent;

  const HPKEPublicKey& public_key() const;
};

struct OptionalNode : public tls::optional<Node> {
  using parent = tls::optional<Node>;
  using parent::parent;

  bytes hash;

  void set_leaf_hash(CipherSuite suite, LeafIndex index);
  void set_parent_hash(CipherSuite suite, NodeIndex index, const bytes& left, const bytes& right);
};

struct TreeKEMPublicKey;

struct TreeKEMPrivateKey {
  CipherSuite suite;
  LeafIndex index;
  tls::opaque<1> update_secret;
  std::map<NodeIndex, tls::opaque<1>> path_secrets;
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

  void decap(LeafIndex from, const TreeKEMPublicKey& pub, const bytes& context, const DirectPath& path);


  private:
  void implant(NodeIndex start, LeafCount size, const bytes& path_secret);
  bytes path_step(const bytes& path_secret) const;
  std::optional<HPKEPrivateKey> private_key(NodeIndex n);
};

struct TreeKEMPublicKey {
  CipherSuite suite;
  tls::vector<OptionalNode, 4> nodes;

  TreeKEMPublicKey(CipherSuite suite);
  TreeKEMPublicKey(const TreeKEMPublicKey& other);
  // TODO other ctors

  LeafIndex add_leaf(const KeyPackage& kp);
  void update_leaf(LeafIndex index, const KeyPackage& kp);
  void blank_path(LeafIndex index);

  std::tuple<TreeKEMPrivateKey, DirectPath> encap(LeafIndex from,
                                                  const bytes& context,
                                                  const bytes& leaf_secret,
                                                  const SignaturePrivateKey& leafSigPriv,
                                                  std::optional<KeyPackageOpts> opts) const;
  void merge(LeafIndex from, const DirectPath& path);
  void set_hash_all();
  bytes root_hash() const;
  LeafCount size() const;
  std::vector<NodeIndex> resolve(NodeIndex index) const;

  std::optional<LeafIndex> find(const KeyPackage& kp) const;
  std::optional<KeyPackage> key_package(LeafIndex index) const;
};

bool operator==(const TreeKEMPublicKey& lhs, const TreeKEMPublicKey& rhs);

} // namespace mls
