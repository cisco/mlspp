#pragma once

#include "common.h"
#include "credential.h"
#include "crypto.h"
#include "tls_syntax.h"
#include "tree_math.h"
#include <optional>
#include <iostream>

namespace mls {

struct ClientInitKey;

class RatchetTreeNode : public CipherAware
{
public:
  RatchetTreeNode(CipherSuite suite);
  RatchetTreeNode(const RatchetTreeNode& other) = default;
  RatchetTreeNode& operator=(const RatchetTreeNode& other);

  RatchetTreeNode(CipherSuite suite, const bytes& secret);
  RatchetTreeNode(const DHPrivateKey& priv);
  RatchetTreeNode(const DHPublicKey& pub);

  bool public_equal(const RatchetTreeNode& other) const;
  const std::optional<DHPrivateKey>& private_key() const;
  const DHPublicKey& public_key() const;
  const std::optional<Credential>& credential() const;

  void merge(const RatchetTreeNode& other);
  void set_credential(const Credential& cred);

  TLS_SERIALIZABLE(_pub, _cred);

private:
  std::optional<DHPrivateKey> _priv;
  DHPublicKey _pub;

  // A credential is populated iff this is a leaf node
  tls::optional<Credential> _cred;
};

// XXX(rlb@ipv.sx): We have to subclass optional<T> in order to
// ensure that nodes are populated with blank values on unmarshal.
// Otherwise, `*opt` will access uninitialized memory.
struct OptionalRatchetTreeNode
  : public tls::variant_optional<RatchetTreeNode, CipherSuite>
{
  using parent = tls::variant_optional<RatchetTreeNode, CipherSuite>;
  using parent::parent;

  OptionalRatchetTreeNode(CipherSuite suite, const bytes& secret);

  bool has_private() const;
  const bytes& hash() const;

  void merge(const RatchetTreeNode& other);
  void set_leaf_hash(CipherSuite suite);
  void set_hash(CipherSuite suite,
                const OptionalRatchetTreeNode& left,
                const OptionalRatchetTreeNode& right);

private:
  bytes _hash;
};

struct RatchetTreeNodeVector
  : public tls::variant_vector<OptionalRatchetTreeNode, CipherSuite, 4>
{
  using parent = tls::variant_vector<OptionalRatchetTreeNode, CipherSuite, 4>;
  using parent::parent;
  using parent::operator[];

  OptionalRatchetTreeNode& operator[](const NodeIndex index);
  const OptionalRatchetTreeNode& operator[](const NodeIndex index) const;
};

struct RatchetNode;
struct DirectPath;

class RatchetTree : public CipherAware
{
public:
  RatchetTree(CipherSuite suite);
  RatchetTree(CipherSuite suite, const bytes& secret, const Credential& cred); // XXX dele?
  RatchetTree(const DHPrivateKey& priv, const Credential& cred);
  RatchetTree(CipherSuite suite,
              const std::vector<bytes>& secrets,
              const std::vector<Credential>& creds);

  struct MergePath
  {
    bytes root_path_secret;
    std::vector<RatchetTreeNode> nodes;
  };

  std::tuple<DirectPath, bytes> encrypt(LeafIndex from, const bytes& leaf);
  MergePath decrypt(LeafIndex from, const DirectPath& path) const;
  void merge_path(LeafIndex from, const MergePath& path);

  void add_leaf(LeafIndex index,
                const DHPublicKey& pub,
                const Credential& cred);
  void add_leaf(LeafIndex index,
                const DHPrivateKey& priv,
                const Credential& cred);
  void add_leaf(LeafIndex index,
                const bytes& leaf_secret,
                const Credential& cred);
  void blank_path(LeafIndex index);
  void blank_path_above(LeafIndex index);
  bytes set_path(LeafIndex index, const bytes& leaf);

  LeafIndex leftmost_free() const;
  void set_leaf(LeafIndex index, const DHPublicKey& leaf_key, const Credential& credential);
  void set_leaf_key(LeafIndex index, const DHPublicKey& leaf_key);
  void set_leaf_secret(LeafIndex index, const bytes& leaf_secret);

  std::optional<LeafIndex> find(const ClientInitKey& cik) const;
  const Credential& get_credential(LeafIndex index) const;

  LeafCount leaf_span() const;
  void truncate(LeafCount leaves);

  uint32_t size() const;
  bool occupied(LeafIndex index) const;
  bytes root_hash() const;
  bool check_credentials() const;
  bool check_invariant(LeafIndex from) const;

  TLS_SERIALIZABLE(_nodes)

protected:
  RatchetTreeNodeVector _nodes;
  size_t _secret_size;

  NodeIndex root_index() const;
  NodeCount node_size() const;
  RatchetTreeNode new_node(const bytes& path_secret) const;
  bytes path_step(const bytes& path_secret) const;
  bytes node_step(const bytes& path_secret) const;

  void add_leaf_inner(LeafIndex index, const RatchetTreeNode& node_val);
  void set_hash(NodeIndex index);
  void set_hash_path(LeafIndex index);
  void set_hash_all(NodeIndex index);

  // XXX(rlb): These are still necessary because operator>> triggers the
  // computation of the tree hash
  friend bool operator==(const RatchetTree& lhs, const RatchetTree& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetTree obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetTree& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetTree& obj);
};

} // namespace mls
