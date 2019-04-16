#pragma once

#include "common.h"
#include "crypto.h"
#include "tls_syntax.h"
#include "tree_math.h"
#include <iosfwd>
#include <optional>

namespace mls {

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
  const std::optional<bytes>& secret() const;
  const std::optional<DHPrivateKey>& private_key() const;
  const DHPublicKey& public_key() const;

  void merge(const RatchetTreeNode& other);

private:
  std::optional<bytes> _secret;
  std::optional<DHPrivateKey> _priv;
  DHPublicKey _pub;

  friend RatchetTreeNode operator+(const RatchetTreeNode& lhs,
                                   const RatchetTreeNode& rhs);
  friend bool operator==(const RatchetTreeNode& lhs,
                         const RatchetTreeNode& rhs);
  friend bool operator!=(const RatchetTreeNode& lhs,
                         const RatchetTreeNode& rhs);
  friend std::ostream& operator<<(std::ostream& out,
                                  const RatchetTreeNode& node);
  friend tls::ostream& operator<<(tls::ostream& out,
                                  const RatchetTreeNode& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetTreeNode& obj);
};

// XXX(rlb@ipv.sx): We have to subclass optional<T> in order to
// ensure that nodes are populated with blank values on unmarshal.
// Otherwise, `*opt` will access uninitialized memory.
struct OptionalRatchetTreeNode
  : public tls::variant_optional<RatchetTreeNode, CipherSuite>
{
  typedef tls::variant_optional<RatchetTreeNode, CipherSuite> parent;
  using parent::parent;

  OptionalRatchetTreeNode(CipherSuite suite, const bytes& secret)
    : parent(RatchetTreeNode(suite, secret))
  {}

  void merge(const RatchetTreeNode& other)
  {
    if (!this->has_value()) {
      this->emplace(other);
    } else {
      this->value().merge(other);
    }
  }
};

struct RatchetTreeNodeVector
  : public tls::variant_vector<OptionalRatchetTreeNode, CipherSuite, 4>
{
  typedef tls::variant_vector<OptionalRatchetTreeNode, CipherSuite, 4> parent;
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
  RatchetTree(CipherSuite suite, const bytes& secret);
  RatchetTree(CipherSuite suite, const std::vector<bytes>& secrets);

  struct MergeInfo
  {
    std::vector<DHPublicKey> public_keys;
    std::vector<bytes> secrets;
  };

  DirectPath encrypt(LeafIndex from, const bytes& leaf) const;
  MergeInfo decrypt(LeafIndex from, const DirectPath& path) const;
  void merge_path(LeafIndex from, const MergeInfo& info);

  void add_leaf(LeafIndex index, const DHPublicKey& pub);
  void add_leaf(LeafIndex index, const bytes& leaf_secret);
  void blank_path(LeafIndex index);
  void set_path(LeafIndex index, const bytes& leaf);

  LeafCount leaf_span() const;
  void truncate(LeafCount leaves);

  uint32_t size() const;
  bool occupied(LeafIndex index) const;
  bytes root_secret() const;
  bool check_invariant(LeafIndex from) const;

private:
  RatchetTreeNodeVector _nodes;
  size_t _secret_size;

  NodeCount node_size() const;
  RatchetTreeNode new_node(const bytes& path_secret) const;
  bytes path_step(const bytes& path_secret) const;
  bytes node_step(const bytes& path_secret) const;

  friend bool operator==(const RatchetTree& lhs, const RatchetTree& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetTree& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetTree& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetTree& obj);
};

} // namespace mls
