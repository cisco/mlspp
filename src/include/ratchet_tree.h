#pragma once

#include "common.h"
#include "crypto.h"
#include "tls_syntax.h"
#include <iosfwd>

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
  const optional<bytes>& secret() const;
  const optional<DHPrivateKey>& private_key() const;
  const DHPublicKey& public_key() const;

  void merge(const RatchetTreeNode& other);

private:
  optional<bytes> _secret;
  optional<DHPrivateKey> _priv;
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
struct OptionalRatchetTreeNode : public optional<RatchetTreeNode>
{
  typedef optional<RatchetTreeNode> parent;
  using parent::parent;

  OptionalRatchetTreeNode(CipherSuite suite)
    : parent(RatchetTreeNode(suite))
  {}

  OptionalRatchetTreeNode(CipherSuite suite, const bytes& secret)
    : parent(RatchetTreeNode(suite, secret))
  {}

  void merge(const RatchetTreeNode& other)
  {
    if (!*this) {
      *this = other;
    } else {
      (*this)->merge(other);
    }
  }
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

  DirectPath encrypt(uint32_t from, const bytes& leaf) const;
  MergeInfo decrypt(uint32_t from, const DirectPath& path) const;
  void merge_path(uint32_t from, const MergeInfo& info);

  void add_leaf(const DHPublicKey& pub);
  void add_leaf(const bytes& leaf_secret);
  void blank_path(uint32_t index);
  void set_path(uint32_t index, const bytes& leaf);

  uint32_t leaf_span() const;
  void truncate(uint32_t leaves);

  uint32_t size() const;
  bytes root_secret() const;
  bool check_invariant(size_t from) const;

private:
  tls::variant_vector<OptionalRatchetTreeNode, CipherSuite, 4> _nodes;

  RatchetTreeNode new_node(const bytes& data) const;

  friend bool operator==(const RatchetTree& lhs, const RatchetTree& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetTree& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetTree& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetTree& obj);
};

} // namespace mls
