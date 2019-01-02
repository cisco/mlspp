#pragma once

#include "common.h"
#include "crypto.h"
#include "tls_syntax.h"
#include <iosfwd>

namespace mls {

class RatchetNode : public CipherAware
{
public:
  RatchetNode(CipherSuite suite);
  RatchetNode(const RatchetNode& other);
  RatchetNode& operator=(const RatchetNode& other);

  RatchetNode(CipherSuite suite, const bytes& secret);
  RatchetNode(const DHPrivateKey& priv);
  RatchetNode(const DHPublicKey& pub);

  bool public_equal(const RatchetNode& other) const;
  const optional<bytes>& secret() const;
  const optional<DHPrivateKey>& private_key() const;
  const DHPublicKey& public_key() const;

  void merge(const RatchetNode& other);

private:
  optional<bytes> _secret;
  optional<DHPrivateKey> _priv;
  DHPublicKey _pub;

  friend RatchetNode operator+(const RatchetNode& lhs, const RatchetNode& rhs);
  friend bool operator==(const RatchetNode& lhs, const RatchetNode& rhs);
  friend bool operator!=(const RatchetNode& lhs, const RatchetNode& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetNode& node);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetNode& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetNode& obj);
};

struct OptionalRatchetNode : public optional<RatchetNode>
{
  typedef optional<RatchetNode> parent;
  using parent::parent;

  OptionalRatchetNode(CipherSuite suite)
    : parent(RatchetNode(suite))
  {}

  OptionalRatchetNode(CipherSuite suite, const bytes& secret)
    : parent(RatchetNode(suite, secret))
  {}
};

struct RatchetPath : public CipherAware
{
  tls::variant_vector<RatchetNode, CipherSuite, 3> nodes;
  tls::variant_vector<ECIESCiphertext, CipherSuite, 3> node_secrets;

  RatchetPath(CipherSuite suite)
    : CipherAware(suite)
    , nodes(suite)
    , node_secrets(suite)
  {}

  friend bool operator==(const RatchetPath& lhs, const RatchetPath& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetPath& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetPath& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetPath& obj);
};

class RatchetTree : public CipherAware
{
public:
  RatchetTree(CipherSuite suite);
  RatchetTree(CipherSuite suite, const bytes& secret);
  RatchetTree(CipherSuite suite, const std::vector<bytes>& secrets);

  RatchetPath encrypt(uint32_t from, const bytes& leaf) const;
  bytes decrypt(uint32_t from, RatchetPath& path) const;
  void merge(uint32_t from, const RatchetPath& path);

  // TODO: Rename to set_path
  void set_leaf(uint32_t index, const bytes& leaf);

  void add_leaf(const DHPublicKey& pub);
  void add_leaf(const bytes& leaf_secret);
  void blank_path(uint32_t index);

  uint32_t size() const;
  RatchetNode root() const;
  bytes root_secret() const;

private:
  tls::variant_vector<OptionalRatchetNode, CipherSuite, 4> _nodes;

  RatchetNode new_node(const bytes& data) const;
  uint32_t working_size(uint32_t from) const;
  std::vector<uint32_t> resolve(uint32_t target) const;
  std::vector<std::vector<uint32_t>> resolve_copath(uint32_t target,
                                                    uint32_t size) const;

  friend bool operator==(const RatchetTree& lhs, const RatchetTree& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetTree& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetTree& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetTree& obj);
};

} // namespace mls
