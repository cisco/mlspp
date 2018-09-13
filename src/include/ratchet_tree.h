#pragma once

#include "common.h"
#include "crypto.h"
#include "tls_syntax.h"
#include <iosfwd>

namespace mls {

// TODO delete
class MerkleNode
{
public:
  // Defaults for the "rule of 6" are OK

  static MerkleNode leaf(const bytes& value);

  bool public_equal(const MerkleNode& other) const;
  const bytes& value() const;

private:
  bytes _value;

  friend MerkleNode operator+(const MerkleNode& lhs, const MerkleNode& rhs);
  friend bool operator==(const MerkleNode& lhs, const MerkleNode& rhs);
  friend bool operator!=(const MerkleNode& lhs, const MerkleNode& rhs);
  friend std::ostream& operator<<(std::ostream& out, const MerkleNode& node);
  friend tls::ostream& operator<<(tls::ostream& out, const MerkleNode& obj);
  friend tls::istream& operator>>(tls::istream& in, MerkleNode& obj);
};

class RatchetNode
{
public:
  RatchetNode() = default;
  RatchetNode(const RatchetNode& other);
  RatchetNode& operator=(const RatchetNode& other);

  RatchetNode(const bytes& secret);
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

struct RatchetPath
{
  tls::vector<RatchetNode, 3> nodes;
  tls::vector<ECIESCiphertext, 3> node_secrets;

  friend bool operator==(const RatchetPath& lhs, const RatchetPath& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetPath& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetPath& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetPath& obj);
};

class RatchetTree
{
public:
  RatchetTree();
  RatchetTree(const bytes& secret);
  RatchetTree(const std::vector<bytes>& secrets);

  RatchetPath encrypt(uint32_t from, const bytes& leaf) const;
  bytes decrypt(uint32_t from, RatchetPath& path) const;
  void merge(uint32_t from, const RatchetPath& path);
  void set_leaf(uint32_t index, const bytes& leaf);

  uint32_t size() const;
  RatchetNode root() const;
  bytes root_secret() const;

private:
  tls::vector<RatchetNode, 3> nodes;

  uint32_t working_size(uint32_t from) const;

  friend bool operator==(const RatchetTree& lhs, const RatchetTree& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetTree& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetTree& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetTree& obj);
};

} // namespace mls
