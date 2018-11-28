#pragma once

#include "common.h"
#include "crypto.h"
#include "tls_syntax.h"
#include <iosfwd>

namespace mls {

class RatchetNode
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
  CipherSuite _suite;
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
  tls::variant_vector<RatchetNode, CipherSuite, 3> nodes;
  tls::variant_vector<ECIESCiphertext, CipherSuite, 3> node_secrets;

  friend bool operator==(const RatchetPath& lhs, const RatchetPath& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetPath& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetPath& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetPath& obj);
};

class RatchetTree
{
public:
  RatchetTree(CipherSuite suite);
  RatchetTree(CipherSuite suite, const bytes& secret);
  RatchetTree(CipherSuite suite, const std::vector<bytes>& secrets);

  RatchetPath encrypt(uint32_t from, const bytes& leaf) const;
  bytes decrypt(uint32_t from, RatchetPath& path) const;
  void merge(uint32_t from, const RatchetPath& path);
  void set_leaf(uint32_t index, const bytes& leaf);

  uint32_t size() const;
  RatchetNode root() const;
  bytes root_secret() const;

private:
  tls::variant_vector<RatchetNode, CipherSuite, 3> _nodes;
  CipherSuite _suite;

  RatchetNode new_node(const bytes& data) const;
  uint32_t working_size(uint32_t from) const;

  friend bool operator==(const RatchetTree& lhs, const RatchetTree& rhs);
  friend std::ostream& operator<<(std::ostream& out, const RatchetTree& obj);
  friend tls::ostream& operator<<(tls::ostream& out, const RatchetTree& obj);
  friend tls::istream& operator>>(tls::istream& in, RatchetTree& obj);
};

} // namespace mls
