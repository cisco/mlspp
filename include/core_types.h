#pragma once

#include "credential.h"
#include "crypto.h"
#include "tree_math.h"

namespace mls {

enum class NodeType : uint8_t {
  leaf = 0x00,
  parent = 0x01,
};

struct ParentNode {
  HPKEPublicKey public_key;
  std::vector<LeafIndex> unmerged_leaves;
  bytes parent_hash;

  static const NodeType type;
  TLS_SERIALIZABLE(public_key, unmerged_leaves, parent_hash)
  TLS_TRAITS(tls::pass, tls::vector<4>, tls::vector<1>)
};

enum class ProtocolVersion : uint8_t
{
  mls10 = 0xFF,
};

// struct {
//     ProtocolVersion version;
//     CipherSuite cipher_suite;
//     HPKEPublicKey init_key;
//     Credential credential;
//     Extension extensions<0..2^16-1>;
//     opaque signature<0..2^16-1>;
// } KeyPackage;
struct KeyPackageOpts {
  // TODO: Things to change in a KeyPackage
};

struct KeyPackage
{
  ProtocolVersion version;
  CipherSuite cipher_suite;
  HPKEPublicKey init_key;
  Credential credential;
  // TODO Extensions
  bytes signature;

  KeyPackage();
  KeyPackage(CipherSuite suite_in,
             HPKEPublicKey init_key_in,
             Credential credential_in,
             const SignaturePrivateKey& sig_priv_in);

  bytes hash() const;

  void sign(const SignaturePrivateKey& sig_priv,
            const std::optional<KeyPackageOpts>& opts);
  bool verify() const;

  static const NodeType type;
  TLS_SERIALIZABLE(version, cipher_suite, init_key, credential, signature)
  TLS_TRAITS(tls::pass, tls::pass, tls::pass, tls::pass, tls::vector<2>)

  private:
  bytes to_be_signed() const;

  friend bool operator==(const KeyPackage& lhs, const KeyPackage& rhs);
};

bool operator==(const KeyPackage& lhs, const KeyPackage& rhs);

// struct {
//    HPKEPublicKey public_key;
//    HPKECiphertext node_secrets<0..2^16-1>;
// } RatchetNode
struct RatchetNode
{
  HPKEPublicKey public_key;
  std::vector<HPKECiphertext> node_secrets;

  TLS_SERIALIZABLE(public_key, node_secrets)
  TLS_TRAITS(tls::pass, tls::vector<2>)
};

enum class NodeType : uint8_t;

// struct {
//    RatchetNode nodes<0..2^16-1>;
// } DirectPath;
struct DirectPath
{
  KeyPackage leaf_key_package;
  std::vector<RatchetNode> nodes;

  void sign(CipherSuite suite,
            const HPKEPublicKey& init_pub,
            const SignaturePrivateKey& sig_priv,
            const std::optional<KeyPackageOpts>& opts);

  TLS_SERIALIZABLE(leaf_key_package, nodes)
  TLS_TRAITS(tls::pass, tls::vector<2>)
};


} // namespace mls
