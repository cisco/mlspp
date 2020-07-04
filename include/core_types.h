#pragma once

#include "credential.h"
#include "crypto.h"
#include "tree_math.h"

namespace mls {

///
/// Extensions
///

enum class ProtocolVersion : uint8_t {
  mls10 = 0xFF,
};

enum struct ExtensionType : uint16_t {
  supported_versions = 1,
  supported_ciphersuites = 2,
  lifetime = 3,
  key_id = 4,
  parent_hash = 5,
};

struct Extension {
  ExtensionType type;
  bytes data;

  TLS_SERIALIZABLE(type, data);
  TLS_TRAITS(tls::pass, tls::vector<2>);
};

struct ExtensionList {
  std::vector<Extension> extensions;

  // XXX(RLB) It would be good if this maintained extensions in order.  It might
  // be possible to do this automatically by changing the storage to a
  // map<ExtensionType, bytes> and extending the TLS code to marshal that type.
  template<typename T>
  inline void add(const T& obj) {
    auto data = tls::marshal(obj);
    extensions.push_back({T::type, std::move(data)});
  }

  template<typename T>
  std::optional<T> get() {
    for (const auto& ext : extensions) {
      if (ext.type == T::type) {
        return tls::get<T>(ext.data);
      }
    }

    return std::nullopt;
  }

  TLS_SERIALIZABLE(extensions);
  TLS_TRAITS(tls::vector<2>);
};

struct SupportedVersionsExtension {
  std::vector<ProtocolVersion> versions;

  static const ExtensionType type;
  TLS_SERIALIZABLE(versions);
  TLS_TRAITS(tls::vector<1>);
};

struct SupportedCipherSuitesExtension {
  std::vector<CipherSuite> cipher_suites;

  static const ExtensionType type;
  TLS_SERIALIZABLE(cipher_suites);
  TLS_TRAITS(tls::vector<1>);
};

struct LifetimeExtension {
  uint64_t not_before;
  uint64_t not_after;

  static const ExtensionType type;
  TLS_SERIALIZABLE(not_before, not_after);
};

struct KeyIDExtension {
  bytes key_id;

  static const ExtensionType type;
  TLS_SERIALIZABLE(key_id);
  TLS_TRAITS(tls::vector<2>);
};

struct ParentHashExtension {
  bytes parent_hash;

  static const ExtensionType type;
  TLS_SERIALIZABLE(parent_hash);
  TLS_TRAITS(tls::vector<1>);
};

///
/// NodeType, ParentNode, and KeyPackage
///

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

///
/// DirectPath
///

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
