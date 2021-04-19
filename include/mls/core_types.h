#pragma once

#include "mls/credential.h"
#include "mls/crypto.h"
#include "mls/tree_math.h"

namespace mls {

///
/// Extensions
///

// enum {
//   reserved(0),
//   mls10(1),
//   (255)
// } ProtocolVersion;
enum class ProtocolVersion : uint8_t
{
  mls10 = 0x01,
};

extern const std::array<ProtocolVersion, 1> all_supported_versions;

struct Extension
{
  using Type = uint16_t;

  Type type;
  bytes data;

  TLS_SERIALIZABLE(type, data)
  TLS_TRAITS(tls::pass, tls::vector<2>)
};

struct ExtensionType
{
  static constexpr Extension::Type capabilities = 1;
  static constexpr Extension::Type lifetime = 2;
  static constexpr Extension::Type key_id = 3;
  static constexpr Extension::Type parent_hash = 4;
  static constexpr Extension::Type ratchet_tree = 5;

  // XXX(RLB) There is no IANA-registered type for this extension yet, so we use
  // a value from the vendor-specific space
  static constexpr Extension::Type sframe_parameters = 0xff02;
};

struct ExtensionList
{
  std::vector<Extension> extensions;

  // XXX(RLB) It would be good if this maintained extensions in order.  It might
  // be possible to do this automatically by changing the storage to a
  // map<ExtensionType, bytes> and extending the TLS code to marshal that type.
  template<typename T>
  inline void add(const T& obj)
  {
    auto data = tls::marshal(obj);
    add(static_cast<uint16_t>(T::type), std::move(data));
  }

  void add(uint16_t type, bytes data);

  template<typename T>
  std::optional<T> find() const
  {
    for (const auto& ext : extensions) {
      if (ext.type == T::type) {
        return tls::get<T>(ext.data);
      }
    }

    return std::nullopt;
  }

  bool has(uint16_t type) const;
  ExtensionList for_group() const;

  TLS_SERIALIZABLE(extensions)
  TLS_TRAITS(tls::vector<4>)
};

struct CapabilitiesExtension
{
  std::vector<ProtocolVersion> versions;
  std::vector<CipherSuite::ID> cipher_suites;
  std::vector<uint16_t> extensions;

  static const uint16_t type;
  TLS_SERIALIZABLE(versions, cipher_suites, extensions)
  TLS_TRAITS(tls::vector<1>, tls::vector<1>, tls::vector<1>)
};

struct LifetimeExtension
{
  uint64_t not_before;
  uint64_t not_after;

  static const uint16_t type;
  TLS_SERIALIZABLE(not_before, not_after)
};

struct KeyIDExtension
{
  bytes key_id;

  static const uint16_t type;
  TLS_SERIALIZABLE(key_id)
  TLS_TRAITS(tls::vector<2>)
};

struct ParentHashExtension
{
  bytes parent_hash;

  static const uint16_t type;
  TLS_SERIALIZABLE(parent_hash)
  TLS_TRAITS(tls::vector<1>)
};

///
/// NodeType, ParentNode, and KeyPackage
///

struct ParentNode
{
  HPKEPublicKey public_key;
  std::vector<LeafIndex> unmerged_leaves;
  bytes parent_hash;

  bytes hash(CipherSuite suite) const;

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
struct KeyPackageOpts
{
  // TODO: Things to change in a KeyPackage
  ExtensionList extensions;
};

struct KeyPackage
{
  ProtocolVersion version;
  CipherSuite cipher_suite;
  HPKEPublicKey init_key;
  Credential credential;
  ExtensionList extensions;
  bytes signature;

  KeyPackage();
  KeyPackage(CipherSuite suite_in,
             HPKEPublicKey init_key_in,
             Credential credential_in,
             const SignaturePrivateKey& sig_priv_in,
             const std::optional<KeyPackageOpts>& opts_in);

  bytes hash() const;

  void sign(const SignaturePrivateKey& sig_priv,
            const std::optional<KeyPackageOpts>& opts);

  bool verify_expiry(uint64_t now) const;
  bool verify_extension_support(const ExtensionList& ext_list) const;
  bool verify() const;

  TLS_SERIALIZABLE(version,
                   cipher_suite,
                   init_key,
                   credential,
                   extensions,
                   signature)
  TLS_TRAITS(tls::pass,
             tls::pass,
             tls::pass,
             tls::pass,
             tls::pass,
             tls::vector<2>)

private:
  bytes to_be_signed() const;

  friend bool operator==(const KeyPackage& lhs, const KeyPackage& rhs);
};

bool
operator==(const KeyPackage& lhs, const KeyPackage& rhs);

///
/// UpdatePath
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
// } UpdatePath;
struct UpdatePath
{
  KeyPackage leaf_key_package;
  std::vector<RatchetNode> nodes;

  TLS_SERIALIZABLE(leaf_key_package, nodes)
  TLS_TRAITS(tls::pass, tls::vector<2>)
};

} // namespace mls
