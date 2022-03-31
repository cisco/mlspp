#include "mls/core_types.h"
#include "mls/messages.h"

#include <set>

namespace mls {

///
/// Extensions
///

const Extension::Type RequiredCapabilitiesExtension::type =
  ExtensionType::required_capabilities;
const Extension::Type ExternalKeyIDExtension::type =
  ExtensionType::external_key_id;

const std::array<uint16_t, 2> default_extensions = {
  RequiredCapabilitiesExtension::type,
  ExternalKeyIDExtension::type,
};

const std::array<uint16_t, 8> default_proposals = {
  ProposalType::add,     ProposalType::update,
  ProposalType::remove,  ProposalType::psk,
  ProposalType::reinit,  ProposalType::external_init,
  ProposalType::app_ack, ProposalType::group_context_extensions,
};

const std::array<ProtocolVersion, 1> all_supported_versions = {
  ProtocolVersion::mls10
};

const std::array<CipherSuite::ID, 6> all_supported_ciphersuites = {
  CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519,
  CipherSuite::ID::P256_AES128GCM_SHA256_P256,
  CipherSuite::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519,
  CipherSuite::ID::X448_AES256GCM_SHA512_Ed448,
  CipherSuite::ID::P521_AES256GCM_SHA512_P521,
  CipherSuite::ID::X448_CHACHA20POLY1305_SHA512_Ed448,
};

Capabilities
Capabilities::create_default()
{
  return {
    { all_supported_versions.begin(), all_supported_versions.end() },
    { all_supported_ciphersuites.begin(), all_supported_ciphersuites.end() },
    { /* No non-default extensions */ },
    { /* No non-default proposals */ },
  };
}

bool
Capabilities::extensions_supported(
  const std::vector<Extension::Type>& required) const
{
  return std::all_of(
    required.begin(), required.end(), [&](Extension::Type type) {
      // Clang and MSVC disagree about the type returned by std::find.  Clang
      // thinks it's a pointer, so clang-tidy requires `const auto*`.  But MSVC
      // thinks it's a std::_Array_const_iterator<uint16_t,2>, which needs
      // `const auto`.
      // NOLINTNEXTLINE(llvm-qualified-auto, readability-qualified-auto)
      const auto default_pos =
        std::find(default_extensions.begin(), default_extensions.end(), type);
      if (default_pos != default_extensions.end()) {
        return true;
      }

      return std::find(extensions.begin(), extensions.end(), type) !=
             extensions.end();
    });
}

bool
Capabilities::proposals_supported(
  const std::vector<Proposal::Type>& required) const
{
  return std::all_of(
    required.begin(), required.end(), [&](Proposal::Type type) {
      // See above for NOLINT reasoning
      // NOLINTNEXTLINE(llvm-qualified-auto, readability-qualified-auto)
      const auto default_pos =
        std::find(default_proposals.begin(), default_proposals.end(), type);
      if (default_pos != default_proposals.end()) {
        return true;
      }

      return std::find(proposals.begin(), proposals.end(), type) !=
             proposals.end();
    });
}

Lifetime
Lifetime::create_default()
{
  return Lifetime{ 0x0000000000000000, 0xffffffffffffffff };
}

void
ExtensionList::add(uint16_t type, bytes data)
{
  auto curr = std::find_if(
    extensions.begin(), extensions.end(), [&](const Extension& ext) -> bool {
      return ext.type == type;
    });
  if (curr != extensions.end()) {
    curr->data = std::move(data);
    return;
  }

  extensions.push_back({ type, std::move(data) });
}

bool
ExtensionList::has(uint16_t type) const
{
  return std::any_of(
    extensions.begin(), extensions.end(), [&](const Extension& ext) -> bool {
      return ext.type == type;
    });
}

///
/// LeafNode
///
LeafNode::LeafNode(CipherSuite cipher_suite,
                   HPKEPublicKey public_key_in,
                   Credential credential_in,
                   Capabilities capabilities_in,
                   Lifetime lifetime_in,
                   ExtensionList extensions_in,
                   const SignaturePrivateKey& sig_priv)
  : public_key(std::move(public_key_in))
  , credential(std::move(credential_in))
  , capabilities(std::move(capabilities_in))
  , content(lifetime_in)
  , extensions(std::move(extensions_in))
{
  sign(cipher_suite, sig_priv, std::nullopt);
}

LeafNode
LeafNode::for_update(CipherSuite cipher_suite,
                     const bytes& group_id,
                     HPKEPublicKey public_key_in,
                     const LeafNodeOptions& opts,
                     const SignaturePrivateKey& sig_priv) const
{
  auto clone = clone_with_options(std::move(public_key_in), opts);

  clone.content = Empty{};
  clone.sign(cipher_suite, sig_priv, group_id);

  return clone;
}

LeafNode
LeafNode::for_commit(CipherSuite cipher_suite,
                     const bytes& group_id,
                     HPKEPublicKey public_key_in,
                     const bytes& parent_hash,
                     const LeafNodeOptions& opts,
                     const SignaturePrivateKey& sig_priv) const
{
  auto clone = clone_with_options(std::move(public_key_in), opts);

  clone.content = ParentHash{ parent_hash };
  clone.sign(cipher_suite, sig_priv, group_id);

  return clone;
}

LeafNodeSource
LeafNode::source() const
{
  return tls::variant<LeafNodeSource>::type(content);
}

LeafNodeRef
LeafNode::ref(CipherSuite cipher_suite) const
{
  return cipher_suite.ref(*this);
}

void
LeafNode::sign(CipherSuite cipher_suite,
               const SignaturePrivateKey& sig_priv,
               const std::optional<bytes>& group_id)
{
  const auto tbs = to_be_signed(group_id);
  signature = sig_priv.sign(cipher_suite, tbs);
}

bool
LeafNode::verify(CipherSuite cipher_suite,
                 const std::optional<bytes>& group_id) const
{
  const auto tbs = to_be_signed(group_id);
  const auto& identity_key = credential.public_key();

  if (CredentialType::x509 == credential.type()) {
    const auto& cred = credential.get<X509Credential>();
    if (cred.signature_scheme() !=
        tls_signature_scheme(cipher_suite.sig().id)) {
      throw std::runtime_error("Signature algorithm invalid");
    }
  }

  return identity_key.verify(cipher_suite, tbs, signature);
}

bool
LeafNode::verify_expiry(uint64_t now) const
{
  static const auto valid = overloaded{
    [now](const Lifetime& lt) {
      return lt.not_before <= now && now <= lt.not_after;
    },
    [](const auto& /* other */) { return false; },
  };
  return var::visit(valid, content);
}

bool
LeafNode::verify_extension_support(const ExtensionList& ext_list) const
{
  // Verify that extensions in the list are supported
  auto ext_types = std::vector<Extension::Type>(ext_list.extensions.size());
  std::transform(ext_list.extensions.begin(),
                 ext_list.extensions.end(),
                 ext_types.begin(),
                 [](const auto& ext) { return ext.type; });

  if (!capabilities.extensions_supported(ext_types)) {
    return false;
  }

  // If there's a RequiredCapabilities extension, verify support
  const auto maybe_req_capas = ext_list.find<RequiredCapabilitiesExtension>();
  if (!maybe_req_capas) {
    return true;
  }

  const auto& req_capas = opt::get(maybe_req_capas);
  return capabilities.extensions_supported(req_capas.extensions) &&
         capabilities.proposals_supported(req_capas.proposals);
}

LeafNode
LeafNode::clone_with_options(HPKEPublicKey public_key_in,
                             const LeafNodeOptions& opts) const
{
  auto clone = *this;

  clone.public_key = std::move(public_key_in);

  if (opts.credential) {
    clone.credential = opt::get(opts.credential);
  }

  if (opts.capabilities) {
    clone.capabilities = opt::get(opts.capabilities);
  }

  if (opts.extensions) {
    clone.extensions = opt::get(opts.extensions);
  }

  return clone;
}

// struct {
//     HPKEPublicKey public_key;
//     Credential credential;
//     Capabilities capabilities;
//
//     LeafNodeSource leaf_node_source;
//     select (leaf_node_source) {
//         case key_package:
//             Lifetime lifetime;
//
//         case update:
//             struct{};
//
//         case commit:
//             opaque parent_hash<V>;
//     }
//
//     Extension extensions<V>;
//
//     select (leaf_node_source) {
//         case key_package:
//             struct{};
//
//         case update:
//             opaque group_id<V>;
//
//         case commit:
//             opaque group_id<V>;
//     }
// } LeafNodeTBS;
struct LeafNodeTBS
{
  const HPKEPublicKey& public_key;
  const Credential& credential;
  const Capabilities& capabilities;
  const var::variant<Lifetime, Empty, ParentHash>& content;
  const ExtensionList& extensions;

  TLS_SERIALIZABLE(public_key, credential, capabilities, content, extensions)
  TLS_TRAITS(tls::pass,
             tls::pass,
             tls::pass,
             tls::variant<LeafNodeSource>,
             tls::pass)
};

bytes
LeafNode::to_be_signed(const std::optional<bytes>& group_id) const
{
  tls::ostream w;

  w << LeafNodeTBS{
    public_key, credential, capabilities, content, extensions,
  };

  switch (source()) {
    case LeafNodeSource::key_package:
      break;

    case LeafNodeSource::update:
    case LeafNodeSource::commit:
      w << opt::get(group_id);
  }

  return w.bytes();
}

///
/// NodeType, ParentNode, and KeyPackage
///

bytes
ParentNode::hash(CipherSuite suite) const
{
  return suite.digest().hash(tls::marshal(this));
}

KeyPackage::KeyPackage()
  : version(ProtocolVersion::mls10)
  , cipher_suite(CipherSuite::ID::unknown)
{}

KeyPackage::KeyPackage(CipherSuite suite_in,
                       HPKEPublicKey init_key_in,
                       LeafNode leaf_node_in,
                       ExtensionList extensions_in,
                       const SignaturePrivateKey& sig_priv_in)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite_in)
  , init_key(std::move(init_key_in))
  , leaf_node(std::move(leaf_node_in))
  , extensions(std::move(extensions_in))
{
  sign(sig_priv_in);
}

KeyPackageRef
KeyPackage::ref() const
{
  return cipher_suite.ref(*this);
}

void
KeyPackage::sign(const SignaturePrivateKey& sig_priv)
{
  auto tbs = to_be_signed();
  signature = sig_priv.sign(cipher_suite, tbs);
}

bool
KeyPackage::verify() const
{
  // Verify the inner leaf node
  if (!leaf_node.verify(cipher_suite, std::nullopt)) {
    return false;
  }

  // Check that the inner leaf node is intended for use in a KeyPackage
  if (leaf_node.source() != LeafNodeSource::key_package) {
    return false;
  }

  // Verify the KeyPackage
  const auto tbs = to_be_signed();
  const auto& identity_key = leaf_node.credential.public_key();

  if (CredentialType::x509 == leaf_node.credential.type()) {
    const auto& cred = leaf_node.credential.get<X509Credential>();
    if (cred.signature_scheme() !=
        tls_signature_scheme(cipher_suite.sig().id)) {
      throw std::runtime_error("Signature algorithm invalid");
    }
  }

  return identity_key.verify(cipher_suite, tbs, signature);
}

bytes
KeyPackage::to_be_signed() const
{
  tls::ostream out;
  out << version << cipher_suite << init_key << leaf_node << extensions;
  return out.bytes();
}

} // namespace mls
