#include "mls/core_types.h"

namespace mls {
///
/// Extensions
///

const std::array<ProtocolVersion, 1> all_supported_versions = {
  ProtocolVersion::mls10
};

constexpr uint16_t SupportedVersionsExtension::type =
  ExtensionType::supported_versions;
constexpr uint16_t SupportedCipherSuitesExtension::type =
  ExtensionType::supported_ciphersuites;
constexpr uint16_t LifetimeExtension::type = ExtensionType::lifetime;
constexpr uint16_t KeyIDExtension::type = ExtensionType::key_id;
constexpr uint16_t ParentHashExtension::type = ExtensionType::parent_hash;

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
/// NodeType, ParentNode, and KeyPackage
///

KeyPackage::KeyPackage()
  : version(ProtocolVersion::mls10)
  , cipher_suite{ CipherSuite::ID::unknown }
{}

static const uint64_t default_not_before = 0x0000000000000000;
static const uint64_t default_not_after = 0xffffffffffffffff;

KeyPackage::KeyPackage(CipherSuite suite_in,
                       HPKEPublicKey init_key_in,
                       Credential credential_in,
                       const SignaturePrivateKey& sig_priv_in,
                       const std::optional<KeyPackageOpts>& opts_in)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite_in)
  , init_key(std::move(init_key_in))
  , credential(std::move(credential_in))
{
  extensions.add(SupportedVersionsExtension{
    { all_supported_versions.begin(), all_supported_versions.end() } });
  extensions.add(SupportedCipherSuitesExtension{
    { all_supported_suites.begin(), all_supported_suites.end() } });

  // TODO(RLB) Set non-eternal lifetimes
  extensions.add(LifetimeExtension{ default_not_before, default_not_after });

  sign(sig_priv_in, opts_in);
}

bytes
KeyPackage::hash() const
{
  return cipher_suite.get().digest.hash(tls::marshal(*this));
}

void
KeyPackage::sign(const SignaturePrivateKey& sig_priv,
                 const std::optional<KeyPackageOpts>& opts)
{
  if (opts.has_value()) {
    // Fill in application-provided extensions
    for (const auto& ext : opts.value().extensions.extensions) {
      extensions.add(ext.type, ext.data);
    }
  }

  auto tbs = to_be_signed();
  signature = sig_priv.sign(cipher_suite, tbs);
}

bool
KeyPackage::verify_expiry(uint64_t now) const
{
  auto maybe_lt = extensions.find<LifetimeExtension>();
  if (!maybe_lt.has_value()) {
    return false;
  }

  auto& lt = maybe_lt.value();
  return lt.not_before <= now && now <= lt.not_after;
}

bool
KeyPackage::verify_extension_support(const ExtensionList& ext_list) const
{
  return std::all_of(
    ext_list.extensions.begin(),
    ext_list.extensions.end(),
    [&](const Extension& ext) -> bool { return extensions.has(ext.type); });
}

bool
KeyPackage::verify() const
{
  auto tbs = to_be_signed();
  auto identity_key = credential.public_key();

  if (CredentialType::selector::x509 == credential.type()) {
    const auto& cred = credential.get<X509Credential>();
    if (cred._signature_scheme !=
        tls_signature_scheme(cipher_suite.get().sig.id)) {
      throw std::runtime_error("Signature algorithm invalid");
    }
  }

  return identity_key.verify(cipher_suite, tbs, signature);
}

bytes
KeyPackage::to_be_signed() const
{
  tls::ostream out;
  out << version << cipher_suite << init_key << credential;
  return out.bytes();
}

bool
operator==(const KeyPackage& lhs, const KeyPackage& rhs)
{
  auto tbs = lhs.to_be_signed() == rhs.to_be_signed();
  auto ver = lhs.verify() && rhs.verify();
  auto same = lhs.signature == rhs.signature;
  return tbs && (ver || same);
}

///
/// UpdatePath
///

void
UpdatePath::sign(CipherSuite suite,
                 const HPKEPublicKey& init_pub,
                 const SignaturePrivateKey& sig_priv,
                 const std::optional<KeyPackageOpts>& opts)
{
  // TODO(RLB) set parent hash extension
  silence_unused(suite);

  leaf_key_package.init_key = init_pub;
  leaf_key_package.sign(sig_priv, opts);
}

} // namespace mls
