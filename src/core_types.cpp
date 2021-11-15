#include "mls/core_types.h"

#include <set>

namespace mls {

///
/// Extensions
///

const Extension::Type CapabilitiesExtension::type = ExtensionType::capabilities;
const Extension::Type RequiredCapabilitiesExtension::type =
  ExtensionType::required_capabilities;
const Extension::Type LifetimeExtension::type = ExtensionType::lifetime;
const Extension::Type KeyIDExtension::type = ExtensionType::key_id;
const Extension::Type ParentHashExtension::type = ExtensionType::parent_hash;

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

CapabilitiesExtension
CapabilitiesExtension::create_default()
{
  return {
    { all_supported_versions.begin(), all_supported_versions.end() },
    { all_supported_ciphersuites.begin(), all_supported_ciphersuites.end() },
    { RequiredCapabilitiesExtension::type },
    { /* No non-default proposals */ },
  };
}

bool
CapabilitiesExtension::extensions_supported(
  const std::vector<Extension::Type>& required) const
{
  return std::all_of(required.begin(), required.end(), [&](const auto& type) {
    return std::find(extensions.begin(), extensions.end(), type) !=
           extensions.end();
  });
}

bool
CapabilitiesExtension::proposals_supported(
  const std::vector<uint16_t>& required) const
{
  return std::all_of(required.begin(), required.end(), [&](const auto& type) {
    return std::find(proposals.begin(), proposals.end(), type) !=
           proposals.end();
  });
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
  extensions.add(CapabilitiesExtension::create_default());
  extensions.add(LifetimeExtension{ default_not_before, default_not_after });
  sign(sig_priv_in, opts_in);
}

KeyPackageID
KeyPackage::id() const
{
  return { cipher_suite.digest().hash(tls::marshal(*this)) };
}

void
KeyPackage::sign(const SignaturePrivateKey& sig_priv,
                 const std::optional<KeyPackageOpts>& opts)
{
  if (opts) {
    // Fill in application-provided extensions
    for (const auto& ext : opt::get(opts).extensions.extensions) {
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
  if (!maybe_lt) {
    return false;
  }

  auto& lt = opt::get(maybe_lt);
  return lt.not_before <= now && now <= lt.not_after;
}

bool
KeyPackage::verify_extension_support(const ExtensionList& ext_list) const
{
  const auto maybe_capas = extensions.find<CapabilitiesExtension>();
  if (!maybe_capas) {
    return false;
  }

  const auto& capas = opt::get(maybe_capas);

  // Verify that extensions in the list are supported
  auto ext_types = std::vector<Extension::Type>(ext_list.extensions.size());
  std::transform(ext_list.extensions.begin(),
                 ext_list.extensions.end(),
                 ext_types.begin(),
                 [](const auto& ext) { return ext.type; });

  if (!capas.extensions_supported(ext_types)) {
    return false;
  }

  // If there's a RequiredCapabilities extension, verify support
  const auto maybe_req_capas = ext_list.find<RequiredCapabilitiesExtension>();
  if (!maybe_req_capas) {
    return true;
  }

  const auto& req_capas = opt::get(maybe_req_capas);
  return capas.extensions_supported(req_capas.extensions) &&
         capas.proposals_supported(req_capas.proposals);
}

bool
KeyPackage::verify() const
{
  auto tbs = to_be_signed();
  auto identity_key = credential.public_key();

  if (CredentialType::x509 == credential.type()) {
    const auto& cred = credential.get<X509Credential>();
    if (cred._signature_scheme != tls_signature_scheme(cipher_suite.sig().id)) {
      throw std::runtime_error("Signature algorithm invalid");
    }
  }

  return identity_key.verify(cipher_suite, tbs, signature);
}

bytes
KeyPackage::to_be_signed() const
{
  tls::ostream out;
  out << version << cipher_suite << init_key;
  tls::vector<1>::encode(out, endpoint_id);
  out << credential << extensions;
  return out.bytes();
}

tls::ostream&
operator<<(tls::ostream& str, const KeyPackage& kp)
{
  str << kp.version << kp.cipher_suite << kp.init_key;
  tls::vector<1>::encode(str, kp.endpoint_id);
  str << kp.credential << kp.extensions;
  tls::vector<2>::encode(str, kp.signature);
  return str;
}

tls::istream&
operator>>(tls::istream& str, KeyPackage& kp)
{
  str >> kp.version >> kp.cipher_suite >> kp.init_key;
  tls::vector<1>::decode(str, kp.endpoint_id);
  str >> kp.credential >> kp.extensions;
  tls::vector<2>::decode(str, kp.signature);

  if (!kp.verify()) {
    throw InvalidParameterError("Invalid signature on key package");
  }
  return str;
}

bool
operator==(const KeyPackage& lhs, const KeyPackage& rhs)
{
  const auto version = (lhs.version == rhs.version);
  const auto cipher_suite = (lhs.cipher_suite == rhs.cipher_suite);
  const auto init_key = (lhs.init_key == rhs.init_key);
  const auto endpoint_id = (lhs.endpoint_id == rhs.endpoint_id);
  const auto credential = (lhs.credential == rhs.credential);
  const auto extensions = (lhs.extensions == rhs.extensions);
  const auto signature = (lhs.signature == rhs.signature);

  return version && cipher_suite && init_key && endpoint_id && credential && extensions &&
         signature;
}

} // namespace mls
