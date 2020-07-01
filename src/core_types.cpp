#include "core_types.h"

namespace mls {

const NodeType KeyPackage::type = NodeType::leaf;

KeyPackage::KeyPackage()
  : version(ProtocolVersion::mls10)
  , cipher_suite(CipherSuite::unknown)
{}

KeyPackage::KeyPackage(CipherSuite suite_in,
                       const HPKEPublicKey& init_key_in,
                       const SignaturePrivateKey& sig_priv_in,
                       const Credential& credential_in)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite_in)
  , init_key(init_key_in)
  , credential(credential_in)
{
  sign(sig_priv_in, std::nullopt);
}

bytes
KeyPackage::hash() const
{
  auto marshaled = tls::marshal(*this);
  return Digest(cipher_suite).write(marshaled).digest();
}

void
KeyPackage::sign(const SignaturePrivateKey& sig_priv,
                 std::optional<KeyPackageOpts> opts)
{
  // TODO(RLB): Apply opts
  auto tbs = to_be_signed();
  signature = sig_priv.sign(tbs);
}

bool
KeyPackage::verify() const
{
  auto tbs = to_be_signed();
  auto identity_key = credential.public_key();
  return identity_key.verify(tbs, signature);
}

bytes
KeyPackage::to_be_signed() const
{
  tls::ostream out;
  out << version << cipher_suite << init_key << credential;
  return out.bytes();
}

// DirectPath

void
DirectPath::sign(CipherSuite suite,
                 const HPKEPublicKey& init_pub,
                 const SignaturePrivateKey& sig_priv,
                 std::optional<KeyPackageOpts> opts)
{
  // TODO set parent hash extension
  leaf_key_package.init_key = init_pub;
  leaf_key_package.sign(sig_priv, opts);
}

} // namespace mls
