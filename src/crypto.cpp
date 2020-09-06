#include "mls/crypto.h"

#include <iostream>
#include <string>

namespace mls {

///
/// Test mode controls
///

int DeterministicHPKE::_refct = 0;

///
/// Pass-through / metrics wrappers
///

Digest::Digest(CipherSuite suite)
  : primitive::Digest(suite)
{}

bytes
hmac(CipherSuite suite, const bytes& key, const bytes& data)
{
  return primitive::hmac(suite, key, data);
}

///
/// HKDF and DeriveSecret
///

bool
constant_time_eq(const bytes& lhs, const bytes& rhs)
{
  size_t size = lhs.size();
  if (rhs.size() > size) {
    size = rhs.size();
  }

  unsigned char diff = 0;
  for (size_t i = 0; i < size; ++i) {
    // Not sure why the linter thinks `diff` is signed
    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    diff |= (lhs[i] ^ rhs[i]);
  }
  return (diff == 0);
}

bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm)
{
  return hmac(suite, salt, ikm);
}

bytes
zero_bytes(size_t size)
{
  bytes out(size);
  for (auto& b : out) {
    b = 0;
  }
  return out;
}

// For simplicity, we enforce that size <= Hash.length, so that
// HKDF-Expand(Secret, Label) reduces to:
//
//   HMAC(Secret, Label || 0x01)
static bytes
hkdf_expand(CipherSuite suite,
            const bytes& secret,
            const bytes& info,
            size_t size)
{
  // Ensure that we need only one hash invocation
  if (size > Digest(suite).output_size()) {
    throw InvalidParameterError("Size too big for hkdf_expand");
  }

  auto label = info;
  label.push_back(0x01);
  auto mac = hmac(suite, secret, label);
  mac.resize(size);
  return mac;
}

struct HKDFLabel
{
  uint16_t length;
  bytes label;
  bytes context;

  TLS_SERIALIZABLE(length, label, context)
  TLS_TRAITS(tls::pass, tls::vector<1>, tls::vector<4>)
};

bytes
hkdf_expand_label(CipherSuite suite,
                  const bytes& secret,
                  const std::string& label,
                  const bytes& context,
                  const size_t length)
{
  auto mls_label = to_bytes(std::string("mls10 ") + label);
  auto length16 = static_cast<uint16_t>(length);
  HKDFLabel label_str{ length16, mls_label, context };
  auto label_bytes = tls::marshal(label_str);
  return hkdf_expand(suite, secret, label_bytes, length);
}

///
/// HPKEPublicKey and HPKEPrivateKey
///
HPKECiphertext
HPKEPublicKey::encrypt(CipherSuite suite,
                       const bytes& aad,
                       const bytes& pt) const
{
  auto pkR = suite.hpke->kem->deserialize(data);
  auto [enc, ctx] = suite.hpke->setup_base_s(*pkR, {});
  auto ct = ctx.seal(aad, pt);
  return HPKECiphertext{ enc, ct };
}

HPKEPrivateKey
HPKEPrivateKey::generate(CipherSuite suite)
{
  auto priv = suite.hpke->kem->generate_key_pair();
  auto priv_data = suite.hpke->kem->serialize_private(*priv);
  auto pub = priv->public_key();
  auto pub_data = suite.hpke->kem->serialize(*pub);
  return HPKEPrivateKey(priv_data, pub_data);
}

HPKEPrivateKey
HPKEPrivateKey::parse(CipherSuite suite, const bytes& data)
{
  auto priv = suite.hpke->kem->deserialize_private(data);
  auto pub = priv->public_key();
  auto pub_data = suite.hpke->kem->serialize(*pub);
  return HPKEPrivateKey(data, pub_data);
}

HPKEPrivateKey
HPKEPrivateKey::derive(CipherSuite suite, const bytes& secret)
{
  auto priv = suite.hpke->kem->derive_key_pair(secret);
  auto priv_data = suite.hpke->kem->serialize_private(*priv);
  auto pub = priv->public_key();
  auto pub_data = suite.hpke->kem->serialize(*pub);
  return HPKEPrivateKey(priv_data, pub_data);
}

bytes
HPKEPrivateKey::decrypt(CipherSuite suite,
                        const bytes& aad,
                        const HPKECiphertext& ct) const
{
  auto skR = suite.hpke->kem->deserialize_private(data);
  auto ctx = suite.hpke->setup_base_r(ct.kem_output, *skR, {});
  auto pt = ctx.open(aad, ct.ciphertext);
  if (!pt.has_value()) {
    throw InvalidParameterError("HPKE decryption failure");
  }

  return pt.value();
}

HPKEPrivateKey::HPKEPrivateKey(bytes priv_data, bytes pub_data)
  : data(std::move(priv_data))
  , public_key{ std::move(pub_data) }
{}

///
/// SignaturePublicKey and SignaturePrivateKey
///
bool
SignaturePublicKey::verify(const CipherSuite& suite,
                           const bytes& message,
                           const bytes& signature) const
{
  auto pub = suite.sig->deserialize(data);
  return suite.sig->verify(message, signature, *pub);
}

SignaturePrivateKey
SignaturePrivateKey::generate(CipherSuite suite)
{
  auto priv = suite.sig->generate_key_pair();
  auto priv_data = suite.sig->serialize_private(*priv);
  auto pub = priv->public_key();
  auto pub_data = suite.sig->serialize(*pub);
  return SignaturePrivateKey(priv_data, pub_data);
}

SignaturePrivateKey
SignaturePrivateKey::parse(CipherSuite suite, const bytes& data)
{
  auto priv = suite.sig->deserialize_private(data);
  auto pub = priv->public_key();
  auto pub_data = suite.sig->serialize(*pub);
  return SignaturePrivateKey(data, pub_data);
}

SignaturePrivateKey
SignaturePrivateKey::derive(CipherSuite suite, const bytes& secret)
{
  auto priv = suite.sig->derive_key_pair(secret);
  auto priv_data = suite.sig->serialize_private(*priv);
  auto pub = priv->public_key();
  auto pub_data = suite.sig->serialize(*pub);
  return SignaturePrivateKey(priv_data, pub_data);
}

bytes
SignaturePrivateKey::sign(const CipherSuite& suite, const bytes& message) const
{
  auto priv = suite.sig->deserialize_private(data);
  return suite.sig->sign(message, *priv);
}

SignaturePrivateKey::SignaturePrivateKey(bytes priv_data, bytes pub_data)
  : data(std::move(priv_data))
  , public_key{ std::move(pub_data) }
{}

} // namespace mls
