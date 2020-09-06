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
{
}

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
  : data(priv_data)
  , public_key{pub_data}
{}

///
/// SignaturePublicKey and SignaturePrivateKey
///

SignaturePublicKey::SignaturePublicKey()
  : _scheme(SignatureScheme::unknown)
{}

SignaturePublicKey::SignaturePublicKey(CipherSuite suite, bytes data)
  : _scheme(scheme_for_suite(suite.id))
  , _data(std::move(data))
{}

void
SignaturePublicKey::set_signature_scheme(SignatureScheme scheme)
{
  _scheme = scheme;
}

void
SignaturePublicKey::set_cipher_suite(CipherSuite suite)
{
  _scheme = scheme_for_suite(suite.id);
}

SignatureScheme
SignaturePublicKey::signature_scheme() const
{
  return _scheme;
}

bytes
SignaturePublicKey::to_bytes() const
{
  return _data;
}

bool
SignaturePublicKey::verify(const bytes& message, const bytes& signature) const
{
  return primitive::verify(_scheme, _data, message, signature);
}

SignaturePrivateKey::SignaturePrivateKey()
  : _suite(CipherSuite::ID::unknown)
  , _scheme(SignatureScheme::unknown)
{}

SignaturePrivateKey
SignaturePrivateKey::generate(CipherSuite suite)
{
  auto scheme = scheme_for_suite(suite.id);
  return SignaturePrivateKey(suite, primitive::generate(scheme));
}

SignaturePrivateKey
SignaturePrivateKey::parse(CipherSuite suite, const bytes& data)
{
  return SignaturePrivateKey(suite, data);
}

SignaturePrivateKey
SignaturePrivateKey::derive(CipherSuite suite, const bytes& secret)
{
  auto scheme = scheme_for_suite(suite.id);
  return SignaturePrivateKey(suite, primitive::derive(scheme, secret));
}

bytes
SignaturePrivateKey::sign(const bytes& message) const
{
  return primitive::sign(_scheme, _data, message);
}

SignaturePublicKey
SignaturePrivateKey::public_key() const
{
  return SignaturePublicKey(_suite, _pub_data);
}

SignaturePrivateKey::SignaturePrivateKey(CipherSuite suite, const bytes& data)
  : _suite(suite)
  , _scheme(scheme_for_suite(suite.id))
  , _data(data)
  , _pub_data(primitive::priv_to_pub(_scheme, data))
{}

} // namespace mls
