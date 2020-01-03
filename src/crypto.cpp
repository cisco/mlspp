#include "crypto.h"

#include <string>

namespace mls {

///
/// Test mode controls
///

int DeterministicHPKE::_refct = 0;

///
/// Metrics
///

uint32_t CryptoMetrics::fixed_base_dh = 0;
uint32_t CryptoMetrics::var_base_dh = 0;
uint32_t CryptoMetrics::digest = 0;
uint32_t CryptoMetrics::hmac = 0;

CryptoMetrics::Report
CryptoMetrics::snapshot()
{
  return {
    fixed_base_dh,
    var_base_dh,
    digest,
    hmac,
  };
}

void
CryptoMetrics::reset()
{
  fixed_base_dh = 0;
  var_base_dh = 0;
  digest = 0;
  hmac = 0;
}

void
CryptoMetrics::count_fixed_base_dh()
{
  fixed_base_dh += 1;
}

void
CryptoMetrics::count_var_base_dh()
{
  var_base_dh += 1;
}

void
CryptoMetrics::count_digest()
{
  digest += 1;
}

void
CryptoMetrics::count_hmac()
{
  hmac += 1;
}

///
/// Pass-through / metrics wrappers
///

Digest::Digest(CipherSuite suite)
  : primitive::Digest(suite)
{
  CryptoMetrics::count_digest();
}

bytes
hmac(CipherSuite suite, const bytes& key, const bytes& data)
{
  CryptoMetrics::count_hmac();
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
  tls::opaque<1> label;
  tls::opaque<4> context;

  TLS_SERIALIZABLE(length, label, context);
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

enum struct HPKEMode : uint8_t
{
  base = 0x00,
  psk = 0x01,
  auth = 0x02,
};

enum struct HPKECipherSuite : uint16_t
{
  P256_SHA256_AES128GCM = 0x0001,
  P521_SHA512_AES256GCM = 0x0002,
  X25519_SHA256_AES128GCM = 0x003,
  X448_SHA512_AES256GCM = 0x0004,
};

static HPKECipherSuite
to_hpke(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
      return HPKECipherSuite::P256_SHA256_AES128GCM;
    case CipherSuite::P521_SHA512_AES256GCM:
      return HPKECipherSuite::P521_SHA512_AES256GCM;
    case CipherSuite::X25519_SHA256_AES128GCM:
      return HPKECipherSuite::X25519_SHA256_AES128GCM;
    case CipherSuite::X448_SHA512_AES256GCM:
      return HPKECipherSuite::X448_SHA512_AES256GCM;

    default:
      throw InvalidParameterError("Unsupported ciphersuite for HPKE");
  }
}

static std::pair<bytes, bytes>
dhkem_encap(CipherSuite suite, const bytes& pub, const bytes& seed)
{
  bytes ephemeral;
  CryptoMetrics::count_fixed_base_dh();
  if (seed.empty()) {
    ephemeral = primitive::generate(suite);
  } else {
    ephemeral = primitive::derive(suite, seed);
  }

  CryptoMetrics::count_var_base_dh();
  auto enc = primitive::priv_to_pub(suite, ephemeral);
  auto zz = primitive::dh(suite, ephemeral, pub);
  return std::make_tuple(enc, zz);
}

static bytes
dhkem_decap(CipherSuite suite, const bytes& priv, const bytes& enc)
{
  CryptoMetrics::count_var_base_dh();
  return primitive::dh(suite, priv, enc);
}

struct HPKEContext
{
  HPKECipherSuite ciphersuite;
  HPKEMode mode;
  tls::opaque<2> kem_context;
  tls::opaque<2> info;

  TLS_SERIALIZABLE(ciphersuite, mode, kem_context, info)
};

static std::pair<bytes, bytes>
setup_core(CipherSuite suite,
           HPKEMode mode,
           const bytes& secret,
           const bytes& kem_context,
           const bytes& info)
{
  auto hpke_suite = to_hpke(suite);
  auto context =
    tls::marshal(HPKEContext{ hpke_suite, mode, kem_context, info });

  auto Nk = suite_key_size(suite);
  auto key_label = to_bytes("hpke key") + context;
  auto key = hkdf_expand(suite, secret, key_label, Nk);

  auto Nn = suite_nonce_size(suite);
  auto nonce_label = to_bytes("hpke nonce") + context;
  auto nonce = hkdf_expand(suite, secret, nonce_label, Nn);

  return std::pair<bytes, bytes>(key, nonce);
}

static std::pair<bytes, bytes>
setup_base(CipherSuite suite,
           const HPKEPublicKey& pkR,
           const bytes& zz,
           const bytes& enc,
           const bytes& info)
{
  auto Nh = Digest(suite).output_size();
  bytes zero(Nh, 0);
  auto secret = hkdf_extract(suite, zero, zz);
  auto kem_context = enc + pkR.to_bytes();
  return setup_core(suite, HPKEMode::base, secret, kem_context, info);
}

HPKEPublicKey::HPKEPublicKey(const bytes& data_in)
  : data(data_in)
{}

HPKECiphertext
HPKEPublicKey::encrypt(CipherSuite suite,
                       const bytes& aad,
                       const bytes& plaintext) const
{
  // SetupBaseI
  bytes seed;
  if (DeterministicHPKE::enabled()) {
    seed = to_bytes() + plaintext;
  }

  auto [enc, zz] = dhkem_encap(suite, data, seed);
  auto [key, nonce] = setup_base(suite, *this, zz, enc, {});

  // Context.Encrypt
  auto ciphertext = primitive::seal(suite, key, nonce, aad, plaintext);
  return HPKECiphertext{ enc, ciphertext };
}

bytes
HPKEPublicKey::to_bytes() const
{
  return data;
}

HPKEPrivateKey
HPKEPrivateKey::generate(CipherSuite suite)
{
  CryptoMetrics::count_fixed_base_dh();
  return HPKEPrivateKey(suite, primitive::generate(suite));
}

HPKEPrivateKey
HPKEPrivateKey::parse(CipherSuite suite, const bytes& data)
{
  return HPKEPrivateKey(suite, data);
}

HPKEPrivateKey
HPKEPrivateKey::derive(CipherSuite suite, const bytes& secret)
{
  CryptoMetrics::count_fixed_base_dh();
  return HPKEPrivateKey(suite, primitive::derive(suite, secret));
}

bytes
HPKEPrivateKey::decrypt(CipherSuite suite,
                        const bytes& aad,
                        const HPKECiphertext& ct) const
{
  // SetupBaseR
  auto zz = dhkem_decap(suite, _data, ct.kem_output);
  auto [key, nonce] = setup_base(suite, public_key(), zz, ct.kem_output, {});

  return primitive::open(suite, key, nonce, aad, ct.ciphertext);
}

HPKEPublicKey
HPKEPrivateKey::public_key() const
{
  return HPKEPublicKey(_pub_data);
}

HPKEPrivateKey::HPKEPrivateKey(CipherSuite suite, bytes data)
  : _data(data)
  , _pub_data(primitive::priv_to_pub(suite, data))
{}

///
/// SignaturePublicKey and SignaturePrivateKey
///

SignaturePublicKey::SignaturePublicKey()
  : _scheme(SignatureScheme::unknown)
{}

SignaturePublicKey::SignaturePublicKey(SignatureScheme scheme, bytes data)
  : _scheme(scheme)
  , _data(data)
{}

void
SignaturePublicKey::set_signature_scheme(SignatureScheme scheme)
{
  _scheme = scheme;
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
  : _scheme(SignatureScheme::unknown)
{}

SignaturePrivateKey
SignaturePrivateKey::generate(SignatureScheme scheme)
{
  return SignaturePrivateKey(scheme, primitive::generate(scheme));
}

SignaturePrivateKey
SignaturePrivateKey::parse(SignatureScheme scheme, const bytes& data)
{
  return SignaturePrivateKey(scheme, data);
}

SignaturePrivateKey
SignaturePrivateKey::derive(SignatureScheme scheme, const bytes& secret)
{
  return SignaturePrivateKey(scheme, primitive::derive(scheme, secret));
}

bytes
SignaturePrivateKey::sign(const bytes& message) const
{
  return primitive::sign(_scheme, _data, message);
}

SignaturePublicKey
SignaturePrivateKey::public_key() const
{
  return SignaturePublicKey(_scheme, _pub_data);
}

SignaturePrivateKey::SignaturePrivateKey(SignatureScheme scheme, bytes data)
  : _scheme(scheme)
  , _data(data)
  , _pub_data(primitive::priv_to_pub(scheme, data))
{}

} // namespace mls
