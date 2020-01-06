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

enum struct HPKEKEMID : uint16_t
{
  DHKEM_P256 = 0x0001,
  DHKEM_X25519 = 0x0002,
  DHKEM_P521 = 0x0003,
  DHKEM_X448 = 0x0004,
};

static size_t
hpke_npk(HPKEKEMID kem)
{
  switch (kem) {
    case HPKEKEMID::DHKEM_P256:
      return 65;
    case HPKEKEMID::DHKEM_X25519:
      return 32;
    case HPKEKEMID::DHKEM_P521:
      return 133;
    case HPKEKEMID::DHKEM_X448:
      return 56;
    default:
      throw InvalidParameterError("Unknown HPKE KEM ID");
  }
}

enum struct HPKEKDFID : uint16_t
{
  HKDF_SHA256 = 0x0001,
  HKDF_SHA512 = 0x0002,
};

enum struct HPKEAEADID : uint16_t
{
  AES_GCM_128 = 0x0001,
  AES_GCM_256 = 0x0002,
};

static std::tuple<HPKEKEMID, HPKEKDFID, HPKEAEADID>
hpke_suite(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
      return std::make_tuple(
        HPKEKEMID::DHKEM_P256, HPKEKDFID::HKDF_SHA256, HPKEAEADID::AES_GCM_128);

    case CipherSuite::P521_SHA512_AES256GCM:
      return std::make_tuple(
        HPKEKEMID::DHKEM_P521, HPKEKDFID::HKDF_SHA512, HPKEAEADID::AES_GCM_256);

    case CipherSuite::X25519_SHA256_AES128GCM:
      return std::make_tuple(HPKEKEMID::DHKEM_X25519,
                             HPKEKDFID::HKDF_SHA256,
                             HPKEAEADID::AES_GCM_128);

    case CipherSuite::X448_SHA512_AES256GCM:
      return std::make_tuple(
        HPKEKEMID::DHKEM_X448, HPKEKDFID::HKDF_SHA512, HPKEAEADID::AES_GCM_256);

    default:
      throw InvalidParameterError("Unsupported ciphersuite for HPKE");
  }
}

static std::tuple<bytes, bytes>
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
  HPKEMode mode;
  HPKEKEMID kem;
  HPKEKDFID kdf;
  HPKEAEADID aead;
  tls::opaque<0> enc;
  tls::opaque<0> pkRm;
  tls::opaque<0> pkIm;
  tls::opaque<0> psk_id_hash;
  tls::opaque<0> info_hash;

  TLS_SERIALIZABLE(mode,
                   kem,
                   kdf,
                   aead,
                   enc,
                   pkRm,
                   pkIm,
                   psk_id_hash,
                   info_hash)
};

static std::tuple<bytes, bytes>
hpke_key_schedule(CipherSuite suite,
                  const HPKEPublicKey& pkR,
                  const bytes& enc,
                  const bytes& zz)
{
  auto [kem, kdf, aead] = hpke_suite(suite);
  auto Npk = hpke_npk(kem);
  auto Nh = Digest(suite).output_size();
  auto Nk = suite_key_size(suite);
  auto Nn = suite_nonce_size(suite);

  // We only support base and no-info.  So we can hard-wire these inputs, and
  // skip VerifyMode().  We will need to generalize if we support other modes or
  // non-empty info later.
  auto mode = HPKEMode::base;
  auto info = bytes{};
  auto pkIm = bytes(Npk, 0);
  auto psk = bytes(Nh, 0);
  auto psk_id = bytes{};

  auto ctx = tls::marshal(HPKEContext{
    mode,
    kem,
    kdf,
    aead,
    enc,
    pkR.to_bytes(),
    pkIm,
    Digest(suite).write(psk_id).digest(),
    Digest(suite).write(info).digest(),
  });

  auto key_ctx = to_bytes("hpke key") + ctx;
  auto nonce_ctx = to_bytes("hpke nonce") + ctx;

  auto secret = hkdf_extract(suite, psk, zz);
  auto key = hkdf_expand(suite, secret, key_ctx, Nk);
  auto nonce = hkdf_expand(suite, secret, nonce_ctx, Nn);

  return std::make_tuple(key, nonce);
}

HPKEPublicKey::HPKEPublicKey(const bytes& data_in)
  : data(data_in)
{}

HPKECiphertext
HPKEPublicKey::encrypt(CipherSuite suite,
                       const bytes& aad,
                       const bytes& pt) const
{
  // SetupBaseI
  bytes seed;
  if (DeterministicHPKE::enabled()) {
    seed = to_bytes() + pt;
  }

  auto [enc, zz] = dhkem_encap(suite, data, seed);
  auto [key, nonce] = hpke_key_schedule(suite, *this, enc, zz);

  // Context.Encrypt
  auto ct = primitive::seal(suite, key, nonce, aad, pt);
  return HPKECiphertext{ enc, ct };
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
  auto [key, nonce] = hpke_key_schedule(suite, public_key(), ct.kem_output, zz);

  return primitive::open(suite, key, nonce, aad, ct.ciphertext);
}

HPKEPublicKey
HPKEPrivateKey::public_key() const
{
  return HPKEPublicKey(_pub_data);
}

HPKEPrivateKey::HPKEPrivateKey(CipherSuite suite, bytes data)
  : _data(std::move(data))
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
  , _data(std::move(data))
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
  , _data(std::move(data))
  , _pub_data(primitive::priv_to_pub(scheme, data))
{}

} // namespace mls
