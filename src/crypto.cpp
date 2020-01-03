#include "crypto.h"
#include "common.h"
#include "primitives.h"

#include "openssl/ecdh.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/obj_mac.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

#include <string>

namespace mls {

static const CipherSuite unknown_suite = static_cast<CipherSuite>(0xFFFF);
static const SignatureScheme unknown_scheme =
  static_cast<SignatureScheme>(0xFFFF);

size_t
suite_nonce_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return 12;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

size_t
suite_key_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
      return 16;

    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return 32;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

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
uint32_t CryptoMetrics::digest_bytes = 0;
uint32_t CryptoMetrics::hmac = 0;

CryptoMetrics::Report
CryptoMetrics::snapshot()
{
  return {
    fixed_base_dh, var_base_dh, digest, digest_bytes, hmac,
  };
}

void
CryptoMetrics::reset()
{
  fixed_base_dh = 0;
  var_base_dh = 0;
  digest = 0;
  digest_bytes = 0;
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
CryptoMetrics::count_digest_bytes(uint32_t count)
{
  digest_bytes += count;
}

void
CryptoMetrics::count_hmac()
{
  hmac += 1;
}

///
/// typed_unique_ptr
///

template<>
void
TypedDelete(BIGNUM* ptr)
{
  BN_free(ptr);
}

template<>
void
TypedDelete(EC_KEY* ptr)
{
  EC_KEY_free(ptr);
}

template<>
void
TypedDelete(EC_POINT* ptr)
{
  EC_POINT_free(ptr);
}

template<>
void
TypedDelete(EVP_CIPHER_CTX* ptr)
{
  EVP_CIPHER_CTX_free(ptr);
}

template<>
void
TypedDelete(EVP_MD_CTX* ptr)
{
  EVP_MD_CTX_free(ptr);
}

template<>
void
TypedDelete(EVP_PKEY_CTX* ptr)
{
  EVP_PKEY_CTX_free(ptr);
}

template<>
void
TypedDelete(EVP_PKEY* ptr)
{
  EVP_PKEY_free(ptr);
}

///
/// OpenSSLError
///

// Wrapper for OpenSSL errors
class OpenSSLError : public std::runtime_error
{
public:
  using parent = std::runtime_error;
  using parent::parent;

  static OpenSSLError current();
};

OpenSSLError
OpenSSLError::current()
{
  uint64_t code = ERR_get_error();
  return OpenSSLError(ERR_error_string(code, nullptr));
}

///
/// Digest
///

static DigestType
digest_type(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
      return DigestType::SHA256;
    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return DigestType::SHA512;
  }

  throw InvalidParameterError("Unknown ciphersuite");
}

static const EVP_MD*
ossl_digest_type(DigestType type)
{
  switch (type) {
    case DigestType::SHA256:
      return EVP_sha256();
    case DigestType::SHA512:
      return EVP_sha512();
  }

  throw InvalidParameterError("Unknown digest type");
}

Digest::Digest(DigestType type)
  : _ctx(EVP_MD_CTX_new())
{
  auto md = ossl_digest_type(type);
  _size = EVP_MD_size(md);
  if (EVP_DigestInit(_ctx.get(), md) != 1) {
    throw OpenSSLError::current();
  }
}

Digest::Digest(CipherSuite suite)
  : Digest(digest_type(suite))
{}

Digest&
Digest::write(uint8_t byte)
{
  CryptoMetrics::count_digest_bytes(1);
  if (EVP_DigestUpdate(_ctx.get(), &byte, 1) != 1) {
    throw OpenSSLError::current();
  }
  return *this;
}

Digest&
Digest::write(const bytes& data)
{
  CryptoMetrics::count_digest_bytes(data.size());
  if (EVP_DigestUpdate(_ctx.get(), data.data(), data.size()) != 1) {
    throw OpenSSLError::current();
  }
  return *this;
}

bytes
Digest::digest()
{
  CryptoMetrics::count_digest();
  unsigned int outlen = output_size();
  auto out = bytes(outlen);
  auto ptr = out.data();
  if (EVP_DigestFinal(_ctx.get(), ptr, &outlen) != 1) {
    throw OpenSSLError::current();
  }
  return out;
}

size_t
Digest::output_size() const
{
  return _size;
}

///
/// HKDF and DeriveSecret
///

bytes
hmac(CipherSuite suite, const bytes& key, const bytes& data)
{
  CryptoMetrics::count_hmac();
  unsigned int size = 0;
  auto type = ossl_digest_type(digest_type(suite));
  bytes md(EVP_MAX_MD_SIZE);
  if (nullptr == HMAC(type,
                      key.data(),
                      key.size(),
                      data.data(),
                      data.size(),
                      md.data(),
                      &size)) {
    throw OpenSSLError::current();
  }

  md.resize(size);
  return md;
}

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

bytes
random_bytes(size_t size)
{
  bytes out(size);
  if (1 != RAND_bytes(out.data(), out.size())) {
    throw OpenSSLError::current();
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

HPKEPublicKey::HPKEPublicKey()
  : _suite(unknown_suite)
{}

HPKEPublicKey::HPKEPublicKey(CipherSuite suite)
  : _suite(suite)
{}

HPKEPublicKey::HPKEPublicKey(CipherSuite suite, bytes data)
  : _suite(suite)
  , _data(data)
{}

CipherSuite
HPKEPublicKey::cipher_suite() const
{
  return _suite;
}

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

HPKECiphertext
HPKEPublicKey::encrypt(const bytes& aad, const bytes& plaintext) const
{
  // SetupBaseI
  bytes seed;
  if (DeterministicHPKE::enabled()) {
    seed = to_bytes() + plaintext;
  }

  auto [enc, zz] = primitive::encap(_suite, _data, seed);
  auto [key, nonce] = setup_base(_suite, *this, zz, enc, {});

  // Context.Encrypt
  auto ciphertext = primitive::seal(_suite, key, nonce, aad, plaintext);
  return HPKECiphertext{ enc, ciphertext };
}

bytes
HPKEPublicKey::to_bytes() const
{
  return _data;
}

HPKEPrivateKey
HPKEPrivateKey::generate(CipherSuite suite)
{
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
  return HPKEPrivateKey(suite, primitive::derive(suite, secret));
}

CipherSuite
HPKEPrivateKey::cipher_suite() const
{
  return _suite;
}

bytes
HPKEPrivateKey::decrypt(const bytes& aad, const HPKECiphertext& ct) const
{
  // SetupBaseR
  auto zz = primitive::decap(_suite, _data, ct.kem_output);
  auto [key, nonce] = setup_base(_suite, public_key(), zz, ct.kem_output, {});

  return primitive::open(_suite, key, nonce, aad, ct.ciphertext);
}

HPKEPublicKey
HPKEPrivateKey::public_key() const
{
  return HPKEPublicKey(_suite, _pub_data);
}

HPKEPrivateKey::HPKEPrivateKey(CipherSuite suite, bytes data)
  : _suite(suite)
  , _data(data)
  , _pub_data(primitive::priv_to_pub(suite, data))
{}

///
/// SignaturePublicKey and SignaturePrivateKey
///

SignaturePublicKey::SignaturePublicKey()
  : _scheme(unknown_scheme)
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
