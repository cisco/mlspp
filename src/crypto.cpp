#include "crypto.h"
#include "common.h"
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

template<typename T>
typed_unique_ptr<T>::typed_unique_ptr()
  : typed_unique_ptr_base<T>(nullptr, TypedDelete<T>)
{}

template<typename T>
typed_unique_ptr<T>::typed_unique_ptr(T* ptr)
  : typed_unique_ptr_base<T>(ptr, TypedDelete<T>)
{}

// This shorthand just saves on explicit template arguments
template<typename T>
typed_unique_ptr<T>
make_typed_unique(T* ptr)
{
  return typed_unique_ptr<T>(ptr);
}

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
/// OpenSSLKey
///

enum struct OpenSSLKeyType
{
  P256,
  P521,
  X25519,
  X448,
  Ed25519,
  Ed448
};

OpenSSLKeyType
ossl_key_type(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
      return OpenSSLKeyType::P256;
    case CipherSuite::P521_SHA512_AES256GCM:
      return OpenSSLKeyType::P521;
    case CipherSuite::X25519_SHA256_AES128GCM:
      return OpenSSLKeyType::X25519;
    case CipherSuite::X448_SHA512_AES256GCM:
      return OpenSSLKeyType::X448;
  }

  throw InvalidParameterError("Unknown ciphersuite");
}

OpenSSLKeyType
ossl_key_type(SignatureScheme scheme)
{
  switch (scheme) {
    case SignatureScheme::P256_SHA256:
      return OpenSSLKeyType::P256;
    case SignatureScheme::P521_SHA512:
      return OpenSSLKeyType::P521;
    case SignatureScheme::Ed25519:
      return OpenSSLKeyType::Ed25519;
    case SignatureScheme::Ed448:
      return OpenSSLKeyType::Ed448;
  }

  throw InvalidParameterError("Unknown signature scheme");
}

struct OpenSSLKey
{
  // XXX(rlb@ipv.sx): Deleted ctor that explicitly initialized to
  // nullptr.  Might have to replace some (!ptr.get()) instances
  // with (!ptr) instances.
  OpenSSLKey() = default;

  explicit OpenSSLKey(EVP_PKEY* key)
    : _key(key)
  {}

  OpenSSLKey(const OpenSSLKey& other) = delete;
  OpenSSLKey(OpenSSLKey&& other) = delete;
  OpenSSLKey& operator=(const OpenSSLKey& other) = delete;
  OpenSSLKey& operator=(const OpenSSLKey&& other) = delete;

  virtual ~OpenSSLKey() = default;

  virtual OpenSSLKeyType type() const = 0;
  virtual size_t secret_size() const = 0;
  virtual size_t sig_size() const = 0;
  virtual bool can_derive() const = 0;
  virtual bool can_sign() const = 0;

  virtual bytes marshal() const = 0;
  virtual void generate() = 0;
  virtual void set_public(const bytes& data) = 0;
  virtual void set_private(const bytes& data) = 0;
  virtual void set_secret(const bytes& data) = 0;
  virtual OpenSSLKey* dup() const = 0;
  virtual OpenSSLKey* dup_public() const = 0;

  // Defined below to make it easier to refer to the more specific
  // key types.
  static OpenSSLKey* create(OpenSSLKeyType type);
  static OpenSSLKey* generate(OpenSSLKeyType type);
  static OpenSSLKey* parse_private(OpenSSLKeyType type, const bytes& data);
  static OpenSSLKey* derive(OpenSSLKeyType type, const bytes& data);

  bytes derive(const OpenSSLKey& other) const
  {
    if (!can_derive() || !other.can_derive()) {
      throw InvalidParameterError("Inappropriate key(s) for derive");
    }

    // This and the next line are acceptable because the OpenSSL
    // functions fail to mark the required EVP_PKEYs as const, even
    // though they are not modified.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto priv_pkey = const_cast<EVP_PKEY*>(_key.get());

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto pub_pkey = const_cast<EVP_PKEY*>(other._key.get());

    auto ctx = make_typed_unique(EVP_PKEY_CTX_new(priv_pkey, nullptr));
    if (ctx.get() == nullptr) {
      throw OpenSSLError::current();
    }

    if (1 != EVP_PKEY_derive_init(ctx.get())) {
      throw OpenSSLError::current();
    }

    if (1 != EVP_PKEY_derive_set_peer(ctx.get(), pub_pkey)) {
      throw OpenSSLError::current();
    }

    size_t out_len;
    if (1 != EVP_PKEY_derive(ctx.get(), nullptr, &out_len)) {
      throw OpenSSLError::current();
    }

    bytes out(out_len);
    uint8_t* ptr = out.data();
    if (1 != (EVP_PKEY_derive(ctx.get(), ptr, &out_len))) {
      throw OpenSSLError::current();
    }

    return out;
  }

  bytes sign(const bytes& message) const
  {
    if (!can_sign()) {
      throw InvalidParameterError("Inappropriate key for sign");
    }

    auto ctx = make_typed_unique(EVP_MD_CTX_create());
    if (ctx.get() == nullptr) {
      throw OpenSSLError::current();
    }

    if (1 !=
        EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, _key.get())) {
      throw OpenSSLError::current();
    }

    auto siglen = sig_size();
    bytes sig(sig_size());
    if (1 !=
        EVP_DigestSign(
          ctx.get(), sig.data(), &siglen, message.data(), message.size())) {
      throw OpenSSLError::current();
    }

    sig.resize(siglen);
    return sig;
  }

  bool verify(const bytes& message, const bytes& signature) const
  {
    if (!can_sign()) {
      throw InvalidParameterError("Inappropriate key for verify");
    }

    auto ctx = make_typed_unique(EVP_MD_CTX_create());
    if (ctx.get() == nullptr) {
      throw OpenSSLError::current();
    }

    if (1 != EVP_DigestVerifyInit(
               ctx.get(), nullptr, nullptr, nullptr, _key.get())) {
      throw OpenSSLError::current();
    }

    auto rv = EVP_DigestVerify(ctx.get(),
                               signature.data(),
                               signature.size(),
                               message.data(),
                               message.size());

    return rv == 1;
  }

  bool operator==(const OpenSSLKey& other)
  {
    // If one pointer is null and the other is not, then the two keys
    // are not equal
    auto lhs_present = (_key && (_key.get() != nullptr));
    auto rhs_present = (other._key && (other._key.get() != nullptr));
    if (lhs_present != rhs_present) {
      return false;
    }

    // If both pointers are null, then the two keys are equal.
    if (!lhs_present) {
      return true;
    }

    auto cmp = EVP_PKEY_cmp(_key.get(), other._key.get());
    return cmp == 1;
  }

  typed_unique_ptr<EVP_PKEY> _key;
};

template<>
void
TypedDelete(OpenSSLKey* ptr)
{
  // XXX(rlb@ipv.sx): We need to use this custom deleter because
  // unique_ptr can't be used with forward-declared types, and I
  // don't want to pull OpenSSLKey up into the header file.
  //
  // We are using a smart pointer here, just in a special way.
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  delete ptr;
}

///
/// OpenSSLKey
///
/// This is used to encapsulate the operations required for
/// different types of points, with a slightly cleaner interface
/// than OpenSSL's EVP interface.
///

enum struct RawKeyType : int
{
  X25519 = EVP_PKEY_X25519,
  X448 = EVP_PKEY_X448,
  Ed25519 = EVP_PKEY_ED25519,
  Ed448 = EVP_PKEY_ED448
};

struct RawKey : OpenSSLKey
{
public:
  explicit RawKey(RawKeyType type)
    : _type(static_cast<int>(type))
  {}

  RawKey(int type, EVP_PKEY* pkey)
    : OpenSSLKey(pkey)
    , _type(type)
  {}

  OpenSSLKeyType type() const override
  {
    auto enum_type = static_cast<RawKeyType>(_type);
    switch (enum_type) {
      case RawKeyType::X25519:
        return OpenSSLKeyType::X25519;
      case RawKeyType::X448:
        return OpenSSLKeyType::X448;
      case RawKeyType::Ed25519:
        return OpenSSLKeyType::Ed25519;
      case RawKeyType::Ed448:
        return OpenSSLKeyType::Ed448;
    }

    throw MissingStateError("Unknown raw key type");
  }

  size_t secret_size() const override
  {
    auto enum_type = static_cast<RawKeyType>(_type);
    switch (enum_type) {
      case RawKeyType::X25519:
      case RawKeyType::Ed25519:
        return 32;
      case RawKeyType::X448:
        return 56;
      case RawKeyType::Ed448:
        return 57;
    }

    throw MissingStateError("Unknown raw key type");
  }

  size_t sig_size() const override { return 200; }
  bool can_derive() const override { return true; }
  bool can_sign() const override
  {
    auto enum_type = static_cast<RawKeyType>(_type);
    switch (enum_type) {
      case RawKeyType::X25519:
      case RawKeyType::X448:
        return false;
      case RawKeyType::Ed25519:
      case RawKeyType::Ed448:
        return true;
    }

    return false;
  }

  bytes marshal() const override
  {
    size_t raw_len;
    if (1 != EVP_PKEY_get_raw_public_key(_key.get(), nullptr, &raw_len)) {
      throw OpenSSLError::current();
    }

    bytes raw(raw_len);
    uint8_t* data_ptr = raw.data();
    if (1 != EVP_PKEY_get_raw_public_key(_key.get(), data_ptr, &raw_len)) {
      throw OpenSSLError::current();
    }

    return raw;
  }

  void generate() override { set_secret(random_bytes(secret_size())); }

  void set_public(const bytes& data) override
  {
    auto pkey =
      EVP_PKEY_new_raw_public_key(_type, nullptr, data.data(), data.size());
    if (pkey == nullptr) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  void set_private(const bytes& data) override
  {
    auto pkey =
      EVP_PKEY_new_raw_private_key(_type, nullptr, data.data(), data.size());
    if (pkey == nullptr) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  void set_secret(const bytes& data) override
  {
    DigestType digest_type;
    switch (static_cast<RawKeyType>(_type)) {
      case RawKeyType::X25519:
      case RawKeyType::Ed25519:
        digest_type = DigestType::SHA256;
        break;
      case RawKeyType::X448:
      case RawKeyType::Ed448:
        digest_type = DigestType::SHA512;
        break;
      default:
        throw InvalidParameterError("set_secret not supported");
    }

    bytes digest = Digest(digest_type).write(data).digest();
    digest.resize(secret_size());
    set_private(digest);
  }

  OpenSSLKey* dup() const override
  {
    if (!_key || (_key.get() == nullptr)) {
      return new RawKey(_type, nullptr);
    }

    size_t raw_len = 0;
    if (1 != EVP_PKEY_get_raw_private_key(_key.get(), nullptr, &raw_len)) {
      throw OpenSSLError::current();
    }

    // The actual key fetch will fail if `_key` represents a public key
    bytes raw(raw_len);
    auto data_ptr = raw.data();
    auto rv = EVP_PKEY_get_raw_private_key(_key.get(), data_ptr, &raw_len);
    if (rv == 1) {
      auto pkey =
        EVP_PKEY_new_raw_private_key(_type, nullptr, raw.data(), raw.size());
      if (pkey == nullptr) {
        throw OpenSSLError::current();
      }

      return new RawKey(_type, pkey);
    }

    return dup_public();
  }

  OpenSSLKey* dup_public() const override
  {
    size_t raw_len = 0;
    if (1 != EVP_PKEY_get_raw_public_key(_key.get(), nullptr, &raw_len)) {
      throw OpenSSLError::current();
    }

    bytes raw(raw_len);
    auto data_ptr = raw.data();
    if (1 != EVP_PKEY_get_raw_public_key(_key.get(), data_ptr, &raw_len)) {
      throw OpenSSLError::current();
    }

    auto pkey =
      EVP_PKEY_new_raw_public_key(_type, nullptr, raw.data(), raw.size());
    if (pkey == nullptr) {
      throw OpenSSLError::current();
    }

    return new RawKey(_type, pkey);
  }

private:
  const int _type;
};

enum struct ECKeyType : int
{
  P256 = NID_X9_62_prime256v1,
  P521 = NID_secp521r1
};

struct ECKey : OpenSSLKey
{
public:
  explicit ECKey(ECKeyType type)
    : _curve_nid(static_cast<int>(type))
  {}

  ECKey(int curve_nid, EVP_PKEY* pkey)
    : OpenSSLKey(pkey)
    , _curve_nid(curve_nid)
  {}

  OpenSSLKeyType type() const override { return OpenSSLKeyType::P256; }

  size_t secret_size() const override
  {
    auto enum_curve = static_cast<ECKeyType>(_curve_nid);
    switch (enum_curve) {
      case ECKeyType::P256:
        return 32;
      case ECKeyType::P521:
        return 66;
    }

    throw InvalidParameterError("Unknown curve");
  }

  size_t sig_size() const override { return 200; }
  bool can_derive() const override { return true; }
  bool can_sign() const override { return true; }

  bytes marshal() const override
  {
    auto pub = EVP_PKEY_get0_EC_KEY(_key.get());

    auto len = i2o_ECPublicKey(pub, nullptr);
    if (len == 0) {
      // Technically, this is not necessarily an error, but in
      // practice it always will be.
      throw OpenSSLError::current();
    }

    bytes out(len);
    auto data = out.data();
    if (i2o_ECPublicKey(pub, &data) == 0) {
      throw OpenSSLError::current();
    }

    return out;
  }

  void generate() override
  {
    auto eckey = make_typed_unique(new_ec_key());
    if (1 != EC_KEY_generate_key(eckey.get())) {
      throw OpenSSLError::current();
    }

    reset(eckey.release());
  }

  void set_public(const bytes& data) override
  {
    auto eckey = make_typed_unique(new_ec_key());

    auto eckey_ptr = eckey.get();
    auto data_ptr = data.data();
    if (nullptr == o2i_ECPublicKey(&eckey_ptr, &data_ptr, data.size())) {
      throw OpenSSLError::current();
    }

    reset(eckey.release());
  }

  void set_private(const bytes& data) override
  {
    auto eckey = make_typed_unique(new_ec_key());

    auto group = EC_KEY_get0_group(eckey.get());
    auto d = make_typed_unique(BN_bin2bn(data.data(), data.size(), nullptr));
    auto pt = make_typed_unique(EC_POINT_new(group));
    EC_POINT_mul(group, pt.get(), d.get(), nullptr, nullptr, nullptr);

    EC_KEY_set_private_key(eckey.get(), d.get());
    EC_KEY_set_public_key(eckey.get(), pt.get());

    reset(eckey.release());
  }

  void set_secret(const bytes& data) override
  {
    DigestType digest_type;
    switch (static_cast<ECKeyType>(_curve_nid)) {
      case ECKeyType::P256:
        digest_type = DigestType::SHA256;
        break;
      case ECKeyType::P521:
        digest_type = DigestType::SHA512;
        break;
      default:
        throw InvalidParameterError("set_secret not supported");
    }

    bytes digest = Digest(digest_type).write(data).digest();
    set_private(digest);
  }

  OpenSSLKey* dup() const override
  {
    if (!_key || (_key.get() == nullptr)) {
      return new ECKey(_curve_nid, static_cast<EVP_PKEY*>(nullptr));
    }

    auto eckey_out = EC_KEY_dup(my_ec_key());
    return new ECKey(_curve_nid, eckey_out);
  }

  OpenSSLKey* dup_public() const override
  {
    auto eckey = my_ec_key();
    auto point = EC_KEY_get0_public_key(eckey);

    auto eckey_out = new_ec_key();
    EC_KEY_set_public_key(eckey_out, point);
    return new ECKey(_curve_nid, eckey_out);
  }

private:
  const int _curve_nid;

  ECKey(int curve_nid, EC_KEY* eckey)
    : _curve_nid(curve_nid)
  {
    reset(eckey);
  }

  void reset(EC_KEY* eckey)
  {
    auto pkey = EVP_PKEY_new();

    // Can't be accountable for OpenSSL's internal casting
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    EVP_PKEY_assign_EC_KEY(pkey, eckey);

    _key.reset(pkey);
  }

  const EC_KEY* my_ec_key() const { return EVP_PKEY_get0_EC_KEY(_key.get()); }

  EC_KEY* new_ec_key() const { return EC_KEY_new_by_curve_name(_curve_nid); }
};

OpenSSLKey*
OpenSSLKey::create(OpenSSLKeyType type)
{
  switch (type) {
    case OpenSSLKeyType::X25519:
      return new RawKey(RawKeyType::X25519);
    case OpenSSLKeyType::X448:
      return new RawKey(RawKeyType::X448);
    case OpenSSLKeyType::Ed25519:
      return new RawKey(RawKeyType::Ed25519);
    case OpenSSLKeyType::Ed448:
      return new RawKey(RawKeyType::Ed448);
    case OpenSSLKeyType::P256:
      return new ECKey(ECKeyType::P256);
    case OpenSSLKeyType::P521:
      return new ECKey(ECKeyType::P521);
  }

  throw InvalidParameterError("Unknown key type");
}

OpenSSLKey*
OpenSSLKey::generate(OpenSSLKeyType type)
{
  auto key = make_typed_unique(create(type));
  key->generate();
  return key.release();
}

OpenSSLKey*
OpenSSLKey::parse_private(OpenSSLKeyType type, const bytes& data)
{
  auto key = make_typed_unique(create(type));
  key->set_private(data);
  return key.release();
}

OpenSSLKey*
OpenSSLKey::derive(OpenSSLKeyType type, const bytes& data)
{
  auto key = make_typed_unique(create(type));
  key->set_secret(data);
  return key.release();
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

bytes
derive_secret(CipherSuite suite,
              const bytes& secret,
              const std::string& label,
              const bytes& context)
{
  auto context_hash = Digest(suite).write(context).digest();
  auto size = Digest(suite).output_size();
  return hkdf_expand_label(suite, secret, label, context_hash, size);
}

///
/// AESGCM
///

AESGCM::AESGCM(const bytes& key, const bytes& nonce)
{
  switch (key.size()) {
    case key_size_128:
      _cipher = EVP_aes_128_gcm();
      break;
    case key_size_192:
      _cipher = EVP_aes_192_gcm();
      break;
    case key_size_256:
      _cipher = EVP_aes_256_gcm();
      break;
    default:
      throw InvalidParameterError("Invalid AES key size");
  }

  if (nonce.size() != nonce_size) {
    throw InvalidParameterError("Invalid AES-GCM nonce size");
  }

  _key = key;
  _nonce = nonce;
}

void
AESGCM::set_aad(const bytes& aad)
{
  _aad = aad;
}

bytes
AESGCM::encrypt(const bytes& plaintext) const
{
  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw OpenSSLError::current();
  }

  if (1 != EVP_EncryptInit(ctx.get(), _cipher, _key.data(), _nonce.data())) {
    throw OpenSSLError::current();
  }

  int outlen = 0;
  if (!_aad.empty()) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, _aad.data(), _aad.size())) {
      throw OpenSSLError::current();
    }
  }

  bytes ciphertext(plaintext.size());
  if (1 != EVP_EncryptUpdate(ctx.get(),
                             ciphertext.data(),
                             &outlen,
                             plaintext.data(),
                             plaintext.size())) {
    throw OpenSSLError::current();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw OpenSSLError::current();
  }

  bytes tag(tag_size);
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, tag.data())) {
    throw OpenSSLError::current();
  }

  return ciphertext + tag;
}

bytes
AESGCM::decrypt(const bytes& ciphertext) const
{
  if (ciphertext.size() < tag_size) {
    throw InvalidParameterError("AES-GCM ciphertext smaller than tag size");
  }

  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw OpenSSLError::current();
  }

  if (1 != EVP_DecryptInit(ctx.get(), _cipher, _key.data(), _nonce.data())) {
    throw OpenSSLError::current();
  }

  bytes tag(ciphertext.end() - tag_size, ciphertext.end());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag.data())) {
    throw OpenSSLError::current();
  }

  int out_size;
  if (!_aad.empty()) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, _aad.data(), _aad.size())) {
      throw OpenSSLError::current();
    }
  }

  bytes plaintext(ciphertext.size() - tag_size);
  if (1 != EVP_DecryptUpdate(ctx.get(),
                             plaintext.data(),
                             &out_size,
                             ciphertext.data(),
                             ciphertext.size() - tag_size)) {
    throw OpenSSLError::current();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw InvalidParameterError("AES-GCM authentication failure");
  }

  return plaintext;
}

size_t
AESGCM::key_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
      return key_size_128;
    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return key_size_256;
  }

  throw InvalidParameterError("Non-AESGCM ciphersuite");
}

///
/// PublicKey
///

PublicKey::PublicKey(CipherSuite suite)
  : CipherAware(suite)
  , SignatureAware(unknown_scheme)
  , _key(OpenSSLKey::create(ossl_key_type(suite)))
{}

PublicKey::PublicKey(SignatureScheme scheme)
  : CipherAware(unknown_suite)
  , SignatureAware(scheme)
  , _key(OpenSSLKey::create(ossl_key_type(scheme)))
{}

PublicKey::PublicKey(const PublicKey& other)
  : CipherAware(other)
  , SignatureAware(other)
  , _key(other._key->dup())
{}

PublicKey::PublicKey(CipherSuite suite, const bytes& data)
  : CipherAware(suite)
  , SignatureAware(unknown_scheme)
  , _key(OpenSSLKey::create(ossl_key_type(suite)))
{
  reset(data);
}

PublicKey::PublicKey(SignatureScheme scheme, const bytes& data)
  : CipherAware(unknown_suite)
  , SignatureAware(scheme)
  , _key(OpenSSLKey::create(ossl_key_type(scheme)))
{
  reset(data);
}

PublicKey::PublicKey(CipherSuite suite, OpenSSLKey* key)
  : CipherAware(suite)
  , SignatureAware(unknown_scheme)
  , _key(key)
{}

PublicKey::PublicKey(SignatureScheme scheme, OpenSSLKey* key)
  : CipherAware(unknown_suite)
  , SignatureAware(scheme)
  , _key(key)
{}

PublicKey&
PublicKey::operator=(const PublicKey& other)
{
  if (&other != this) {
    _key.reset(other._key->dup());
    _suite = other._suite;
    _scheme = other._scheme;
  }
  return *this;
}

PublicKey&
PublicKey::operator=(PublicKey&& other) noexcept
{
  if (&other != this) {
    _key = std::move(other._key);
    _suite = other._suite;
    _scheme = other._scheme;
  }
  return *this;
}

bool
PublicKey::operator==(const PublicKey& other) const
{
  return *_key == *other._key;
}

bool
PublicKey::operator!=(const PublicKey& other) const
{
  return !(*this == other);
}

bytes
PublicKey::to_bytes() const
{
  return _key->marshal();
}

void
PublicKey::reset(const bytes& data)
{
  _key->set_public(data);
}

void
PublicKey::reset(OpenSSLKey* key)
{
  _key.reset(key);
}

tls::ostream&
operator<<(tls::ostream& out, const PublicKey& obj)
{
  tls::vector<uint8_t, 2> data = obj.to_bytes();
  return out << data;
}

tls::istream&
operator>>(tls::istream& in, PublicKey& obj)
{
  tls::opaque<2> data;
  in >> data;
  obj.reset(data);
  return in;
}

///
/// PrivateKey
///

PrivateKey::PrivateKey(const PrivateKey& other)
  : CipherAware(other)
  , SignatureAware(other)
  , _key(other._key->dup())
  , _pub(type_preserving_dup(other._pub.get()))
{}

PrivateKey&
PrivateKey::operator=(const PrivateKey& other)
{
  if (this != &other) {
    _key.reset(other._key->dup());
    _pub = type_preserving_dup(other._pub.get());
    _suite = other._suite;
    _scheme = other._scheme;
  }
  return *this;
}

PrivateKey&
PrivateKey::operator=(PrivateKey&& other) noexcept
{
  if (this != &other) {
    _key = std::move(other._key);
    _pub = std::move(other._pub);
    _suite = other._suite;
    _scheme = other._scheme;
  }
  return *this;
}

bool
PrivateKey::operator==(const PrivateKey& other) const
{
  return *_key == *other._key;
}

bool
PrivateKey::operator!=(const PrivateKey& other) const
{
  return !(*this == other);
}

std::unique_ptr<PublicKey>
PrivateKey::type_preserving_dup(const PublicKey* pub) const
{
  auto dh = dynamic_cast<const DHPublicKey*>(pub);
  auto sig = dynamic_cast<const SignaturePublicKey*>(pub);

  if (dh != nullptr) {
    return std::make_unique<DHPublicKey>(*dh);
  }

  if (sig != nullptr) {
    return std::make_unique<SignaturePublicKey>(*sig);
  }

  throw InvalidParameterError("Unknown public key type");
}

PrivateKey::PrivateKey(CipherSuite suite, OpenSSLKey* key)
  : CipherAware(suite)
  , SignatureAware(unknown_scheme)
  , _key(key)
  , _pub(nullptr)
{
  _pub = std::make_unique<DHPublicKey>(suite, _key->dup_public());
}

PrivateKey::PrivateKey(SignatureScheme scheme, OpenSSLKey* key)
  : CipherAware(unknown_suite)
  , SignatureAware(scheme)
  , _key(key)
  , _pub(nullptr)
{
  _pub = std::make_unique<SignaturePublicKey>(scheme, _key->dup_public());
}

///
/// DHPublicKey and DHPrivateKey
///

// XXX(rlb@ipv.sx): This is a bit of a hack, but it means that if
// we're constructing objects for serialization, then we don't
// need to do all the variant stuff
DHPublicKey::DHPublicKey()
  : PublicKey(CipherSuite::X25519_SHA256_AES128GCM)
{}

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
  uint16_t ciphersuite;
  uint8_t mode;
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
  auto context_str = HPKEContext{ static_cast<uint16_t>(hpke_suite),
                                  static_cast<uint8_t>(mode),
                                  kem_context,
                                  info };
  auto context = tls::marshal(context_str);

  auto Nk = AESGCM::key_size(suite);
  auto key_label = to_bytes("hpke key") + context;
  auto key = hkdf_expand(suite, secret, key_label, Nk);

  auto Nn = AESGCM::nonce_size;
  auto nonce_label = to_bytes("hpke nonce") + context;
  auto nonce = hkdf_expand(suite, secret, nonce_label, Nn);

  return std::pair<bytes, bytes>(key, nonce);
}

static std::pair<bytes, bytes>
setup_base(CipherSuite suite,
           const DHPublicKey& pkR,
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
DHPublicKey::encrypt(const bytes& aad, const bytes& plaintext) const
{
  // SetupBaseI
  auto ephemeral = DHPrivateKey::generate(_suite);
  if (DeterministicHPKE::enabled()) {
    auto seed = to_bytes() + plaintext;
    ephemeral = DHPrivateKey::derive(_suite, seed);
  }

  auto enc = ephemeral.public_key().to_bytes();
  auto zz = ephemeral.derive(*this);

  bytes key, nonce;
  bytes info;
  std::tie(key, nonce) = setup_base(_suite, *this, zz, enc, info);

  // Context.Encrypt
  AESGCM gcm(key, nonce);
  gcm.set_aad(aad);
  auto content = gcm.encrypt(plaintext);
  return HPKECiphertext{ ephemeral.public_key(), content };
}

DHPrivateKey
DHPrivateKey::generate(CipherSuite suite)
{
  CryptoMetrics::count_fixed_base_dh();
  auto type = ossl_key_type(suite);
  return DHPrivateKey(suite, OpenSSLKey::generate(type));
}

DHPrivateKey
DHPrivateKey::parse(CipherSuite suite, const bytes& data)
{
  auto type = ossl_key_type(suite);
  return DHPrivateKey(suite, OpenSSLKey::parse_private(type, data));
}

DHPrivateKey
DHPrivateKey::derive(CipherSuite suite, const bytes& secret)
{
  CryptoMetrics::count_fixed_base_dh();
  auto type = ossl_key_type(suite);
  return DHPrivateKey(suite, OpenSSLKey::derive(type, secret));
}

DHPrivateKey
DHPrivateKey::node_derive(CipherSuite suite, const bytes& path_secret)
{
  auto secret_size = Digest(suite).output_size();
  auto node_secret =
    hkdf_expand_label(suite, path_secret, "node", {}, secret_size);
  return DHPrivateKey::derive(suite, node_secret);
}

bytes
DHPrivateKey::derive(const DHPublicKey& pub) const
{
  CryptoMetrics::count_var_base_dh();
  return _key->derive(*pub._key);
}

bytes
DHPrivateKey::decrypt(const bytes& aad, const HPKECiphertext& ciphertext) const
{
  // SetupBaseR
  auto enc = ciphertext.ephemeral.to_bytes();
  auto zz = derive(ciphertext.ephemeral);

  bytes key, nonce;
  bytes info;
  std::tie(key, nonce) = setup_base(_suite, public_key(), zz, enc, info);

  AESGCM gcm(key, nonce);
  gcm.set_aad(aad);
  return gcm.decrypt(ciphertext.content);
}

const DHPublicKey&
DHPrivateKey::public_key() const
{
  if (_pub == nullptr) {
    throw InvalidParameterError("No public key available");
  }

  return dynamic_cast<const DHPublicKey&>(*_pub);
}

DHPrivateKey::DHPrivateKey(CipherSuite suite, OpenSSLKey* key)
  : PrivateKey(suite, key)
{
  _pub = std::make_unique<DHPublicKey>(suite, key->dup_public());
}

///
/// SignaturePublicKey and SignaturePrivateKey
///

bool
SignaturePublicKey::verify(const bytes& message, const bytes& signature) const
{
  return _key->verify(message, signature);
}

SignaturePrivateKey
SignaturePrivateKey::generate(SignatureScheme scheme)
{
  auto type = ossl_key_type(scheme);
  return SignaturePrivateKey(scheme, OpenSSLKey::generate(type));
}

SignaturePrivateKey
SignaturePrivateKey::parse(SignatureScheme scheme, const bytes& data)
{
  auto type = ossl_key_type(scheme);
  return SignaturePrivateKey(scheme, OpenSSLKey::parse_private(type, data));
}

SignaturePrivateKey
SignaturePrivateKey::derive(SignatureScheme scheme, const bytes& secret)
{
  auto type = ossl_key_type(scheme);
  return SignaturePrivateKey(scheme, OpenSSLKey::derive(type, secret));
}

bytes
SignaturePrivateKey::sign(const bytes& message) const
{
  return _key->sign(message);
}

const SignaturePublicKey&
SignaturePrivateKey::public_key() const
{
  if (_pub == nullptr) {
    throw InvalidParameterError("No public key available");
  }

  return dynamic_cast<const SignaturePublicKey&>(*_pub);
}

SignaturePrivateKey::SignaturePrivateKey(SignatureScheme scheme,
                                         OpenSSLKey* key)
  : PrivateKey(scheme, key)
{
  _pub = std::make_unique<SignaturePublicKey>(scheme, key->dup_public());
}

} // namespace mls
