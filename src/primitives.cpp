#include "primitives.h"

#include "openssl/ecdh.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/obj_mac.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

#include <stdexcept>

namespace mls {

namespace primitive {

///
/// Smarter smart pointers
///
template<typename T>
void
TypedDelete(T* ptr);

template<>
void
TypedDelete(EVP_MD_CTX* ptr);

template<>
void
TypedDelete(EVP_PKEY* ptr);

template<typename T>
using typed_unique_ptr_base = std::unique_ptr<T, decltype(&TypedDelete<T>)>;

template<typename T>
class typed_unique_ptr : public typed_unique_ptr_base<T>
{
public:
  using parent = typed_unique_ptr_base<T>;

  typed_unique_ptr()
    : parent(nullptr, TypedDelete<T>)
  {}

  explicit typed_unique_ptr(T* ptr)
    : parent(ptr, TypedDelete<T>)
  {}
};

// This shorthand just saves on explicit template arguments
template<typename T>
typed_unique_ptr<T>
make_typed_unique(T* ptr)
{
  return typed_unique_ptr<T>(ptr);
}

///
/// And supporting delete methods
///
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

///
/// Errors
///
static std::runtime_error
openssl_error()
{
  uint64_t code = ERR_get_error();
  return std::runtime_error(ERR_error_string(code, nullptr));
}

///
/// Randomness
///
bytes
random_bytes(size_t size)
{
  bytes out(size);
  if (1 != RAND_bytes(out.data(), out.size())) {
    throw openssl_error();
  }
  return out;
}

///
/// Digest and HMAC
///

static const EVP_MD*
openssl_digest_type(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
      return EVP_sha256();

    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return EVP_sha512();

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

struct Digest::Implementation
{
  size_t size;
  typed_unique_ptr<EVP_MD_CTX> ctx;

  explicit Implementation(CipherSuite suite)
    : ctx(EVP_MD_CTX_new())
  {
    auto md = openssl_digest_type(suite);
    size = EVP_MD_size(md);
    if (EVP_DigestInit(ctx.get(), md) != 1) {
      throw openssl_error();
    }
  }

  void write(uint8_t byte)
  {
    if (EVP_DigestUpdate(ctx.get(), &byte, 1) != 1) {
      throw openssl_error();
    }
  }

  void write(const bytes& data)
  {
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
      throw openssl_error();
    }
  }

  bytes digest()
  {
    unsigned int outlen = size;
    auto out = bytes(outlen);
    auto ptr = out.data();
    if (EVP_DigestFinal(ctx.get(), ptr, &outlen) != 1) {
      throw openssl_error();
    }
    return out;
  }
};

Digest::~Digest() = default;

Digest::Digest(CipherSuite suite)
  : _impl(new Implementation(suite))
{}

Digest&
Digest::write(uint8_t byte)
{
  _impl->write(byte);
  return *this;
}

Digest&
Digest::write(const bytes& data)
{
  _impl->write(data);
  return *this;
}

bytes
Digest::digest()
{
  return _impl->digest();
}

size_t
Digest::output_size() const
{
  return _impl->size;
}

bytes
hmac(CipherSuite suite, const bytes& key, const bytes& data)
{
  unsigned int size = 0;
  auto type = openssl_digest_type(suite);
  bytes md(EVP_MAX_MD_SIZE);
  if (nullptr == HMAC(type,
                      key.data(),
                      key.size(),
                      data.data(),
                      data.size(),
                      md.data(),
                      &size)) {
    throw openssl_error();
  }

  md.resize(size);
  return md;
}

///
/// Symmetric encryption
///

static const EVP_CIPHER*
openssl_cipher(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
      return EVP_aes_128_gcm();

    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return EVP_aes_256_gcm();

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

static size_t
openssl_tag_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return 16;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

bytes
seal(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     const bytes& aad,
     const bytes& plaintext)
{
  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_EncryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  if (!aad.empty()) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad.size())) {
      throw openssl_error();
    }
  }

  bytes ciphertext(plaintext.size());
  if (1 != EVP_EncryptUpdate(ctx.get(),
                             ciphertext.data(),
                             &outlen,
                             plaintext.data(),
                             plaintext.size())) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }

  auto tag_size = openssl_tag_size(suite);
  bytes tag(tag_size);
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, tag.data())) {
    throw openssl_error();
  }

  return ciphertext + tag;
}

bytes
open(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     const bytes& aad,
     const bytes& ciphertext)
{
  auto tag_size = openssl_tag_size(suite);
  if (ciphertext.size() < tag_size) {
    throw InvalidParameterError("AES-GCM ciphertext smaller than tag size");
  }

  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_DecryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  bytes tag(ciphertext.end() - tag_size, ciphertext.end());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag.data())) {
    throw openssl_error();
  }

  int out_size;
  if (!aad.empty()) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad.size())) {
      throw openssl_error();
    }
  }

  bytes plaintext(ciphertext.size() - tag_size);
  if (1 != EVP_DecryptUpdate(ctx.get(),
                             plaintext.data(),
                             &out_size,
                             ciphertext.data(),
                             ciphertext.size() - tag_size)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw InvalidParameterError("AES-GCM authentication failure");
  }

  return plaintext;
}

///
/// Signing
///

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
    default:
      throw InvalidParameterError("Unknown ciphersuite");
  }
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
    default:
      throw InvalidParameterError("Unknown signature scheme");
  }
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
  virtual bytes marshal_private() const = 0;
  virtual void generate() = 0;
  virtual void set_public(const bytes& data) = 0;
  virtual void set_private(const bytes& data) = 0;
  virtual void set_secret(const bytes& data) = 0;

  // Defined below to make it easier to refer to the more specific
  // key types.
  static OpenSSLKey* create(OpenSSLKeyType type);
  static OpenSSLKey* generate(OpenSSLKeyType type);
  static OpenSSLKey* parse_private(OpenSSLKeyType type, const bytes& data);
  static OpenSSLKey* parse_public(OpenSSLKeyType type, const bytes& data);
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
      throw openssl_error();
    }

    if (1 != EVP_PKEY_derive_init(ctx.get())) {
      throw openssl_error();
    }

    if (1 != EVP_PKEY_derive_set_peer(ctx.get(), pub_pkey)) {
      throw openssl_error();
    }

    size_t out_len;
    if (1 != EVP_PKEY_derive(ctx.get(), nullptr, &out_len)) {
      throw openssl_error();
    }

    bytes out(out_len);
    uint8_t* ptr = out.data();
    if (1 != (EVP_PKEY_derive(ctx.get(), ptr, &out_len))) {
      throw openssl_error();
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
      throw openssl_error();
    }

    if (1 !=
        EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, _key.get())) {
      throw openssl_error();
    }

    auto siglen = sig_size();
    bytes sig(sig_size());
    if (1 !=
        EVP_DigestSign(
          ctx.get(), sig.data(), &siglen, message.data(), message.size())) {
      throw openssl_error();
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
      throw openssl_error();
    }

    if (1 != EVP_DigestVerifyInit(
               ctx.get(), nullptr, nullptr, nullptr, _key.get())) {
      throw openssl_error();
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
      throw openssl_error();
    }

    bytes raw(raw_len);
    uint8_t* data_ptr = raw.data();
    if (1 != EVP_PKEY_get_raw_public_key(_key.get(), data_ptr, &raw_len)) {
      throw openssl_error();
    }

    return raw;
  }

  bytes marshal_private() const override
  {
    size_t raw_len;
    if (1 != EVP_PKEY_get_raw_private_key(_key.get(), nullptr, &raw_len)) {
      throw openssl_error();
    }

    bytes raw(raw_len);
    uint8_t* data_ptr = raw.data();
    if (1 != EVP_PKEY_get_raw_private_key(_key.get(), data_ptr, &raw_len)) {
      throw openssl_error();
    }

    return raw;
  }

  void generate() override { set_secret(random_bytes(secret_size())); }

  void set_public(const bytes& data) override
  {
    auto pkey =
      EVP_PKEY_new_raw_public_key(_type, nullptr, data.data(), data.size());
    if (pkey == nullptr) {
      throw openssl_error();
    }

    _key.reset(pkey);
  }

  void set_private(const bytes& data) override
  {
    auto pkey =
      EVP_PKEY_new_raw_private_key(_type, nullptr, data.data(), data.size());
    if (pkey == nullptr) {
      throw openssl_error();
    }

    _key.reset(pkey);
  }

  void set_secret(const bytes& data) override
  {
    CipherSuite ersatz_suite;
    switch (static_cast<RawKeyType>(_type)) {
      case RawKeyType::X25519:
      case RawKeyType::Ed25519:
        ersatz_suite = CipherSuite::P256_SHA256_AES128GCM;
        break;
      case RawKeyType::X448:
      case RawKeyType::Ed448:
        ersatz_suite = CipherSuite::P521_SHA512_AES256GCM;
        break;
      default:
        throw InvalidParameterError("set_secret not supported");
    }

    bytes digest = Digest(ersatz_suite).write(data).digest();
    digest.resize(secret_size());
    set_private(digest);
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
      throw openssl_error();
    }

    bytes out(len);
    auto data = out.data();
    if (i2o_ECPublicKey(pub, &data) == 0) {
      throw openssl_error();
    }

    return out;
  }

  bytes marshal_private() const override
  {
    auto eckey = EVP_PKEY_get0_EC_KEY(_key.get());
    auto d = EC_KEY_get0_private_key(eckey);

    bytes out(BN_num_bytes(d));
    auto data = out.data();
    if (BN_bn2bin(d, data) != int(out.size())) {
      throw openssl_error();
    }

    return out;
  }

  void generate() override
  {
    auto eckey = make_typed_unique(new_ec_key());
    if (1 != EC_KEY_generate_key(eckey.get())) {
      throw openssl_error();
    }

    reset(eckey.release());
  }

  void set_public(const bytes& data) override
  {
    auto eckey = make_typed_unique(new_ec_key());

    auto eckey_ptr = eckey.get();
    auto data_ptr = data.data();
    if (nullptr == o2i_ECPublicKey(&eckey_ptr, &data_ptr, data.size())) {
      throw openssl_error();
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
    CipherSuite ersatz_suite;
    switch (static_cast<ECKeyType>(_curve_nid)) {
      case ECKeyType::P256:
        ersatz_suite = CipherSuite::P256_SHA256_AES128GCM;
        break;
      case ECKeyType::P521:
        ersatz_suite = CipherSuite::P521_SHA512_AES256GCM;
        break;
      default:
        throw InvalidParameterError("set_secret not supported");
    }

    bytes digest = Digest(ersatz_suite).write(data).digest();
    set_private(digest);
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
  auto key = std::unique_ptr<OpenSSLKey>(create(type));
  key->generate();
  return key.release();
}

OpenSSLKey*
OpenSSLKey::parse_private(OpenSSLKeyType type, const bytes& data)
{
  auto key = std::unique_ptr<OpenSSLKey>(create(type));
  key->set_private(data);
  return key.release();
}

OpenSSLKey*
OpenSSLKey::parse_public(OpenSSLKeyType type, const bytes& data)
{
  auto key = std::unique_ptr<OpenSSLKey>(create(type));
  key->set_public(data);
  return key.release();
}

OpenSSLKey*
OpenSSLKey::derive(OpenSSLKeyType type, const bytes& data)
{
  auto key = std::unique_ptr<OpenSSLKey>(create(type));
  key->set_secret(data);
  return key.release();
}

///
/// DHKEM
///
bytes
generate(CipherSuite suite)
{
  auto type = ossl_key_type(suite);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::generate(type));
  return key->marshal_private();
}

bytes
derive(CipherSuite suite, const bytes& data)
{
  auto type = ossl_key_type(suite);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::derive(type, data));
  return key->marshal_private();
}

bytes
priv_to_pub(CipherSuite suite, const bytes& data)
{
  auto type = ossl_key_type(suite);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::parse_private(type, data));
  return key->marshal();
}

bytes
dh(CipherSuite suite, const bytes& priv, const bytes& pub)
{
  auto type = ossl_key_type(suite);
  auto pub_key =
    std::unique_ptr<OpenSSLKey>(OpenSSLKey::parse_public(type, pub));
  auto priv_key =
    std::unique_ptr<OpenSSLKey>(OpenSSLKey::parse_private(type, priv));
  return priv_key->derive(*pub_key);
}

///
/// Signing
///
bytes
generate(SignatureScheme scheme)
{
  auto type = ossl_key_type(scheme);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::generate(type));
  return key->marshal_private();
}

bytes
derive(SignatureScheme scheme, const bytes& data)
{
  auto type = ossl_key_type(scheme);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::derive(type, data));
  return key->marshal_private();
}

bytes
priv_to_pub(SignatureScheme scheme, const bytes& data)
{
  auto type = ossl_key_type(scheme);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::parse_private(type, data));
  return key->marshal();
}

bytes
sign(SignatureScheme scheme, const bytes& priv, const bytes& message)
{
  auto type = ossl_key_type(scheme);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::parse_private(type, priv));
  return key->sign(message);
}

bool
verify(SignatureScheme scheme,
       const bytes& pub,
       const bytes& message,
       const bytes& signature)
{
  auto type = ossl_key_type(scheme);
  auto key = std::unique_ptr<OpenSSLKey>(OpenSSLKey::parse_public(type, pub));
  return key->verify(message, signature);
}

} // namespace primitive
} // namespace mls
