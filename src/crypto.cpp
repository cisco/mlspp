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
#include "state.h"

#include <string>

namespace mls {

///
/// Test mode controls
///

namespace test {

int DeterministicECIES::_refct = 0;

bool
deterministic_signature_scheme(SignatureScheme scheme)
{
  switch (scheme) {
    case SignatureScheme::P256_SHA256:
      return false;
    case SignatureScheme::P521_SHA512:
      return false;
    case SignatureScheme::Ed25519:
      return true;
    case SignatureScheme::Ed448:
      return true;
  }
}

}

///
/// CipherSuite and SignatureScheme
///

static const CipherSuite unknown_suite = static_cast<CipherSuite>(0xFFFF);
static const SignatureScheme unknown_scheme =
  static_cast<SignatureScheme>(0xFFFF);

tls::ostream&
operator<<(tls::ostream& out, const CipherSuite& obj)
{
  return out << static_cast<uint16_t>(obj);
}

tls::istream&
operator>>(tls::istream& in, CipherSuite& obj)
{
  uint16_t val;
  in >> val;
  obj = static_cast<CipherSuite>(val);
  return in;
}

tls::ostream&
operator<<(tls::ostream& out, const SignatureScheme& obj)
{
  return out << static_cast<uint16_t>(obj);
}

tls::istream&
operator>>(tls::istream& in, SignatureScheme& obj)
{
  uint16_t val;
  in >> val;
  obj = static_cast<SignatureScheme>(val);
  return in;
}

///
/// OpenSSLError
///

OpenSSLError
OpenSSLError::current()
{
  unsigned long code = ERR_get_error();
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
  OpenSSLKey()
    : _key(nullptr)
  {}

  OpenSSLKey(EVP_PKEY* key)
    : _key(key)
  {}

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

  bool operator==(const OpenSSLKey& other)
  {
    // If one pointer is null and the other is not, then the two keys
    // are not equal
    if (!!_key.get() != !!other._key.get()) {
      return false;
    }

    // If both pointers are null, then the two keys are equal.
    if (!_key.get()) {
      return true;
    }

    auto cmp = EVP_PKEY_cmp(_key.get(), other._key.get());
    return cmp == 1;
  }

  typed_unique_ptr<EVP_PKEY> _key;
};

///
/// Deleters and smart pointers for OpenSSL types
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

template<>
void
TypedDelete(OpenSSLKey* ptr)
{
  delete ptr;
}

template<>
void
TypedDelete(PublicKey* ptr)
{
  delete ptr;
}

// This shorthand just saves on explicit template arguments
template<typename T>
typed_unique_ptr<T>
make_typed_unique(T* ptr)
{
  return typed_unique_ptr<T>(ptr);
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
  RawKey(RawKeyType type)
    : _type(static_cast<int>(type))
  {}

  RawKey(int type, EVP_PKEY* pkey)
    : OpenSSLKey(pkey)
    , _type(type)
  {}

  virtual OpenSSLKeyType type() const
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

  virtual size_t secret_size() const
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

  virtual size_t sig_size() const { return 200; }
  virtual bool can_derive() const { return true; }
  virtual bool can_sign() const
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

  virtual bytes marshal() const
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

  virtual void generate() { set_secret(random_bytes(secret_size())); }

  virtual void set_public(const bytes& data)
  {
    auto pkey =
      EVP_PKEY_new_raw_public_key(_type, nullptr, data.data(), data.size());
    if (!pkey) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  virtual void set_private(const bytes& data)
  {
    auto pkey =
      EVP_PKEY_new_raw_private_key(_type, nullptr, data.data(), data.size());
    if (!pkey) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  virtual void set_secret(const bytes& data)
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

    bytes digest =
      Digest(digest_type).write(dh_hash_prefix).write(data).digest();
    digest.resize(secret_size());
    set_private(digest);
  }

  virtual OpenSSLKey* dup() const
  {
    // XXX(rlb@ipv.sx): This shouldn't be necessary, but somehow the
    // RatchetTree ctor tries to copy an empty key.
    if (!_key.get()) {
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
      if (!pkey) {
        throw OpenSSLError::current();
      }

      return new RawKey(_type, pkey);
    }

    return dup_public();
  }

  virtual OpenSSLKey* dup_public() const
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
    if (!pkey) {
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
  ECKey(ECKeyType type)
    : _curve_nid(static_cast<int>(type))
  {}

  ECKey(int curve_nid, EVP_PKEY* pkey)
    : _curve_nid(curve_nid)
    , OpenSSLKey(pkey)
  {}

  virtual OpenSSLKeyType type() const { return OpenSSLKeyType::P256; }
  virtual size_t secret_size() const
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
  virtual size_t sig_size() const { return 200; }
  virtual bool can_derive() const { return true; }
  virtual bool can_sign() const { return true; }

  virtual bytes marshal() const
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

  virtual void generate()
  {
    auto eckey = make_typed_unique(new_ec_key());
    if (1 != EC_KEY_generate_key(eckey.get())) {
      throw OpenSSLError::current();
    }

    reset(eckey.release());
  }

  virtual void set_public(const bytes& data)
  {
    auto eckey = make_typed_unique(new_ec_key());

    auto eckey_ptr = eckey.get();
    auto data_ptr = data.data();
    if (!o2i_ECPublicKey(&eckey_ptr, &data_ptr, data.size())) {
      throw OpenSSLError::current();
    }

    reset(eckey.release());
  }

  virtual void set_private(const bytes& data)
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

  virtual void set_secret(const bytes& data)
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

    bytes digest =
      Digest(digest_type).write(dh_hash_prefix).write(data).digest();
    set_private(digest);
  }

  virtual OpenSSLKey* dup() const
  {
    // XXX(rlb@ipv.sx): This shouldn't be necessary, but somehow the
    // RatchetTree ctor tries to copy an empty key.
    if (!_key.get()) {
      return new ECKey(_curve_nid, static_cast<EVP_PKEY*>(nullptr));
    }

    auto eckey_out = EC_KEY_dup(my_ec_key());
    return new ECKey(_curve_nid, eckey_out);
  }

  virtual OpenSSLKey* dup_public() const
  {
    auto eckey = my_ec_key();
    auto group = EC_KEY_get0_group(eckey);
    auto point = EC_KEY_get0_public_key(eckey);

    auto eckey_out = new_ec_key();
    EC_KEY_set_public_key(eckey_out, point);
    return new ECKey(_curve_nid, eckey_out);
  }

private:
  const int _curve_nid;

  ECKey(int curve_nid, EC_KEY* eckey)
    : OpenSSLKey()
    , _curve_nid(curve_nid)
  {
    reset(eckey);
  }

  void reset(EC_KEY* eckey)
  {
    auto pkey = EVP_PKEY_new();
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

DigestType
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

const EVP_MD*
ossl_digest_type(DigestType type)
{
  switch (type) {
    case DigestType::SHA256:
      return EVP_sha256();
    case DigestType::SHA512:
      return EVP_sha512();
  }
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
  if (EVP_DigestUpdate(_ctx.get(), &byte, 1) != 1) {
    throw OpenSSLError::current();
  }
  return *this;
}

Digest&
Digest::write(const bytes& data)
{
  if (EVP_DigestUpdate(_ctx.get(), data.data(), data.size()) != 1) {
    throw OpenSSLError::current();
  }
  return *this;
}

bytes
Digest::digest()
{
  unsigned int outlen = output_size();
  auto out = bytes(outlen);
  auto ptr = out.data();
  if (EVP_DigestFinal(_ctx.get(), ptr, &outlen) != 1) {
    throw OpenSSLError::current();
  }
  return out;
}

const size_t
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
  unsigned int size = 0;
  auto type = ossl_digest_type(digest_type(suite));
  bytes md(EVP_MAX_MD_SIZE);
  if (!HMAC(type,
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

bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm)
{
  return hmac(suite, salt, ikm);
}

// struct {
//     uint16 length = Length;
//     opaque label<6..255> = "mls10 " + Label;
//     GroupState state = State;
// } HkdfLabel;
struct HKDFLabel
{
  uint16_t length;
  tls::opaque<1, 7> label;
  GroupState group_state;
};

tls::ostream&
operator<<(tls::ostream& out, const HKDFLabel& obj)
{
  return out << obj.length << obj.label << obj.group_state;
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
  if (!RAND_bytes(out.data(), out.size())) {
    throw OpenSSLError::current();
  }
  return out;
}

// For simplicity, we enforce that size <= Hash.length, so that
// HKDF-Expand(Secret, Label) reduces to:
//
//   HMAC(Secret, Label || 0x01)
template<typename T>
static bytes
hkdf_expand(CipherSuite suite, const bytes& secret, const T& info, size_t size)
{
  // Ensure that we need only one hash invocation
  if (size > Digest(suite).output_size()) {
    throw InvalidParameterError("Size too big for hkdf_expand");
  }

  auto label = tls::marshal(info);
  label.push_back(0x01);
  auto mac = hmac(suite, secret, label);
  mac.resize(size);
  return mac;
}

bytes
derive_secret(CipherSuite suite,
              const bytes& secret,
              const std::string& label,
              const GroupState& state,
              size_t size)
{
  std::string mls_label = std::string("mls10 ") + label;
  bytes vec_label(mls_label.begin(), mls_label.end());

  HKDFLabel label_str{ uint16_t(size), vec_label, state };
  return hkdf_expand(suite, secret, label_str, size);
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
AESGCM::encrypt(const bytes& pt) const
{
  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw OpenSSLError::current();
  }

  if (!EVP_EncryptInit(ctx.get(), _cipher, _key.data(), _nonce.data())) {
    throw OpenSSLError::current();
  }

  int outlen = pt.size() + tag_size;
  bytes ct(pt.size() + tag_size);

  if (_aad.size() > 0) {
    if (!EVP_EncryptUpdate(
          ctx.get(), nullptr, &outlen, _aad.data(), _aad.size())) {
      throw OpenSSLError::current();
    }
  }

  if (!EVP_EncryptUpdate(ctx.get(), ct.data(), &outlen, pt.data(), pt.size())) {
    throw OpenSSLError::current();
  }

  if (!EVP_EncryptFinal(ctx.get(), ct.data() + pt.size(), &outlen)) {
    throw OpenSSLError::current();
  }

  if (!EVP_CIPHER_CTX_ctrl(
        ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, ct.data() + pt.size())) {
    throw OpenSSLError::current();
  }

  return ct;
}

bytes
AESGCM::decrypt(const bytes& ct) const
{
  if (ct.size() < tag_size) {
    throw InvalidParameterError("AES-GCM ciphertext smaller than tag size");
  }

  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw OpenSSLError::current();
  }

  if (!EVP_DecryptInit(ctx.get(), _cipher, _key.data(), _nonce.data())) {
    throw OpenSSLError::current();
  }

  uint8_t* tag = const_cast<uint8_t*>(ct.data() + ct.size() - tag_size);
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag)) {
    throw OpenSSLError::current();
  }

  int dummy;
  if (_aad.size() > 0) {
    if (!EVP_DecryptUpdate(
          ctx.get(), nullptr, &dummy, _aad.data(), _aad.size())) {
      throw OpenSSLError::current();
    }
  }

  bytes pt(ct.size() - tag_size);
  if (!EVP_DecryptUpdate(
        ctx.get(), pt.data(), &dummy, ct.data(), ct.size() - tag_size)) {
    throw OpenSSLError::current();
  }

  if (!EVP_DecryptFinal(ctx.get(), pt.data() + ct.size() - tag_size, &dummy)) {
    throw OpenSSLError::current();
  }

  return pt;
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
  : _key(OpenSSLKey::create(ossl_key_type(suite)))
  , CipherAware(suite)
  , SignatureAware(unknown_scheme)
{}

PublicKey::PublicKey(SignatureScheme scheme)
  : _key(OpenSSLKey::create(ossl_key_type(scheme)))
  , CipherAware(unknown_suite)
  , SignatureAware(scheme)
{}

PublicKey::PublicKey(const PublicKey& other)
  : _key(other._key->dup())
  , CipherAware(other)
  , SignatureAware(other)
{}

PublicKey::PublicKey(CipherSuite suite, const bytes& data)
  : _key(OpenSSLKey::create(ossl_key_type(suite)))
  , CipherAware(suite)
  , SignatureAware(unknown_scheme)
{
  reset(data);
}

PublicKey::PublicKey(SignatureScheme scheme, const bytes& data)
  : _key(OpenSSLKey::create(ossl_key_type(scheme)))
  , CipherAware(unknown_suite)
  , SignatureAware(scheme)
{
  reset(data);
}

PublicKey::PublicKey(CipherSuite suite, OpenSSLKey* key)
  : _key(key)
  , CipherAware(suite)
  , SignatureAware(unknown_scheme)
{}

PublicKey::PublicKey(SignatureScheme scheme, OpenSSLKey* key)
  : _key(key)
  , CipherAware(unknown_suite)
  , SignatureAware(scheme)
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
PublicKey::operator=(PublicKey&& other)
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
  : _key(other._key->dup())
  , _pub(new PublicKey(*other._pub))
  , CipherAware(other)
  , SignatureAware(other)
{}

PrivateKey&
PrivateKey::operator=(const PrivateKey& other)
{
  if (this != &other) {
    _key.reset(other._key->dup());
    _pub.reset(new PublicKey(*other._pub));
    _suite = other._suite;
    _scheme = other._scheme;
  }
  return *this;
}

PrivateKey&
PrivateKey::operator=(PrivateKey&& other)
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

PrivateKey::PrivateKey(CipherSuite suite, OpenSSLKey* key)
  : _key(key)
  , _pub(nullptr)
  , CipherAware(suite)
  , SignatureAware(unknown_scheme)
{}

PrivateKey::PrivateKey(SignatureScheme scheme, OpenSSLKey* key)
  : _key(key)
  , _pub(nullptr)
  , CipherAware(unknown_suite)
  , SignatureAware(scheme)
{}

///
/// DHPublicKey and DHPrivateKey
///

// key = HKDF-Expand(Secret, ECIESLabel("key"), Length)
// nonce = HKDF-Expand(Secret, ECIESLabel("nonce"), Length)
//
// Where ECIESLabel is specified as:
//
// struct {
//   uint16 length = Length;
//   opaque label<12..255> = "mls10 ecies " + Label;
// } ECIESLabel;
struct ECIESLabel
{
  uint16_t length;
  tls::opaque<1, 12> label;
};

tls::ostream&
operator<<(tls::ostream& out, const ECIESLabel& obj)
{
  return out << obj.length << obj.label;
}

static std::pair<bytes, bytes>
derive_ecies_secrets(CipherSuite suite, const bytes& shared_secret)
{
  uint16_t key_size = AESGCM::key_size(suite);
  std::string key_label_str{ "mls10 ecies key" };
  bytes key_label_vec{ key_label_str.begin(), key_label_str.end() };
  ECIESLabel key_label{ key_size, key_label_vec };
  auto key = hkdf_expand(suite, shared_secret, key_label, key_size);

  std::string nonce_label_str{ "mls10 ecies nonce" };
  bytes nonce_label_vec{ nonce_label_str.begin(), nonce_label_str.end() };
  ECIESLabel nonce_label{ AESGCM::nonce_size, nonce_label_vec };
  auto nonce =
    hkdf_expand(suite, shared_secret, nonce_label, AESGCM::nonce_size);

  return std::pair<bytes, bytes>(key, nonce);
}

ECIESCiphertext
DHPublicKey::encrypt(const bytes& plaintext) const
{
  auto ephemeral = DHPrivateKey::generate(_suite);
  if (test::DeterministicECIES::enabled()) {
    auto seed = to_bytes();
    seed.insert(seed.end(), plaintext.begin(), plaintext.end());
    ephemeral = DHPrivateKey::derive(_suite, seed);
  }

  auto shared_secret = ephemeral.derive(*this);

  bytes key, nonce;
  std::tie(key, nonce) = derive_ecies_secrets(_suite, shared_secret);

  AESGCM gcm(key, nonce);
  auto content = gcm.encrypt(plaintext);
  return ECIESCiphertext{ ephemeral.public_key(), content };
}

DHPrivateKey
DHPrivateKey::generate(CipherSuite suite)
{
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
DHPrivateKey::derive(CipherSuite suite, const bytes& data)
{
  auto type = ossl_key_type(suite);
  return DHPrivateKey(suite, OpenSSLKey::derive(type, data));
}

bytes
DHPrivateKey::derive(const DHPublicKey& pub) const
{
  if (!_key->can_derive() || !pub._key->can_derive()) {
    throw InvalidParameterError("Inappropriate key(s) for derive");
  }

  EVP_PKEY* priv_pkey = const_cast<EVP_PKEY*>(_key->_key.get());
  EVP_PKEY* pub_pkey = const_cast<EVP_PKEY*>(pub._key->_key.get());

  auto ctx = make_typed_unique(EVP_PKEY_CTX_new(priv_pkey, nullptr));
  if (!ctx.get()) {
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

bytes
DHPrivateKey::decrypt(const ECIESCiphertext& ciphertext) const
{
  auto shared_secret = derive(ciphertext.ephemeral);

  bytes key, nonce;
  std::tie(key, nonce) = derive_ecies_secrets(_suite, shared_secret);

  AESGCM gcm(key, nonce);
  return gcm.decrypt(ciphertext.content);
}

const DHPublicKey&
DHPrivateKey::public_key() const
{
  auto pub = static_cast<DHPublicKey*>(_pub.get());
  return *pub;
}

DHPrivateKey::DHPrivateKey(CipherSuite suite, OpenSSLKey* key)
  : PrivateKey(suite, key)
{
  _pub.reset(new DHPublicKey(suite, key->dup_public()));
}

///
/// SignaturePublicKey and SignaturePrivateKey
///

bool
SignaturePublicKey::verify(const bytes& msg, const bytes& sig) const
{
  if (!_key->can_sign()) {
    throw InvalidParameterError("Inappropriate key for verify");
  }

  auto ctx = make_typed_unique(EVP_MD_CTX_create());
  if (!ctx.get()) {
    throw OpenSSLError::current();
  }

  if (1 !=
      EVP_DigestVerifyInit(ctx.get(), NULL, NULL, NULL, _key->_key.get())) {
    throw OpenSSLError::current();
  }

  auto rv =
    EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(), msg.size());

  return rv == 1;
}

SignaturePrivateKey
SignaturePrivateKey::generate(SignatureScheme scheme)
{
  auto type = ossl_key_type(scheme);
  return SignaturePrivateKey(scheme, OpenSSLKey::generate(type));
}

SignaturePrivateKey
SignaturePrivateKey::derive(SignatureScheme scheme, const bytes& data)
{
  auto type = ossl_key_type(scheme);
  return SignaturePrivateKey(scheme, OpenSSLKey::derive(type, data));
}

bytes
SignaturePrivateKey::sign(const bytes& msg) const
{
  if (!_key->can_sign()) {
    throw InvalidParameterError("Inappropriate key for sign");
  }

  auto ctx = make_typed_unique(EVP_MD_CTX_create());
  if (!ctx.get()) {
    throw OpenSSLError::current();
  }

  if (1 != EVP_DigestSignInit(ctx.get(), NULL, NULL, NULL, _key->_key.get())) {
    throw OpenSSLError::current();
  }

  auto siglen = _key->sig_size();
  bytes sig(_key->sig_size());
  if (1 !=
      EVP_DigestSign(ctx.get(), sig.data(), &siglen, msg.data(), msg.size())) {
    throw OpenSSLError::current();
  }

  sig.resize(siglen);
  return sig;
}

const SignaturePublicKey&
SignaturePrivateKey::public_key() const
{
  auto pub = static_cast<SignaturePublicKey*>(_pub.get());
  return *pub;
}

SignaturePrivateKey::SignaturePrivateKey(SignatureScheme scheme,
                                         OpenSSLKey* key)
  : PrivateKey(scheme, key)
{
  _pub.reset(new SignaturePublicKey(scheme, key->dup_public()));
}

///
/// ECIESCiphertext
///

bool
operator==(const ECIESCiphertext& lhs, const ECIESCiphertext& rhs)
{
  return (lhs.ephemeral == rhs.ephemeral) && (lhs.content == rhs.content);
}

tls::ostream&
operator<<(tls::ostream& out, const ECIESCiphertext& obj)
{
  return out << obj.ephemeral << obj.content;
}

tls::istream&
operator>>(tls::istream& in, ECIESCiphertext& obj)
{
  return in >> obj.ephemeral >> obj.content;
}

} // namespace mls
