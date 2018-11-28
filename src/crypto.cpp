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

#include <iostream>
#include <string>

namespace mls {

///
/// CipherSuite and SignatureScheme
///

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
  X25519,
  Ed25519
};

OpenSSLKeyType
ossl_key_type(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
      return OpenSSLKeyType::P256;
    case CipherSuite::X25519_SHA256_AES128GCM:
      return OpenSSLKeyType::X25519;
  }
}

OpenSSLKeyType
ossl_key_type(SignatureScheme scheme)
{
  switch (scheme) {
    case SignatureScheme::P256_SHA256:
      return OpenSSLKeyType::P256;
    case SignatureScheme::Ed25519_SHA256:
      return OpenSSLKeyType::X25519;
  }
}

struct OpenSSLKey
{
public:
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
  virtual void set_secret(const bytes& data) = 0;
  virtual OpenSSLKey* dup() const = 0;
  virtual OpenSSLKey* dup_public() const = 0;

  // Defined below to make it easier to refer to the more specific
  // key types.
  static OpenSSLKey* create(OpenSSLKeyType type);

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

enum RawKeyType : int
{
  X25519 = EVP_PKEY_X25519,
  Ed25519 = EVP_PKEY_ED25519,
};

struct RawKey : OpenSSLKey
{
public:
  RawKey(RawKeyType type)
    : _type(type)
  {}

  RawKey(RawKeyType type, EVP_PKEY* pkey)
    : OpenSSLKey(pkey)
    , _type(type)
  {}

  virtual OpenSSLKeyType type() const
  {
    switch (_type) {
      case X25519:
        return OpenSSLKeyType::X25519;
      case Ed25519:
        return OpenSSLKeyType::Ed25519;
    }

    throw MissingStateError("Unknown raw key type");
  }
  virtual size_t secret_size() const { return 32; }
  virtual size_t sig_size() const { return 200; }
  virtual bool can_derive() const { return true; }
  virtual bool can_sign() const { return _type == RawKeyType::Ed25519; }

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
    EVP_PKEY* pkey =
      EVP_PKEY_new_raw_public_key(_type, nullptr, data.data(), data.size());
    if (!pkey) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  virtual void set_secret(const bytes& data)
  {
    bytes digest = SHA256Digest(dh_hash_prefix).write(data).digest();

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
      _type, nullptr, digest.data(), digest.size());
    if (!pkey) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  virtual OpenSSLKey* dup() const
  {
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
  RawKeyType _type;
};

struct P256Key : OpenSSLKey
{
public:
  P256Key() = default;

  P256Key(EVP_PKEY* pkey)
    : OpenSSLKey(pkey)
  {}

  virtual OpenSSLKeyType type() const { return OpenSSLKeyType::P256; }
  virtual size_t secret_size() const { return 32; }
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

  virtual void set_secret(const bytes& data)
  {
    bytes digest = SHA256Digest(dh_hash_prefix).write(data).digest();

    EC_KEY* eckey = new_ec_key();

    auto group = EC_KEY_get0_group(eckey);
    auto d =
      make_typed_unique(BN_bin2bn(digest.data(), digest.size(), nullptr));
    auto pt = make_typed_unique(EC_POINT_new(group));
    EC_POINT_mul(group, pt.get(), d.get(), nullptr, nullptr, nullptr);

    EC_KEY_set_private_key(eckey, d.get());
    EC_KEY_set_public_key(eckey, pt.get());

    reset(eckey);
  }

  virtual OpenSSLKey* dup() const
  {
    auto eckey_out = EC_KEY_dup(my_ec_key());
    return new P256Key(eckey_out);
  }

  virtual OpenSSLKey* dup_public() const
  {
    auto eckey = my_ec_key();
    auto group = EC_KEY_get0_group(eckey);
    auto point = EC_KEY_get0_public_key(eckey);

    auto eckey_out = new_ec_key();
    EC_KEY_set_public_key(eckey_out, point);
    return new P256Key(eckey_out);
  }

private:
  static const int _curve_nid = NID_X9_62_prime256v1;

  P256Key(EC_KEY* eckey)
    : OpenSSLKey()
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
    case OpenSSLKeyType::Ed25519:
      return new RawKey(RawKeyType::Ed25519);
    case OpenSSLKeyType::P256:
      return new P256Key;
  }
}

///
/// SHA256Digest
///

SHA256Digest::SHA256Digest()
{
  if (SHA256_Init(&_ctx) != 1) {
    throw OpenSSLError::current();
  }
}

SHA256Digest::SHA256Digest(uint8_t byte)
  : SHA256Digest()
{
  write(byte);
}

SHA256Digest::SHA256Digest(const bytes& data)
  : SHA256Digest()
{
  write(data);
}

SHA256Digest&
SHA256Digest::write(uint8_t byte)
{
  if (SHA256_Update(&_ctx, &byte, 1) != 1) {
    throw OpenSSLError::current();
  }
  return *this;
}

SHA256Digest&
SHA256Digest::write(const bytes& data)
{
  if (SHA256_Update(&_ctx, data.data(), data.size()) != 1) {
    throw OpenSSLError::current();
  }
  return *this;
}

bytes
SHA256Digest::digest()
{
  bytes out(SHA256_DIGEST_LENGTH);
  if (SHA256_Final(out.data(), &_ctx) != 1) {
    throw OpenSSLError::current();
  }
  return out;
}

///
/// HKDF and DeriveSecret
///

static bytes
hmac_sha256(const bytes& key, const bytes& data)
{
  unsigned int size = 0;
  bytes md(SHA256_DIGEST_LENGTH);
  if (!HMAC(EVP_sha256(),
            key.data(),
            key.size(),
            data.data(),
            data.size(),
            md.data(),
            &size)) {
    throw OpenSSLError::current();
  }

  return md;
}

bytes
hkdf_extract(const bytes& salt, const bytes& ikm)
{
  return hmac_sha256(salt, ikm);
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
  State group_state;
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

// XXX: This method requires that size <= Hash.length, so that
// HKDF-Expand(Secret, Label) reduces to:
//
//   HMAC(Secret, Label || 0x01)
template<typename T>
static bytes
hkdf_expand(const bytes& secret, const T& info, size_t size)
{
  auto label = tls::marshal(info);
  label.push_back(0x01);
  auto mac = hmac_sha256(secret, label);
  mac.resize(size);
  return mac;
}

bytes
derive_secret(const bytes& secret,
              const std::string& label,
              const State& state,
              size_t size)
{
  std::string mls_label = std::string("mls10 ") + label;
  bytes vec_label(mls_label.begin(), mls_label.end());

  HKDFLabel label_str{ uint16_t(size), vec_label, state };
  return hkdf_expand(secret, label_str, size);
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

///
/// PublicKey
///

PublicKey::PublicKey()
  : _key(nullptr)
{}

PublicKey::PublicKey(OpenSSLKeyType type)
  : _type(type)
  , _activated(true)
  , _key(OpenSSLKey::create(type))
{}

PublicKey::PublicKey(const PublicKey& other)
  : _type(other._type)
  , _activated(true)
  , _key(other._key->dup())
{}

PublicKey::PublicKey(PublicKey&& other)
  : _type(other._type)
  , _activated(true)
  , _key(std::move(other._key))
{}

PublicKey::PublicKey(OpenSSLKeyType type, const bytes& data)
  : _type(type)
  , _activated(true)
  , _key(OpenSSLKey::create(type))
{
  reset(data);
}

PublicKey::PublicKey(OpenSSLKey* key)
  : _type(key->type())
  , _activated(true)
  , _key(key)
{}

PublicKey&
PublicKey::operator=(const PublicKey& other)
{
  if (&other != this) {
    _type = other._type;
    _activated = other._activated;
    if (other._key) {
      _key.reset(other._key->dup());
    }
  }
  return *this;
}

PublicKey&
PublicKey::operator=(PublicKey&& other)
{
  if (&other != this) {
    _type = other._type;
    _activated = other._activated;
    _key = std::move(other._key);
  }
  return *this;
}

bool
PublicKey::operator==(const PublicKey& other) const
{
  if (!_key || !other._key) {
    return false;
  }

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

void
PublicKey::activate_base(OpenSSLKeyType type)
{
  _key.reset(OpenSSLKey::create(type));
  reset(_raw);
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
  in >> obj._raw;
  if (obj._activated) {
    obj.reset(obj._raw);
  }
  return in;
}

///
/// PrivateKey
///

PrivateKey::PrivateKey(const PrivateKey& other)
  : _key(other._key->dup())
  , _pub(new PublicKey(*other._pub))
{}

PrivateKey::PrivateKey(PrivateKey&& other)
  : _key(std::move(other._key))
  , _pub(std::move(other._pub))
{}

PrivateKey&
PrivateKey::operator=(const PrivateKey& other)
{
  if (this != &other) {
    _key.reset(other._key->dup());
    _pub.reset(new PublicKey(*other._pub));
  }
  return *this;
}

PrivateKey&
PrivateKey::operator=(PrivateKey&& other)
{
  if (this != &other) {
    _key = std::move(other._key);
    _pub = std::move(other._pub);
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

PrivateKey::PrivateKey(OpenSSLKey* key)
  : _key(key)
  , _pub(nullptr)
{
  auto base = OpenSSLKey::create(key->type());
  auto pub = new PublicKey(base);
  _pub.reset(pub);
}

///
/// DHPublicKey and DHPrivateKey
///

DHPublicKey::DHPublicKey(CipherSuite suite)
  : PublicKey(ossl_key_type(suite))
  , _suite(suite)
{}

DHPublicKey::DHPublicKey(CipherSuite suite, const bytes& data)
  : PublicKey(ossl_key_type(suite), data)
  , _suite(suite)
{}

void
DHPublicKey::activate(CipherSuite suite)
{
  activate_base(ossl_key_type(suite));
}

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
derive_ecies_secrets(const bytes& shared_secret)
{
  std::string key_label_str{ "mls10 ecies key" };
  bytes key_label_vec{ key_label_str.begin(), key_label_str.end() };
  ECIESLabel key_label{ AESGCM::key_size_128, key_label_vec };
  auto key = hkdf_expand(shared_secret, key_label, AESGCM::key_size_128);

  std::string nonce_label_str{ "mls10 ecies nonce" };
  bytes nonce_label_vec{ nonce_label_str.begin(), nonce_label_str.end() };
  ECIESLabel nonce_label{ AESGCM::nonce_size, nonce_label_vec };
  auto nonce = hkdf_expand(shared_secret, nonce_label, AESGCM::nonce_size);

  return std::pair<bytes, bytes>(key, nonce);
}

ECIESCiphertext
DHPublicKey::encrypt(const bytes& plaintext) const
{
  auto ephemeral = DHPrivateKey::generate(_suite);
  auto shared_secret = ephemeral.derive(*this);

  bytes key, nonce;
  std::tie(key, nonce) = derive_ecies_secrets(shared_secret);

  AESGCM gcm(key, nonce);
  auto content = gcm.encrypt(plaintext);
  return ECIESCiphertext{ ephemeral.public_key(), content };
}

DHPrivateKey
DHPrivateKey::generate(CipherSuite suite)
{
  auto type = ossl_key_type(suite);
  DHPrivateKey key(OpenSSLKey::create(type));
  key._key->generate();
  key._pub->reset(key._key->dup_public());
  return key;
}

DHPrivateKey
DHPrivateKey::derive(CipherSuite suite, const bytes& seed)
{
  auto type = ossl_key_type(suite);
  DHPrivateKey key(OpenSSLKey::create(type));
  key._key->set_secret(seed);
  key._pub->reset(key._key->dup_public());
  return key;
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

const DHPublicKey&
DHPrivateKey::public_key() const
{
  auto pub = static_cast<DHPublicKey*>(_pub.get());
  return *pub;
}

bytes
DHPrivateKey::decrypt(const ECIESCiphertext& ciphertext) const
{
  auto shared_secret = derive(ciphertext.ephemeral);

  bytes key, nonce;
  std::tie(key, nonce) = derive_ecies_secrets(shared_secret);

  AESGCM gcm(key, nonce);
  return gcm.decrypt(ciphertext.content);
}

///
/// SignaturePublicKey and SignaturePrivateKey
///

SignaturePublicKey::SignaturePublicKey(SignatureScheme scheme)
  : PublicKey(ossl_key_type(scheme))
{}

SignaturePublicKey::SignaturePublicKey(SignatureScheme scheme,
                                       const bytes& data)
  : PublicKey(ossl_key_type(scheme), data)
{}

void
SignaturePublicKey::activate(SignatureScheme scheme)
{
  activate_base(ossl_key_type(scheme));
}

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
  SignaturePrivateKey key(OpenSSLKey::create(type));
  key._key->generate();
  key._pub->reset(key._key->dup_public());
  return key;
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

///
/// ECIESCiphertext
///

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
