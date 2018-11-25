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

#define DH_CURVE NID_X9_62_prime256v1
#define SIG_CURVE NID_X9_62_prime256v1
#define DH_OUTPUT_BYTES SHA256_DIGEST_LENGTH

namespace mls {

// Things we need to do per-key-type:
// * TypedDup
// * to_bytes
// * from_bytes
// * construct from data

///
/// OpenSSLKey
///
/// This is used to encapsulate the operations required for
/// different types of points, with a slightly cleaner interface
/// than OpenSSL's EVP interface.
///

bool
operator==(const OpenSSLKey& lhs, const OpenSSLKey& rhs)
{
  // If one pointer is null and the other is not, then the two keys
  // are not equal
  if (!!lhs._key.get() != !!rhs._key.get()) {
    return false;
  }

  // If both pointers are null, then the two keys are equal.
  if (!lhs._key.get()) {
    return true;
  }

  auto cmp = EVP_PKEY_cmp(lhs._key.get(), rhs._key.get());
  return cmp == 1;
}

bytes
OpenSSLKey::derive(const OpenSSLKey& pub)
{
  if (!can_derive() || !pub.can_derive()) {
    throw InvalidParameterError("Inappropriate key(s) for derive");
  }

  EVP_PKEY* priv_pkey = const_cast<EVP_PKEY*>(_key.get());
  EVP_PKEY* pub_pkey = const_cast<EVP_PKEY*>(pub._key.get());

  Scoped<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(priv_pkey, nullptr));
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

struct X25519Key : OpenSSLKey
{
public:
  X25519Key() = default;

  X25519Key(EVP_PKEY* pkey)
    : OpenSSLKey(pkey)
  {}

  virtual size_t secret_size() const { return 32; }
  virtual bool can_derive() const { return true; }

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

  virtual void set_private(const bytes& data)
  {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, data.data(), data.size());
    if (!pkey) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  virtual void set_public(const bytes& data)
  {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, data.data(), data.size());
    if (!pkey) {
      throw OpenSSLError::current();
    }

    _key.reset(pkey);
  }

  virtual void set_secret(const bytes& data)
  {
    bytes digest = SHA256Digest(dh_hash_prefix).write(data).digest();

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, digest.data(), digest.size());
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
      auto pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, raw.data(), raw.size());
      if (!pkey) {
        throw OpenSSLError::current();
      }

      return new X25519Key(pkey);
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

    auto pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, raw.data(), raw.size());
    if (!pkey) {
      throw OpenSSLError::current();
    }

    return new X25519Key(pkey);
  }
};

///
/// OpenSSLError
///

OpenSSLError
OpenSSLError::current()
{
  unsigned long code = ERR_get_error();
  return OpenSSLError(ERR_error_string(code, nullptr));
}

template<>
void
TypedDelete(EVP_PKEY* ptr)
{
  EVP_PKEY_free(ptr);
}

template<>
void
TypedDelete(EVP_PKEY_CTX* ptr)
{
  EVP_PKEY_CTX_free(ptr);
}

template<>
void
TypedDelete(EC_KEY* ptr)
{
  EC_KEY_free(ptr);
}

template<>
void
TypedDelete(EC_GROUP* ptr)
{
  EC_GROUP_free(ptr);
}

template<>
void
TypedDelete(EC_POINT* ptr)
{
  EC_POINT_free(ptr);
}

template<>
void
TypedDelete(BIGNUM* ptr)
{
  BN_free(ptr);
}

template<>
void
TypedDelete(EVP_CIPHER_CTX* ptr)
{
  EVP_CIPHER_CTX_free(ptr);
}

template<>
EC_KEY*
TypedDup(EC_KEY* ptr)
{
  return EC_KEY_dup(ptr);
}

template<>
EC_GROUP*
TypedDup(EC_GROUP* ptr)
{
  return EC_GROUP_dup(ptr);
}

template<>
EVP_PKEY*
TypedDup(EVP_PKEY* ptr)
{
  // TODO fork on key type

  size_t raw_len = 0;
  if (1 != EVP_PKEY_get_raw_private_key(ptr, nullptr, &raw_len)) {
    throw OpenSSLError::current();
  }

  // The actual key fetch will fail if `ptr` represents a public key
  bytes raw(raw_len);
  uint8_t* data_ptr = raw.data();
  int rv = EVP_PKEY_get_raw_private_key(ptr, data_ptr, &raw_len);
  if (rv == 1) {
    return EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, raw.data(), raw.size());
  }

  if (1 != EVP_PKEY_get_raw_public_key(ptr, nullptr, &raw_len)) {
    throw OpenSSLError::current();
  }

  raw.resize(raw_len);
  data_ptr = raw.data();
  if (1 != EVP_PKEY_get_raw_public_key(ptr, data_ptr, &raw_len)) {
    throw OpenSSLError::current();
  }

  return EVP_PKEY_new_raw_public_key(
    EVP_PKEY_X25519, nullptr, raw.data(), raw.size());
}

Scoped<EC_GROUP>
defaultECGroup()
{
  Scoped<EC_GROUP> group = EC_GROUP_new_by_curve_name(DH_CURVE);
  if (group.get() == nullptr) {
    throw OpenSSLError::current();
  }
  return group;
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
  Scoped<EVP_CIPHER_CTX> ctx = EVP_CIPHER_CTX_new();
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

  Scoped<EVP_CIPHER_CTX> ctx = EVP_CIPHER_CTX_new();
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
/// DHPublicKey
///

DHPublicKey::DHPublicKey()
  : _key(new X25519Key)
{}

DHPublicKey::DHPublicKey(const DHPublicKey& other)
  : _key(other._key->dup())
{}

DHPublicKey::DHPublicKey(DHPublicKey&& other)
  : _key(std::move(other._key))
{}

DHPublicKey::DHPublicKey(const bytes& data)
  : _key(new X25519Key)
{
  reset(data);
}

DHPublicKey&
DHPublicKey::operator=(const DHPublicKey& other)
{
  if (&other != this) {
    _key.reset(other._key->dup());
  }
  return *this;
}

DHPublicKey&
DHPublicKey::operator=(DHPublicKey&& other)
{
  if (&other != this) {
    _key = std::move(other._key);
  }
  return *this;
}

bool
DHPublicKey::operator==(const DHPublicKey& other) const
{
  return *_key == *other._key;
}

bool
DHPublicKey::operator!=(const DHPublicKey& other) const
{
  return !(*this == other);
}

bytes
DHPublicKey::to_bytes() const
{
  return _key->marshal();
}

void
DHPublicKey::reset(const bytes& data)
{
  _key->set_public(data);
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
  HKDFLabel key_label{ AESGCM::key_size_128, key_label_vec };
  auto key = hkdf_expand(shared_secret, key_label, AESGCM::key_size_128);

  std::string nonce_label_str{ "mls10 ecies nonce" };
  bytes nonce_label_vec{ nonce_label_str.begin(), nonce_label_str.end() };
  HKDFLabel nonce_label{ AESGCM::nonce_size, nonce_label_vec };
  auto nonce = hkdf_expand(shared_secret, nonce_label, AESGCM::nonce_size);

  return std::pair<bytes, bytes>(key, nonce);
}

ECIESCiphertext
DHPublicKey::encrypt(const bytes& plaintext) const
{
  auto ephemeral = DHPrivateKey::generate();
  auto shared_secret = ephemeral.derive(*this);

  bytes key, nonce;
  std::tie(key, nonce) = derive_ecies_secrets(shared_secret);

  AESGCM gcm(key, nonce);
  auto content = gcm.encrypt(plaintext);
  return ECIESCiphertext{ ephemeral.public_key(), content };
}

tls::ostream&
operator<<(tls::ostream& out, const DHPublicKey& obj)
{
  tls::vector<uint8_t, 2> data = obj.to_bytes();
  return out << data;
}

tls::istream&
operator>>(tls::istream& in, DHPublicKey& obj)
{
  tls::vector<uint8_t, 2> data;
  in >> data;
  obj.reset(data);
  return in;
}

///
/// DHPrivateKey
///

DHPrivateKey
DHPrivateKey::generate()
{
  return derive(random_bytes(32));
}

DHPrivateKey
DHPrivateKey::derive(const bytes& seed)
{
  DHPrivateKey key;
  key._key.reset(new X25519Key);
  key._key->set_secret(seed);
  key._pub._key.reset(key._key->dup_public());
  return key;
}

DHPrivateKey::DHPrivateKey(const DHPrivateKey& other)
  : _key(other._key->dup())
  , _pub(other._pub)
{}

DHPrivateKey::DHPrivateKey(DHPrivateKey&& other)
  : _key(std::move(other._key))
  , _pub(std::move(other._pub))
{}

DHPrivateKey&
DHPrivateKey::operator=(const DHPrivateKey& other)
{
  if (this != &other) {
    _key.reset(other._key->dup());
    _pub = other._pub;
  }
  return *this;
}

DHPrivateKey&
DHPrivateKey::operator=(DHPrivateKey&& other)
{
  if (this != &other) {
    _key = std::move(other._key);
    _pub = std::move(other._pub);
  }
  return *this;
}

bool
DHPrivateKey::operator==(const DHPrivateKey& other) const
{
  return _key == other._key;
}

bool
DHPrivateKey::operator!=(const DHPrivateKey& other) const
{
  return !(*this == other);
}

bytes
DHPrivateKey::derive(const DHPublicKey& pub) const
{
  return _key->derive(*pub._key);
}

const DHPublicKey&
DHPrivateKey::public_key() const
{
  return _pub;
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

///
/// SignaturePublicKey
///

SignaturePublicKey::SignaturePublicKey(const SignaturePublicKey& other)
  : _key(other._key)
{}

SignaturePublicKey::SignaturePublicKey(SignaturePublicKey&& other)
  : _key(std::move(other._key))
{}

SignaturePublicKey::SignaturePublicKey(const bytes& data)
{
  reset(data);
}

SignaturePublicKey&
SignaturePublicKey::operator=(const SignaturePublicKey& other)
{
  if (&other != this) {
    _key = other._key;
  }
  return *this;
}

SignaturePublicKey&
SignaturePublicKey::operator=(SignaturePublicKey&& other)
{
  if (&other != this) {
    _key = std::move(other._key);
  }
  return *this;
}

bool
SignaturePublicKey::operator==(const SignaturePublicKey& other) const
{
  // Raw pointers OK here because get0 methods return pointers to
  // memory managed by the EC_KEY.
  const EC_GROUP* group = EC_KEY_get0_group(_key.get());
  const EC_POINT* lhs = EC_KEY_get0_public_key(_key.get());
  const EC_POINT* rhs = EC_KEY_get0_public_key(other._key.get());
  return (EC_POINT_cmp(group, lhs, rhs, nullptr) == 0);
}

bool
SignaturePublicKey::operator!=(const SignaturePublicKey& other) const
{
  return !(*this == other);
}

bool
SignaturePublicKey::verify(const bytes& message, const bytes& signature) const
{
  EC_KEY* temp_key = const_cast<EC_KEY*>(_key.get());
  auto digest = SHA256Digest(message).digest();
  int rv = ECDSA_verify(0,
                        digest.data(),
                        digest.size(),
                        signature.data(),
                        signature.size(),
                        temp_key);
  if (rv < 0) {
    throw OpenSSLError::current();
  }

  return (rv == 1);
}

bytes
SignaturePublicKey::to_bytes() const
{
  EC_KEY* temp_key = const_cast<EC_KEY*>(_key.get());
  int len = i2o_ECPublicKey(temp_key, nullptr);
  if (len == 0) {
    // Technically, this is not necessarily an error, but in
    // practice it always will be.
    throw OpenSSLError::current();
  }

  bytes out(len);
  unsigned char* data = out.data();
  if (i2o_ECPublicKey(temp_key, &data) == 0) {
    throw OpenSSLError::current();
  }

  return out;
}

void
SignaturePublicKey::reset(const bytes& data)
{
  EC_KEY* key = EC_KEY_new_by_curve_name(DH_CURVE);
  if (!key) {
    throw OpenSSLError::current();
  }

  const uint8_t* ptr = data.data();
  if (!o2i_ECPublicKey(&key, &ptr, data.size())) {
    throw OpenSSLError::current();
  }

  _key = key;
}

SignaturePublicKey::SignaturePublicKey(const EC_POINT* pt)
  : _key(EC_KEY_new_by_curve_name(SIG_CURVE))
{
  if (EC_KEY_set_public_key(_key.get(), pt) != 1) {
    throw OpenSSLError::current();
  }
}

tls::ostream&
operator<<(tls::ostream& out, const SignaturePublicKey& obj)
{
  tls::vector<uint8_t, 2> data = obj.to_bytes();
  return out << data;
}

tls::istream&
operator>>(tls::istream& in, SignaturePublicKey& obj)
{
  tls::vector<uint8_t, 2> data;
  in >> data;
  obj.reset(data);
  return in;
}

///
/// SignaturePrivateKey
///

SignaturePrivateKey
SignaturePrivateKey::generate()
{
  // Raw pointer is OK here because SignaturePrivateKey takes over
  // management of the memory referenced by key.
  EC_KEY* key = EC_KEY_new_by_curve_name(SIG_CURVE);
  if (EC_KEY_generate_key(key) != 1) {
    throw OpenSSLError::current();
  }

  return SignaturePrivateKey(key);
}

SignaturePrivateKey::SignaturePrivateKey(const SignaturePrivateKey& other)
  : _key(other._key)
  , _pub(other._pub)
{}

SignaturePrivateKey::SignaturePrivateKey(SignaturePrivateKey&& other)
  : _key(std::move(other._key))
  , _pub(std::move(other._pub))
{}

SignaturePrivateKey&
SignaturePrivateKey::operator=(const SignaturePrivateKey& other)
{
  if (this != &other) {
    _key = other._key;
    _pub = other._pub;
  }
  return *this;
}

SignaturePrivateKey&
SignaturePrivateKey::operator=(SignaturePrivateKey&& other)
{
  if (this != &other) {
    _key = std::move(other._key);
    _pub = std::move(other._pub);
  }
  return *this;
}

bytes
point_data(const EC_KEY* key)
{
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  const EC_POINT* pt = EC_KEY_get0_public_key(key);
  const EC_GROUP* group = EC_KEY_get0_group(key);

  bytes data;
  int len = 0;
  len = EC_POINT_point2oct(group, pt, form, nullptr, len, nullptr);
  data.resize(len);
  EC_POINT_point2oct(group, pt, form, data.data(), len, nullptr);
  return data;
}

bool
SignaturePrivateKey::operator==(const SignaturePrivateKey& other) const
{
  // Raw pointers here are OK because "get0" methods return pointers
  // to memory owned by _key.
  const BIGNUM* d1 = EC_KEY_get0_private_key(_key.get());
  const BIGNUM* d2 = EC_KEY_get0_private_key(other._key.get());
  const EC_POINT* p1 = EC_KEY_get0_public_key(_key.get());
  const EC_POINT* p2 = EC_KEY_get0_public_key(other._key.get());
  const EC_GROUP* group = EC_KEY_get0_group(_key.get());

  auto deq = BN_cmp(d1, d2);
  auto peq = EC_POINT_cmp(group, p1, p2, nullptr);
  if (peq == -1) {
    throw OpenSSLError::current();
  }

  auto out = (deq == 0) && (peq == 0) && (_pub == other._pub);
  return out;
}

bool
SignaturePrivateKey::operator!=(const SignaturePrivateKey& other) const
{
  return !(*this == other);
}

bytes
SignaturePrivateKey::sign(const bytes& message) const
{
  EC_KEY* temp_key = const_cast<EC_KEY*>(_key.get());
  bytes sig(ECDSA_size(_key.get()));
  auto digest = SHA256Digest(message).digest();

  unsigned int siglen = 0;
  int rv =
    ECDSA_sign(0, digest.data(), digest.size(), sig.data(), &siglen, temp_key);
  if (rv != 1) {
    throw OpenSSLError::current();
  }

  sig.resize(siglen);
  return sig;
}

SignaturePublicKey
SignaturePrivateKey::public_key() const
{
  return _pub;
}

SignaturePrivateKey::SignaturePrivateKey(EC_KEY* key)
  : _key(key)
  , _pub(EC_KEY_get0_public_key(key))
{}

tls::ostream&
operator<<(tls::ostream& out, const SignaturePrivateKey& obj)
{
  const BIGNUM* dN = EC_KEY_get0_private_key(obj._key.get());
  int len = BN_num_bytes(dN);

  tls::opaque<1> d(len);
  BN_bn2bin(dN, d.data());

  tls::opaque<1> pub = obj._pub.to_bytes();

  return out << d << pub;
}

tls::istream&
operator>>(tls::istream& in, SignaturePrivateKey& obj)
{
  tls::opaque<1> d, pub;
  in >> d >> pub;

  const uint8_t* ptr = pub.data();
  Scoped<EC_KEY> key = EC_KEY_new_by_curve_name(DH_CURVE);
  EC_KEY* temp = key.get();
  if (!o2i_ECPublicKey(&temp, &ptr, pub.size())) {
    throw OpenSSLError::current();
  }

  Scoped<EC_GROUP> group = defaultECGroup();
  EC_KEY_set_group(key.get(), group.get());

  Scoped<BIGNUM> dN = BN_bin2bn(d.data(), d.size(), nullptr);
  EC_KEY_set_private_key(key.get(), dN.get());

  obj = SignaturePrivateKey(key.release());
  return in;
}

} // namespace mls
