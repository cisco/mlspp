#include "crypto.h"
#include "common.h"
#include "openssl/ecdh.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/hmac.h"
#include "openssl/obj_mac.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "state.h"

#include <string>

#define DH_CURVE NID_X9_62_prime256v1
#define SIG_CURVE NID_X9_62_prime256v1
#define DH_OUTPUT_BYTES SHA256_DIGEST_LENGTH

namespace mls {

OpenSSLError
OpenSSLError::current()
{
  unsigned long code = ERR_get_error();
  return OpenSSLError(ERR_error_string(code, nullptr));
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

bytes
derive_secret(const bytes& secret, const std::string& label, const State& state)
{
  std::string mls_label = std::string("mls10 ") + label;
  bytes vec_label(mls_label.begin(), mls_label.end());

  HKDFLabel label_str{ SHA256_DIGEST_LENGTH, vec_label, state };

  auto hkdf_label = tls::marshal(label_str);

  // We always extract Hash.length octets of output, in which case,
  // HKDF-Expand(Secret, Label) reduces to:
  //
  //   HMAC(secret, Label || 0x01)
  //
  hkdf_label.push_back(0x01);
  return hmac_sha256(secret, hkdf_label);
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

DHPublicKey::DHPublicKey(const DHPublicKey& other)
  : _key(other._key)
{}

DHPublicKey::DHPublicKey(DHPublicKey&& other)
  : _key(std::move(other._key))
{}

DHPublicKey::DHPublicKey(const bytes& data)
{
  reset(data);
}

DHPublicKey&
DHPublicKey::operator=(const DHPublicKey& other)
{
  if (&other != this) {
    _key = other._key;
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
  if (_key.get() == nullptr && other._key.get() == nullptr) {
    return true;
  } else if (_key.get() == nullptr) {
    return false;
  } else if (other._key.get() == nullptr) {
    return false;
  }

  // Raw pointers OK here because get0 methods return pointers to
  // memory managed by the EC_KEY.
  const EC_GROUP* group = EC_KEY_get0_group(_key.get());
  const EC_POINT* lhs = EC_KEY_get0_public_key(_key.get());
  const EC_POINT* rhs = EC_KEY_get0_public_key(other._key.get());
  return (EC_POINT_cmp(group, lhs, rhs, nullptr) == 0);
}

bool
DHPublicKey::operator!=(const DHPublicKey& other) const
{
  return !(*this == other);
}

bytes
DHPublicKey::to_bytes() const
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
DHPublicKey::reset(const bytes& data)
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

ECIESCiphertext
DHPublicKey::encrypt(const bytes& plaintext) const
{
  auto ephemeral = DHPrivateKey::generate();
  auto zz = ephemeral.derive(*this);

  auto key = SHA256Digest(0x00).write(zz).digest();
  key.resize(AESGCM::key_size_128);
  auto nonce = SHA256Digest(0x01).write(zz).digest();
  nonce.resize(AESGCM::nonce_size);

  AESGCM gcm(key, nonce);
  auto content = gcm.encrypt(plaintext);
  return ECIESCiphertext{ ephemeral.public_key(), content };
}

DHPublicKey::DHPublicKey(const EC_POINT* pt)
  : _key(EC_KEY_new_by_curve_name(DH_CURVE))
{
  if (EC_KEY_set_public_key(_key.get(), pt) != 1) {
    throw OpenSSLError::current();
  }
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
  // Raw pointer is OK here because DHPrivateKey takes over
  // management of the memory referenced by key.
  EC_KEY* key = EC_KEY_new_by_curve_name(DH_CURVE);
  if (EC_KEY_generate_key(key) != 1) {
    throw OpenSSLError::current();
  }

  return DHPrivateKey(key);
}

DHPrivateKey
DHPrivateKey::derive(const bytes& seed)
{
  bytes digest = SHA256Digest(dh_hash_prefix).write(seed).digest();

  Scoped<BIGNUM> d = BN_bin2bn(digest.data(), digest.size(), nullptr);
  Scoped<EC_GROUP> group = defaultECGroup();
  Scoped<EC_POINT> pt = EC_POINT_new(group.get());
  EC_POINT_mul(group.get(), pt.get(), d.get(), nullptr, nullptr, nullptr);

  EC_KEY* key = EC_KEY_new_by_curve_name(DH_CURVE);
  EC_KEY_set_group(key, group.get());
  EC_KEY_set_private_key(key, d.get());
  EC_KEY_set_public_key(key, pt.get());

  return DHPrivateKey(key);
}

DHPrivateKey::DHPrivateKey(const DHPrivateKey& other)
  : _key(other._key)
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
    _key = other._key;
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
  // Raw pointers here are OK because "get0" methods return pointers
  // to memory owned by _key.
  const BIGNUM* d1 = EC_KEY_get0_private_key(_key.get());
  const BIGNUM* d2 = EC_KEY_get0_private_key(other._key.get());
  const EC_POINT* p1 = EC_KEY_get0_public_key(_key.get());
  const EC_POINT* p2 = EC_KEY_get0_public_key(other._key.get());
  const EC_GROUP* group = EC_KEY_get0_group(_key.get());

  auto out =
    (BN_cmp(d1, d2) == 0) && (EC_POINT_cmp(group, p1, p2, nullptr) == 0);
  return out;
}

bool
DHPrivateKey::operator!=(const DHPrivateKey& other) const
{
  return !(*this == other);
}

bytes
DHPrivateKey::derive(const DHPublicKey& pub) const
{
  bytes out(DH_OUTPUT_BYTES);
  // ECDH_compute_key shouldn't modify the private key, but it's
  // missing the const modifier.
  EC_KEY* priv_key = const_cast<EC_KEY*>(_key.get());
  const EC_POINT* pub_key = EC_KEY_get0_public_key(pub._key.get());
  ECDH_compute_key(out.data(), out.size(), pub_key, priv_key, nullptr);
  return out;
}

DHPublicKey
DHPrivateKey::public_key() const
{
  return _pub;
}

DHPrivateKey::DHPrivateKey(EC_KEY* key)
  : _key(key)
  , _pub(EC_KEY_get0_public_key(key))
{}

bytes
DHPrivateKey::decrypt(const ECIESCiphertext& ciphertext) const
{
  auto zz = derive(ciphertext.ephemeral);

  auto key = SHA256Digest(0x00).write(zz).digest();
  key.resize(AESGCM::key_size_128);
  auto nonce = SHA256Digest(0x01).write(zz).digest();
  nonce.resize(AESGCM::nonce_size);

  AESGCM gcm(key, nonce);
  return gcm.decrypt(ciphertext.content);
}

tls::ostream&
operator<<(tls::ostream& out, const DHPrivateKey& obj)
{
  const BIGNUM* dN = EC_KEY_get0_private_key(obj._key.get());
  int len = BN_num_bytes(dN);

  tls::opaque<1> d(len);
  BN_bn2bin(dN, d.data());

  tls::opaque<1> pub = obj._pub.to_bytes();

  return out << d << pub;
}

tls::istream&
operator>>(tls::istream& in, DHPrivateKey& obj)
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

  obj = DHPrivateKey(key.release());
  return in;
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
