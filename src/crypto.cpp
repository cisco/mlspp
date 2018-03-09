#include "crypto.h"
#include "common.h"
#include "openssl/ecdh.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/hmac.h"
#include "openssl/obj_mac.h"
#include "openssl/sha.h"

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
//     opaque label<7..255> = "mls10 " + Label;
//     opaque group_id<0..2^16-1> = ID;
//     uint64 epoch = Epoch;
//     opaque message<1..2^16-1> = Msg
// } HkdfLabel;
struct HKDFLabel
{
  uint16_t length;
  tls::opaque<1, 7> label;
  tls::opaque<2> group_id;
  epoch_t epoch;
  tls::opaque<2, 1> message;
};

tls::ostream&
operator<<(tls::ostream& out, const HKDFLabel& obj)
{
  return out << obj.length << obj.label << obj.group_id << obj.epoch
             << obj.message;
}

bytes
derive_secret(const bytes& secret,
              const std::string& label,
              const bytes& group_id,
              const epoch_t& epoch,
              const bytes& message)
{
  std::string mls_label = std::string("mls10 ") + label;
  bytes vec_label(mls_label.begin(), mls_label.end());

  HKDFLabel label_str{
    SHA256_DIGEST_LENGTH, vec_label, group_id, epoch, message
  };

  tls::ostream writer;
  writer << label_str;
  auto hkdf_label = writer.bytes();

  // We always extract Hash.length octets of output, in which case,
  // HKDF-Expand(Secret, Label) reduces to:
  //
  //   HMAC(secret, Label || 0x01)
  //
  hkdf_label.push_back(0x01);
  return hmac_sha256(secret, hkdf_label);
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

DHPublicKey::DHPublicKey() {}

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
DHPrivateKey::derive(DHPublicKey pub) const
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

SignaturePublicKey::SignaturePublicKey() {}

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

  auto out =
    (BN_cmp(d1, d2) == 0) && (EC_POINT_cmp(group, p1, p2, nullptr) == 0);
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

} // namespace mls
