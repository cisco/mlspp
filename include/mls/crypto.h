#pragma once

#include <hpke/digest.h>
#include <hpke/hpke.h>
#include <hpke/random.h>
#include <hpke/signature.h>
#include <mls/common.h>
#include <tls/tls_syntax.h>

#include <vector>

namespace mls {

/// Signature Code points, borrowed from RFC 8446
enum struct SignatureScheme : uint16_t
{
  ecdsa_secp256r1_sha256 = 0x0403,
  ecdsa_secp384r1_sha384 = 0x0805,
  ecdsa_secp521r1_sha512 = 0x0603,
  ed25519 = 0x0807,
  ed448 = 0x0808,
  rsa_pkcs1_sha256 = 0x0401,
};

SignatureScheme
tls_signature_scheme(hpke::Signature::ID id);

/// Cipher suites

struct KeyAndNonce
{
  bytes key;
  bytes nonce;
};

// opaque HashReference[16];
// HashReference KeyPackageRef;
// HashReference LeafNodeRef;
// HashReference ProposalRef;
using HashReference = std::array<uint8_t, 16>;
using KeyPackageRef = HashReference;
using LeafNodeRef = HashReference;
using ProposalRef = HashReference;

struct CipherSuite
{
  enum struct ID : uint16_t
  {
    unknown = 0x0000,
    X25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    P256_AES128GCM_SHA256_P256 = 0x0002,
    X25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    X448_AES256GCM_SHA512_Ed448 = 0x0004,
    P521_AES256GCM_SHA512_P521 = 0x0005,
    X448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
  };

  CipherSuite();
  CipherSuite(ID id_in);

  ID cipher_suite() const { return id; }
  SignatureScheme signature_scheme() const;

  size_t secret_size() const { return get().digest.hash_size; }
  size_t key_size() const { return get().hpke.aead.key_size; }
  size_t nonce_size() const { return get().hpke.aead.nonce_size; }

  bytes zero() const { return bytes(secret_size(), 0); }
  const hpke::HPKE& hpke() const { return get().hpke; }
  const hpke::Digest& digest() const { return get().digest; }
  const hpke::Signature& sig() const { return get().sig; }

  bytes expand_with_label(const bytes& secret,
                          const std::string& label,
                          const bytes& context,
                          size_t length) const;
  bytes derive_secret(const bytes& secret, const std::string& label) const;

  template<typename T>
  HashReference ref(const T& val) const
  {
    auto ref = HashReference{};
    auto marshaled = tls::marshal(val);
    auto extracted = hpke().kdf.extract({}, marshaled);
    auto expanded =
      hpke().kdf.expand(extracted, reference_label<T>(), ref.size());
    std::copy(expanded.begin(), expanded.end(), ref.begin());
    return ref;
  }

  TLS_SERIALIZABLE(id)

private:
  ID id;

  struct Ciphers
  {
    hpke::HPKE hpke;
    const hpke::Digest& digest;
    const hpke::Signature& sig;
  };

  const Ciphers& get() const;

  template<typename T>
  static const bytes& reference_label();
};

extern const std::array<CipherSuite::ID, 6> all_supported_suites;

// Utilities
using hpke::random_bytes;

bool
constant_time_eq(const bytes& lhs, const bytes& rhs);

// HPKE Keys
struct HPKECiphertext
{
  bytes kem_output;
  bytes ciphertext;

  TLS_SERIALIZABLE(kem_output, ciphertext)
};

struct HPKEPublicKey
{
  bytes data;

  HPKECiphertext encrypt(CipherSuite suite,
                         const bytes& info,
                         const bytes& aad,
                         const bytes& pt) const;

  std::tuple<bytes, bytes> do_export(CipherSuite suite,
                                     const bytes& info,
                                     const std::string& label,
                                     size_t size) const;

  TLS_SERIALIZABLE(data)
};

struct HPKEPrivateKey
{
  static HPKEPrivateKey generate(CipherSuite suite);
  static HPKEPrivateKey parse(CipherSuite suite, const bytes& data);
  static HPKEPrivateKey derive(CipherSuite suite, const bytes& secret);

  HPKEPrivateKey() = default;

  bytes data;
  HPKEPublicKey public_key;

  bytes decrypt(CipherSuite suite,
                const bytes& info,
                const bytes& aad,
                const HPKECiphertext& ct) const;

  bytes do_export(CipherSuite suite,
                  const bytes& info,
                  const bytes& kem_output,
                  const std::string& label,
                  size_t size) const;

  TLS_SERIALIZABLE(data, public_key)

private:
  HPKEPrivateKey(bytes priv_data, bytes pub_data);
};

// Signature Keys
struct SignaturePublicKey
{
  bytes data;

  bool verify(const CipherSuite& suite,
              const bytes& message,
              const bytes& signature) const;

  TLS_SERIALIZABLE(data)
};

struct SignaturePrivateKey
{
  static SignaturePrivateKey generate(CipherSuite suite);
  static SignaturePrivateKey parse(CipherSuite suite, const bytes& data);
  static SignaturePrivateKey derive(CipherSuite suite, const bytes& secret);

  bytes data;
  SignaturePublicKey public_key;

  bytes sign(const CipherSuite& suite, const bytes& message) const;

  TLS_SERIALIZABLE(data, public_key)

private:
  SignaturePrivateKey(bytes priv_data, bytes pub_data);
};

} // namespace mls
