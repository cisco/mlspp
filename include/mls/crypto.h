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

// opaque HashReference<V>;
// HashReference KeyPackageRef;
// HashReference ProposalRef;
using HashReference = bytes;
using KeyPackageRef = HashReference;
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
    P384_AES256GCM_SHA384_P384 = 0x0007,
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
  bytes ref(const T& value) const
  {
    return raw_ref(reference_label<T>(), tls::marshal(value));
  }

  bytes raw_ref(const bytes& label, const bytes& value) const
  {
    // RefHash(label, value) = Hash(RefHashInput)
    //
    // struct {
    //   opaque label<V>;
    //   opaque value<V>;
    // } RefHashInput;
    auto w = tls::ostream();
    w << label << value;
    return digest().hash(w.bytes());
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

extern const std::array<CipherSuite::ID, 7> all_supported_suites;

// Utilities
using hpke::random_bytes;

// HPKE Keys
namespace encrypt_label {
extern const bytes update_path_node;
extern const bytes welcome;
} // namespace encrypt_label

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
                         const bytes& label,
                         const bytes& context,
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
                const bytes& label,
                const bytes& context,
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
namespace sign_label {
extern const bytes mls_content;
extern const bytes leaf_node;
extern const bytes key_package;
extern const bytes group_info;
} // namespace sign_label

struct SignaturePublicKey
{
  bytes data;

  bool verify(const CipherSuite& suite,
              const bytes& label,
              const bytes& message,
              const bytes& signature) const;

  TLS_SERIALIZABLE(data)
};

struct SignaturePrivateKey
{
  static SignaturePrivateKey generate(CipherSuite suite);
  static SignaturePrivateKey parse(CipherSuite suite, const bytes& data);
  static SignaturePrivateKey derive(CipherSuite suite, const bytes& secret);

  SignaturePrivateKey() = default;

  bytes data;
  SignaturePublicKey public_key;

  bytes sign(const CipherSuite& suite,
             const bytes& label,
             const bytes& message) const;

  TLS_SERIALIZABLE(data, public_key)

private:
  SignaturePrivateKey(bytes priv_data, bytes pub_data);
};

} // namespace mls
