#pragma once

#include <functional>
#include <memory>
#include <string>

#include <bytes/bytes.h>
#include <namespace.h>
using namespace MLS_NAMESPACE::bytes_ns;

namespace MLS_NAMESPACE::hpke {

struct Signature
{
  enum struct ID
  {
    P256_SHA256,
    P384_SHA384,
    P521_SHA512,
    Ed25519,
#if !defined(WITH_BORINGSSL)
    Ed448,
#endif
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
  };

  template<Signature::ID id>
  static const Signature& get();

  virtual ~Signature() = default;

  struct PublicKey
  {
    virtual ~PublicKey() = default;
  };

  struct PrivateKey
  {
    virtual ~PrivateKey() = default;
    virtual std::unique_ptr<PublicKey> public_key() const = 0;
  };

  /// ExternalPrivateKey represents a private key that may not be exportable.
  /// This is used for keys stored in secure enclaves, HSMs, or other secure
  /// storage that can perform signing operations but won't reveal key material.
  struct ExternalPrivateKey
  {
    virtual ~ExternalPrivateKey() = default;

    /// Clone this external key
    virtual std::unique_ptr<ExternalPrivateKey> clone() const = 0;

    /// Get the public key corresponding to this private key
    virtual std::unique_ptr<PublicKey> public_key() const = 0;

    /// Check if the key material can be exported
    virtual bool exportable() const = 0;

    /// Export the key as a serializable PrivateKey (throws if !exportable())
    virtual std::unique_ptr<PrivateKey> to_exportable(
      const Signature& sig) const = 0;
  };

  /// Type for external signing callbacks (used by BoringSSL and custom
  /// backends)
  using ExternalSignCallback = std::function<bytes(const bytes& data)>;

  const ID id;

  virtual std::unique_ptr<PrivateKey> generate_key_pair() const = 0;
  virtual std::unique_ptr<PrivateKey> derive_key_pair(
    const bytes& ikm) const = 0;

  virtual bytes serialize(const PublicKey& pk) const = 0;
  virtual std::unique_ptr<PublicKey> deserialize(const bytes& enc) const = 0;

  virtual bytes serialize_private(const PrivateKey& sk) const = 0;
  virtual std::unique_ptr<PrivateKey> deserialize_private(
    const bytes& skm) const = 0;

  struct PrivateJWK
  {
    const Signature& sig;
    std::optional<std::string> key_id;
    std::unique_ptr<PrivateKey> key;
  };
  static PrivateJWK parse_jwk_private(const std::string& jwk_json);

  struct PublicJWK
  {
    const Signature& sig;
    std::optional<std::string> key_id;
    std::unique_ptr<PublicKey> key;
  };
  static PublicJWK parse_jwk(const std::string& jwk_json);

  virtual std::unique_ptr<PrivateKey> import_jwk_private(
    const std::string& jwk_json) const = 0;
  virtual std::unique_ptr<PublicKey> import_jwk(
    const std::string& jwk_json) const = 0;
  virtual std::string export_jwk_private(const PrivateKey& env) const = 0;
  virtual std::string export_jwk(const PublicKey& env) const = 0;

  virtual bytes sign(const bytes& data, const PrivateKey& sk) const = 0;
  virtual bool verify(const bytes& data,
                      const bytes& sig,
                      const PublicKey& pk) const = 0;

  /// Sign using an external (possibly non-exportable) private key
  virtual bytes sign_external(const bytes& data,
                              const ExternalPrivateKey& sk) const = 0;

  /// Load an external private key from a URI (e.g., "pkcs11:...", "engine:...")
  /// Returns nullptr if the URI scheme is not supported.
  virtual std::unique_ptr<ExternalPrivateKey> load_external_key(
    const std::string& uri) const;

  /// Create an external key from a signing callback and public key.
  /// This is useful for BoringSSL and custom secure enclave integrations.
  virtual std::unique_ptr<ExternalPrivateKey> external_key_from_callback(
    std::unique_ptr<PublicKey> pub,
    ExternalSignCallback callback) const;

  static std::unique_ptr<PrivateKey> generate_rsa(size_t bits);

protected:
  Signature(ID id_in);
};

} // namespace MLS_NAMESPACE::hpke
