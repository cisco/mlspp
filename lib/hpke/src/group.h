#pragma once

#include <hpke/hpke.h>
#include <hpke/signature.h>
#include <namespace.h>

#include "openssl_common.h"
#include <openssl/evp.h>

namespace MLS_NAMESPACE::hpke {

struct Group
{
  enum struct ID : uint8_t
  {
    P256,
    P384,
    P521,
    X25519,
    X448,
    Ed25519,
    Ed448,
  };

  struct PublicKey
    : public KEM::PublicKey
    , public Signature::PublicKey
  {
    virtual ~PublicKey() = default;
  };

  struct PrivateKey
  {
    virtual ~PrivateKey() = default;
    virtual std::unique_ptr<PublicKey> public_key() const = 0;
  };

  template<Group::ID id>
  static const Group& get();

  virtual ~Group() = default;

  const ID id;
  const size_t seed_size;
  const size_t dh_size;
  const size_t pk_size;
  const size_t sk_size;
  const std::string jwk_key_type;
  const std::string jwk_curve_name;

  virtual std::unique_ptr<PrivateKey> generate_key_pair() const = 0;
  virtual std::unique_ptr<PrivateKey> derive_key_pair(
    const bytes& suite_id,
    const bytes& ikm) const = 0;
  virtual std::unique_ptr<PrivateKey> random_scalar(
    const bytes& seed) const = 0;

  virtual bytes serialize(const PublicKey& pk) const = 0;
  virtual std::unique_ptr<PublicKey> deserialize(const bytes& enc) const = 0;

  virtual bytes serialize_private(const PrivateKey& sk) const = 0;
  virtual std::unique_ptr<PrivateKey> deserialize_private(
    const bytes& skm) const = 0;

  virtual bytes dh(const PrivateKey& sk, const PublicKey& pk) const = 0;

  virtual bytes sign(const bytes& data, const PrivateKey& sk) const = 0;
  virtual bool verify(const bytes& data,
                      const bytes& sig,
                      const PublicKey& pk) const = 0;

  virtual std::tuple<bytes, bytes> coordinates(const PublicKey& pk) const = 0;
  virtual std::unique_ptr<PublicKey> public_key_from_coordinates(
    const bytes& x,
    const bytes& y) const = 0;

protected:
  const KDF& kdf;

  friend struct DHKEM;

  Group(ID group_id_in, const KDF& kdf_in);
};

struct EVPGroup : public Group
{
  EVPGroup(Group::ID group_id, const KDF& kdf);

  struct PublicKey : public Group::PublicKey
  {
    explicit PublicKey(EVP_PKEY* pkey_in);
    ~PublicKey() override = default;

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    typed_unique_ptr<EVP_PKEY> pkey;
  };

  struct PrivateKey : public Group::PrivateKey
  {
    explicit PrivateKey(EVP_PKEY* pkey_in);
    ~PrivateKey() override = default;

    std::unique_ptr<Group::PublicKey> public_key() const override;

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    typed_unique_ptr<EVP_PKEY> pkey;
  };

  /// ExternalPrivateKey holds an EVP_PKEY that may be backed by an HSM,
  /// secure enclave, or other non-exportable key store.
  struct ExternalPrivateKey : public Signature::ExternalPrivateKey
  {
    ExternalPrivateKey(EVP_PKEY* pkey_in,
                       bool is_exportable,
                       bytes serialized_priv = {});
    ~ExternalPrivateKey() override = default;

    std::unique_ptr<Signature::ExternalPrivateKey> clone() const override;
    std::unique_ptr<Signature::PublicKey> public_key() const override;
    bool exportable() const override;
    std::unique_ptr<Signature::PrivateKey> to_exportable(
      const Signature& sig) const override;

    // Sign using the external key - used by Group::sign_external
    bytes sign(const bytes& data, const EVPGroup& group) const;

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    typed_unique_ptr<EVP_PKEY> pkey;

  private:
    bool is_exportable_;
    bytes serialized_private_key_; // Stored for exportable keys
  };

  std::unique_ptr<Group::PrivateKey> generate_key_pair() const override;

  bytes dh(const Group::PrivateKey& sk,
           const Group::PublicKey& pk) const override;

  bytes sign(const bytes& data, const Group::PrivateKey& sk) const override;
  bool verify(const bytes& data,
              const bytes& sig,
              const Group::PublicKey& pk) const override;

  /// Sign using an external (possibly non-exportable) key
  bytes sign_external(const bytes& data, const ExternalPrivateKey& sk) const;

  /// Load an external key from a provider URI (OpenSSL 3.x) or ENGINE (1.1.x)
  std::unique_ptr<ExternalPrivateKey> load_external_key(
    const std::string& uri) const;
};

} // namespace MLS_NAMESPACE::hpke
