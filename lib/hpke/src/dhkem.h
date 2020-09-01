#pragma once

#include <hpke/hpke.h>

namespace hpke {

struct DHGroup
{
  enum struct ID : uint8_t
  {
    P256,
    P384,
    P521,
    X25519,
    X448,
  };

  static std::unique_ptr<DHGroup> create(ID group_id, KDF::ID kdf_id);
  virtual ~DHGroup() = default;

  virtual std::unique_ptr<KEM::PrivateKey> generate_key_pair() const = 0;
  virtual std::unique_ptr<KEM::PrivateKey> derive_key_pair(
    const bytes& ikm) const = 0;

  virtual bytes serialize(const KEM::PublicKey& pk) const = 0;
  virtual std::unique_ptr<KEM::PublicKey> deserialize(
    const bytes& enc) const = 0;

  virtual bytes serialize_private(const KEM::PrivateKey& sk) const = 0;
  virtual std::unique_ptr<KEM::PrivateKey> deserialize_private(
    const bytes& skm) const = 0;

  virtual bytes dh(const KEM::PrivateKey& sk,
                   const KEM::PublicKey& pk) const = 0;

  size_t dh_size() const;
  size_t pk_size() const;
  size_t sk_size() const;

protected:
  ID group_id;
  std::unique_ptr<KDF> kdf;
  bytes suite_id;

  friend struct DHKEM;

  DHGroup(ID group_id_in, KDF::ID kdf_id)
    : group_id(group_id_in)
    , kdf(KDF::create(kdf_id))
  {}
};

struct DHKEM : public KEM
{
  DHKEM(KEM::ID kem_id_in, DHGroup::ID group_id_in, KDF::ID kdf_id_in);
  std::unique_ptr<KEM> clone() const override;
  ~DHKEM() override = default;

  std::unique_ptr<KEM::PrivateKey> generate_key_pair() const override;
  std::unique_ptr<KEM::PrivateKey> derive_key_pair(
    const bytes& ikm) const override;

  bytes serialize(const KEM::PublicKey& pk) const override;
  std::unique_ptr<KEM::PublicKey> deserialize(const bytes& enc) const override;

  bytes serialize_private(const KEM::PrivateKey& sk) const override;
  std::unique_ptr<KEM::PrivateKey> deserialize_private(
    const bytes& skm) const override;

  std::pair<bytes, bytes> encap(const KEM::PublicKey& pk) const override;
  bytes decap(const bytes& enc, const KEM::PrivateKey& sk) const override;

  std::pair<bytes, bytes> auth_encap(const KEM::PublicKey& pkR,
                                     const KEM::PrivateKey& skS) const override;
  bytes auth_decap(const bytes& enc,
                   const KEM::PublicKey& pkS,
                   const KEM::PrivateKey& skR) const override;

  size_t secret_size() const override;
  size_t enc_size() const override;
  size_t pk_size() const override;
  size_t sk_size() const override;

private:
  KEM::ID kem_id;
  DHGroup::ID group_id;
  KDF::ID kdf_id;
  std::unique_ptr<DHGroup> dh;
  std::unique_ptr<KDF> kdf;
  bytes suite_id;

  bytes extract_and_expand(const bytes& dh, const bytes& kem_context) const;
};

} // namespace hpke
