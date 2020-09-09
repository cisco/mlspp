#pragma once

#include <hpke/hpke.h>
#include <hpke/signature.h>

namespace hpke {

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

  virtual std::unique_ptr<PrivateKey> generate_key_pair() const = 0;
  virtual std::unique_ptr<PrivateKey> derive_key_pair(
    const bytes& suite_id,
    const bytes& ikm) const = 0;

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

  size_t dh_size() const;
  size_t pk_size() const;
  size_t sk_size() const;

protected:
  ID group_id;
  const KDF& kdf;

  friend struct DHKEM;

  Group(ID group_id_in, const KDF& kdf_in)
    : group_id(group_id_in)
    , kdf(kdf_in)
  {}
};

} // namespace hpke
