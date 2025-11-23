#ifdef WITH_PQ
#pragma once

#include <hpke/hpke.h>
#include <namespace.h>

namespace MLS_NAMESPACE::hpke {

struct MLKEM : public KEM
{
  struct PublicKey : public KEM::PublicKey
  {
    PublicKey(bytes pk_in);
    bytes pk;
  };

  struct PrivateKey : public KEM::PrivateKey
  {
    PrivateKey(bytes sk_in, bytes expanded_sk_in, bytes pk_in);
    std::unique_ptr<KEM::PublicKey> public_key() const override;

    bytes sk;
    bytes expanded_sk;
    bytes pk;
  };

  template<KEM::ID>
  static const MLKEM& get();

  ~MLKEM() override = default;

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

  // auth_encap and auth_decap not implemented

private:
  const KEM::ID kem_id;
  bytes suite_id;

  MLKEM(KEM::ID kem_id_in);
  friend MLKEM make_mlkem(KEM::ID kem_id_in);

  friend struct HybridKEM;
  static constexpr auto seed_size = size_t(64);
  static constexpr auto secret_size = size_t(32);
  static constexpr auto sk_size = size_t(64);
};

} // namespace MLS_NAMESPACE::hpke

#endif // def WITH_PQ
