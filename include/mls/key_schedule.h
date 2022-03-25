#pragma once

#include <map>
#include <mls/common.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/tree_math.h>

namespace mls {

struct HashRatchet
{
  CipherSuite suite;
  NodeIndex node;
  Secret next_secret;
  uint32_t next_generation;
  std::map<uint32_t, KeyAndNonce> cache;

  size_t key_size;
  size_t nonce_size;
  size_t secret_size;

  // These defaults are necessary for use with containers
  HashRatchet() = default;
  HashRatchet(const HashRatchet& other) = default;
  HashRatchet(HashRatchet&& other) = default;
  HashRatchet& operator=(const HashRatchet& other) = default;
  HashRatchet& operator=(HashRatchet&& other) = default;

  HashRatchet(CipherSuite suite_in, NodeIndex node_in, Secret&& base_secret_in);

  std::tuple<uint32_t, KeyAndNonce> next();
  KeyAndNonce get(uint32_t generation);
  void erase(uint32_t generation);
};

struct SecretTree
{
  SecretTree() = default;
  SecretTree(CipherSuite suite_in,
             LeafCount group_size_in,
             Secret&& encryption_secret_in);

  Secret get(LeafIndex sender);

private:
  CipherSuite suite;
  NodeIndex root;
  LeafCount group_size;
  std::vector<Secret> secrets;
  size_t secret_size;
};

struct GroupKeySource
{
  enum struct RatchetType
  {
    handshake,
    application,
  };

  GroupKeySource() = default;
  GroupKeySource(CipherSuite suite_in,
                 LeafCount group_size,
                 Secret&& encryption_secret);

  std::tuple<uint32_t, KeyAndNonce> next(RatchetType type, LeafIndex sender);
  KeyAndNonce get(RatchetType type, LeafIndex sender, uint32_t generation);
  void erase(RatchetType type, LeafIndex sender, uint32_t generation);

  MLSCiphertext encrypt(const TreeKEMPublicKey& tree,
                        LeafIndex index,
                        const Secret& sender_data_secret,
                        const MLSPlaintext& pt);
  MLSPlaintext decrypt(const TreeKEMPublicKey& tree,
                       const Secret& sender_data_secret,
                       const MLSCiphertext& ct);

private:
  CipherSuite suite;
  SecretTree secret_tree;

  using Key = std::tuple<RatchetType, LeafIndex>;
  std::map<Key, HashRatchet> chains;

  HashRatchet& chain(RatchetType type, LeafIndex sender);

  static const std::array<RatchetType, 2> all_ratchet_types;
};

struct KeyScheduleEpoch
{
private:
  CipherSuite suite;

public:
  Secret joiner_secret;
  Secret psk_secret;
  Secret epoch_secret;

  Secret sender_data_secret;
  Secret encryption_secret;
  Secret exporter_secret;
  Secret authentication_secret;
  Secret external_secret;
  Secret confirmation_key;
  Secret membership_key;
  Secret resumption_secret;
  Secret init_secret;

  HPKEPrivateKey external_priv;

  KeyScheduleEpoch() = default;

  // Full initializer, used by invited joiner
  KeyScheduleEpoch(CipherSuite suite_in,
                   const Secret& joiner_secret,
                   const std::vector<PSKWithSecret>& psks,
                   const bytes& context);

  // Ciphersuite-only initializer, used by external joiner
  KeyScheduleEpoch(CipherSuite suite_in);

  // Initial epoch
  KeyScheduleEpoch(CipherSuite suite_in,
                   const Secret& init_secret,
                   const bytes& context);

  // Subsequent epochs
  KeyScheduleEpoch(CipherSuite suite_in,
                   const Secret& init_secret,
                   const Secret& commit_secret,
                   const std::vector<PSKWithSecret>& psks,
                   const bytes& context);

  static std::tuple<bytes, Secret> external_init(
    CipherSuite suite,
    const HPKEPublicKey& external_pub);
  Secret receive_external_init(const bytes& kem_output) const;

  KeyScheduleEpoch next(const Secret& commit_secret,
                        const std::vector<PSKWithSecret>& psks,
                        const std::optional<Secret>& force_init_secret,
                        const bytes& context) const;

  GroupKeySource encryption_keys(LeafCount size) const;
  bytes membership_tag(const GroupContext& context,
                       const MLSPlaintext& pt) const;
  bytes confirmation_tag(const bytes& confirmed_transcript_hash) const;
  Secret do_export(const std::string& label,
                   const bytes& context,
                   size_t size) const;
  PSKWithSecret branch_psk(const bytes& group_id, epoch_t epoch);
  PSKWithSecret reinit_psk(const bytes& group_id, epoch_t epoch);

  static Secret welcome_secret(CipherSuite suite,
                               const Secret& joiner_secret,
                               const std::vector<PSKWithSecret>& psks);
  static KeyAndNonce sender_data_keys(CipherSuite suite,
                                      const Secret& sender_data_secret,
                                      const bytes& ciphertext);
};

bool
operator==(const KeyScheduleEpoch& lhs, const KeyScheduleEpoch& rhs);

struct TranscriptHash
{
  CipherSuite suite;
  bytes confirmed;
  bytes interim;

  TranscriptHash(CipherSuite suite_in);

  void update(const MLSPlaintext& pt);
  void update_confirmed(const MLSPlaintext& pt);
  void update_interim(const MAC& confirmation_tag);
  void update_interim(const MLSPlaintext& pt);
};

bool
operator==(const TranscriptHash& lhs, const TranscriptHash& rhs);

} // namespace mls
