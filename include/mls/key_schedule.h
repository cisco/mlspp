#pragma once

#include <mls/common.h>
#include <mls/crypto.h>
#include <mls/tree_math.h>
#include <mls/messages.h>
#include <map>

namespace mls {

struct BaseKeySource;
struct HashRatchet;

struct KeyAndNonce
{
  bytes key;
  bytes nonce;
};

struct HashRatchet
{
  CipherSuite suite;
  NodeIndex node;
  bytes next_secret;
  uint32_t next_generation;
  std::map<uint32_t, KeyAndNonce> cache;

  size_t key_size;
  size_t nonce_size;
  size_t secret_size;

  // These defaults are necessary for use with containers
  HashRatchet() = default;
  HashRatchet(const HashRatchet& other) = default;

  HashRatchet(CipherSuite suite_in, NodeIndex node_in, bytes base_secret_in);

  std::tuple<uint32_t, KeyAndNonce> next();
  KeyAndNonce get(uint32_t generation);
  void erase(uint32_t generation);
};

struct SecretTree
{
  SecretTree() = default;
  SecretTree(CipherSuite suite_in,
             LeafCount group_size_in,
             bytes encryption_secret_in);

  bytes get(LeafIndex sender);

private:
  CipherSuite suite;
  NodeIndex root;
  LeafCount group_size;
  std::vector<bytes> secrets;
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
                 bytes encryption_secret);

  std::tuple<uint32_t, KeyAndNonce> next(RatchetType type, LeafIndex sender);
  KeyAndNonce get(RatchetType type, LeafIndex sender, uint32_t generation);
  void erase(RatchetType type, LeafIndex sender, uint32_t generation);

private:
  CipherSuite suite;
  SecretTree secret_tree;

  using Key = std::tuple<RatchetType, LeafIndex>;
  std::map<Key, HashRatchet> chains;

  HashRatchet& chain(RatchetType type, LeafIndex sender);

  static const std::array<RatchetType, 2> all_ratchet_types;
};

struct KeyScheduleEpoch;

struct KeyScheduleEpoch
{
  CipherSuite suite;

  bytes joiner_secret;
  bytes member_secret;
  bytes epoch_secret;

  bytes sender_data_secret;
  bytes encryption_secret;
  bytes exporter_secret;
  bytes authentication_secret;
  bytes external_secret;
  bytes confirmation_key;
  bytes membership_key;
  bytes resumption_secret;
  bytes init_secret;

  HPKEPrivateKey external_priv;

  GroupKeySource keys;

  KeyScheduleEpoch() = default;

  // Generate an initial random epoch
  KeyScheduleEpoch(CipherSuite suite);

  // Generate an epoch based on the joiner secret
  KeyScheduleEpoch(CipherSuite suite_in,
                   bytes joiner_secret_in,
                   const bytes& psk_secret,
                   const bytes& context,
                   LeafCount size);

  // Advance to the next epoch
  KeyScheduleEpoch next(const bytes& commit_secret,
                        const bytes& psk_secret,
                        const bytes& context,
                        LeafCount size) const;

  KeyAndNonce sender_data(const bytes& ciphertext) const;
  bytes membership_tag(const GroupContext& context, const MLSPlaintext& pt) const;
  bytes confirmation_tag(const bytes& confirmed_transcript_hash) const;

private:
  void init_secrets(LeafCount size);
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
  void update_interim(const MLSPlaintext& pt);
};

bool
operator==(const TranscriptHash& lhs, const TranscriptHash& rhs);

} // namespace mls
