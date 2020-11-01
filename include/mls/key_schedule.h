#pragma once

#include "mls/common.h"
#include "mls/crypto.h"
#include "mls/tree_math.h"
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
             LeafCount group_size,
             bytes encryption_secret);

  bytes get(LeafIndex sender);

private:
  CipherSuite suite;
  NodeIndex root;
  NodeCount width;
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
  bytes epoch_secret;

  bytes sender_data_secret;

  bytes encryption_secret;
  GroupKeySource keys;

  bytes exporter_secret;
  bytes confirmation_key;
  bytes membership_key;
  bytes init_secret;

  static KeyScheduleEpoch first(CipherSuite suite,
                                const bytes& init_secret,
                                const bytes& context);
  static KeyScheduleEpoch create(CipherSuite suite,
                                 LeafCount size,
                                 const bytes& epoch_secret,
                                 const bytes& context);
  KeyScheduleEpoch next(LeafCount size,
                        const bytes& update_secret,
                        const bytes& context) const;

  KeyAndNonce sender_data(const bytes& ciphertext);
};

bool
operator==(const KeyScheduleEpoch& lhs, const KeyScheduleEpoch& rhs);

} // namespace mls
