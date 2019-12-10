#pragma once

#include "common.h"
#include "crypto.h"
#include "tree_math.h"
#include <map>

namespace mls {

struct BaseKeySource;
struct HashRatchet;

struct KeyAndNonce {
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

struct BaseKeySource
{
  CipherSuite suite;
  size_t secret_size;

  BaseKeySource(CipherSuite suite_in);

  virtual ~BaseKeySource() = default;
  virtual BaseKeySource* dup() const = 0;
  virtual bytes get(LeafIndex sender) = 0;
};

struct GroupKeySource
{
  CipherSuite suite;
  std::unique_ptr<BaseKeySource> base_source;
  std::map<LeafIndex, HashRatchet> chains;

  GroupKeySource();
  GroupKeySource(const GroupKeySource& other);
  GroupKeySource& operator=(const GroupKeySource& other);
  GroupKeySource(BaseKeySource* base_source_in);

  std::tuple<uint32_t, KeyAndNonce> next(LeafIndex sender);
  KeyAndNonce get(LeafIndex sender, uint32_t generation);
  void erase(LeafIndex sender, uint32_t generation);

  private:
  HashRatchet& chain(LeafIndex sender);
};

struct KeyScheduleEpoch;

struct FirstEpoch {
  CipherSuite suite;
  bytes init_secret;
  bytes group_info_secret;
  bytes group_info_key;
  bytes group_info_nonce;

  static FirstEpoch create(CipherSuite suite, const bytes& init_secret);
  KeyScheduleEpoch next(LeafCount size, const bytes& update_secret, const bytes& context);
};

struct KeyScheduleEpoch {
  CipherSuite suite;
  bytes epoch_secret;

  bytes sender_data_secret;
  bytes sender_data_key;

  bytes handshake_secret;
  GroupKeySource handshake_keys;

  bytes application_secret;
  GroupKeySource application_keys;

  bytes confirmation_key;
  bytes init_secret;

  KeyScheduleEpoch() = default;

  static KeyScheduleEpoch create(CipherSuite suite, LeafCount size, const bytes& epoch_secret, const bytes& context);
  KeyScheduleEpoch next(LeafCount size, const bytes& update_secret, const bytes& context);
};

bool operator==(const KeyScheduleEpoch& lhs, const KeyScheduleEpoch& rhs);

} // namespace mls
