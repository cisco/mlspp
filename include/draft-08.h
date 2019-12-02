#pragma once

#include "common.h"
#include "credential.h"
#include "crypto.h"
#include "messages.h"
#include "tls_syntax.h"
#include "ratchet_tree.h"

namespace draft08 {

using HPKEPublicKey = mls::DHPublicKey;
using mls::CipherSuite;
using mls::Credential;
using mls::Digest;
using mls::DirectPath;
using mls::HPKECiphertext;
using mls::LeafIndex;
using mls::RatchetTree;
using mls::bytes;

///
/// Welcome
///

enum class ProtocolVersion : uint8_t
{
  mls10 = 0xFF,
};

struct KeyPackage {
  tls::opaque<1> epoch_secret;
  tls::opaque<1> path_secret;

  TLS_SERIALIZABLE(epoch_secret, path_secret);
};

struct GroupInfo {
  tls::opaque<1> group_id;
  uint32_t epoch;
  RatchetTree tree;
  tls::opaque<1> confirmed_transcript_hash;
  tls::opaque<1> interim_transcript_hash;

  tls::opaque<1> confirmation;
  uint32_t signer_index;
  tls::opaque<1> signature;

  TLS_SERIALIZABLE(group_id, epoch, tree, confirmed_transcript_hash, interim_transcript_hash, confirmation, signer_index, signature);
};

struct EncryptedKeyPackage {
  EncryptedKeyPackage(CipherSuite suite)
    : encrypted_key_package(suite)
  {}

  tls::opaque<1> client_init_key_hash;
  HPKECiphertext encrypted_key_package;

  TLS_SERIALIZABLE(client_init_key_hash, encrypted_key_package);
};

struct Welcome {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  tls::variant_vector<EncryptedKeyPackage, CipherSuite, 4> key_packages;
  tls::opaque<4> encrypted_group_info;

  TLS_SERIALIZABLE(version, cipher_suite, key_packages, encrypted_group_info);
};

tls::ostream& operator<<(tls::ostream& str, const Welcome& obj);
tls::istream& operator>>(tls::istream& str, Welcome& obj);

///
/// ClientInitKey
///

struct State;

enum struct ExtensionType : uint16_t
{
  invalid = 0,
  supported_versions = 1,
  supported_ciphersuites = 2,
  expiration = 3,
};

struct Extension
{
  ExtensionType extension_type;
  tls::opaque<2> extension_data;

  TLS_SERIALIZABLE(extension_type, extension_data);
};

struct ClientInitKey {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  HPKEPublicKey init_key;
  Credential credential;
  tls::vector<Extension, 2> extensions;
  tls::opaque<2> signature;

  TLS_SERIALIZABLE(version, cipher_suite, init_key, credential, extensions, signature);
};

///
/// Proposals & Commit
///

enum struct ProposalType : uint8_t {
  invalid = 0,
  add = 1,
  update = 2,
  remove = 3,
};

struct Add {
  ClientInitKey client_init_key;

  static ProposalType type;
  TLS_SERIALIZABLE(client_init_key)
};

struct Update {
  HPKEPublicKey leaf_key;

  static ProposalType type;
  TLS_SERIALIZABLE(leaf_key)
};

struct Remove {
  LeafIndex removed;

  static ProposalType type;
  TLS_SERIALIZABLE(removed)
};

using Proposal = tls::variant<ProposalType, Add, Update, Remove>;

using ProposalID = tls::opaque<1>;

struct Commit {
  tls::vector<ProposalID, 2> updates;
  tls::vector<ProposalID, 2> removes;
  tls::vector<ProposalID, 2> adds;
  tls::vector<ProposalID, 2> ignored;
  DirectPath path;
};

///
/// State
///

// 0 -> creator
// 0 -> joiner
// joined -> joined


struct State {
  // TODO mark these const?
  ProtocolVersion version;
  CipherSuite cipher_suite;
  bytes group_id;
  uint32_t epoch;
  RatchetTree tree;
  bytes confirmed_transcript_hash;
  bytes interim_transcript_hash;

  bytes init_secret;
  bytes epoch_secret;
  bytes confirmation_key;
  bytes confirmation;

  State(CipherSuite cipher_suite_in, bytes group_id_in)
    : version(ProtocolVersion::mls10)
    , cipher_suite(cipher_suite_in)
    , group_id(group_id_in)
    , epoch(0)
    , tree(cipher_suite_in)
  {
    auto digest_size = Digest(cipher_suite).output_size();
    auto zero = bytes(digest_size, 0);
    confirmed_transcript_hash = zero;
    interim_transcript_hash = zero;
    init_secret = zero;
    confirmation_key = zero;
    confirmation = zero;
  }

  State(const ClientInitKey& client_init_key,
        const Welcome& welcome)
    : tree(client_init_key.cipher_suite)
  {
    /* TODO */
  }

  std::tuple<State, Commit, Welcome> commit(const bytes& leaf_secret) const {
    // TODO assemble
    // TODO make direct path
  }

  ///////////

  /*
  struct CachedUpdate {
    LeafIndex target;
    Update update;
  };

  std::map<ProposalID, Add> adds;
  std::map<ProposalID, CachedUpdate> updates;
  std::map<ProposalID, Remove> removes;
  std::map<ProposalID, Proposal> ignored;

  void handle(uint32_t sender, const ProposalID& id, const Proposal& proposal) {
    // TODO Ignore if:
    // * Update for removed
    // * Remove for removed
    // * Update for updated

    // Cache by type
    switch (proposal.type()) {
      case ProposalType::add:
        adds.at(id) = std::get<Add>(proposal);
        break;
      case ProposalType::update:
        updates.at(id) = CachedUpdate{LeafIndex{sender}, std::get<Update>(proposal)};
        break;
      case ProposalType::remove:
        removes.at(id) = std::get<Remove>(proposal);
        break;
      case ProposalType::invalid:
      default:
        // TODO throw
        break;
    }
  }

  State clone() const {
    // TODO actually clone
    return State(cipher_suite, group_id);
  }

  void apply(const CachedUpdate& update) {
    tree.blank_path(update.target);
    tree.set_leaf_key(update.target, update.update.leaf_key);
  }

  void apply(const Remove& remove) {
    tree.blank_path(remove.removed);
  }

  void apply(const Add& add) {
    auto index = tree.leftmost_free();
    tree.set_leaf(index, add.client_init_key.init_key, add.client_init_key.credential);
  }

  void ratchet(const DirectPath& path) {} // TODO

  State handle(const Commit& commit) const {
    auto next = clone();

    // Apply proposals to tree from cache
    for (const auto& id : commit.updates) {
      next.apply(updates.at(id));
    }

    for (const auto& id : commit.removes) {
      next.apply(removes.at(id));
    }

    for (const auto& id : commit.adds) {
      next.apply(adds.at(id));
    }

    // TODO update transcripts
    // TODO verify confirmation

    next.ratchet(commit.path);
    return next;
  }
  */


};





} // namespace draft08
